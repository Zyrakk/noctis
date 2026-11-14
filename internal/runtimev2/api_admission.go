package runtimev2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/jackc/pgx/v5"
)

const (
	apiLoginBurst        = 10
	apiLoginInterval     = 6 * time.Second
	apiDBRequestLimit    = 16
	apiDBCloseTimeout    = 2 * time.Second
	apiLoginMaxBodyBytes = 4096
)

// apiAdmission bounds requests admitted to the DB phase, not all connections:
// delegated stores may open more connections while an admitted request runs.
type apiAdmission struct {
	mu      sync.Mutex
	now     func() time.Time
	last    time.Time
	credit  time.Duration
	dbSlots chan struct{}
}

func newAPI(cfg configv2.Config, username, password string) *API {
	return &API{cfg: cfg, username: username, password: password,
		admission: newAPIAdmission(time.Now), connect: pgx.Connect}
}

func newAPIAdmission(now func() time.Time) *apiAdmission {
	return &apiAdmission{now: now, last: now(), credit: apiLoginBurst * apiLoginInterval,
		dbSlots: make(chan struct{}, apiDBRequestLimit)}
}

// takeLogin consumes every locally admitted attempt, including successful ones.
// A denied attempt does not delay recovery. The returned wait is rounded up by
// the caller to whole seconds for Retry-After.
func (a *apiAdmission) takeLogin() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if elapsed := now.Sub(a.last); elapsed > 0 {
		remaining := apiLoginBurst*apiLoginInterval - a.credit
		if elapsed > remaining {
			elapsed = remaining
		}
		a.credit += elapsed
		a.last = now
	}
	if a.credit < apiLoginInterval {
		return apiLoginInterval - a.credit
	}
	a.credit -= apiLoginInterval
	return 0
}

func (a *apiAdmission) acquireDB() bool {
	select {
	case a.dbSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *apiAdmission) releaseDB() { <-a.dbSlots }

func validSessionToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (a *API) admitLogin(w http.ResponseWriter, r *http.Request) bool {
	if retry := a.admission.takeLogin(); retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		failure(w, 429, "login_rate_limited")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, apiLoginMaxBodyBytes+1))
	if err != nil || len(body) > apiLoginMaxBodyBytes {
		failure(w, 400, "invalid_login")
		return false
	}
	var input *struct{ Username, Password string }
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&input); err != nil || input == nil {
		failure(w, 400, "invalid_login")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		failure(w, 400, "invalid_login")
		return false
	}
	expectedUser, actualUser := sha256.Sum256([]byte(a.username)), sha256.Sum256([]byte(input.Username))
	expectedPass, actualPass := sha256.Sum256([]byte(a.password)), sha256.Sum256([]byte(input.Password))
	if subtle.ConstantTimeCompare(expectedUser[:], actualUser[:])&subtle.ConstantTimeCompare(expectedPass[:], actualPass[:]) != 1 {
		failure(w, 401, "invalid_credentials")
		return false
	}
	return true
}

func closeAPIConnection(c interface{ Close(context.Context) error }) {
	// Request cancellation must not skip cleanup, nor can cleanup hold a permit forever.
	ctx, cancel := context.WithTimeout(context.Background(), apiDBCloseTimeout)
	defer cancel()
	c.Close(ctx)
}
