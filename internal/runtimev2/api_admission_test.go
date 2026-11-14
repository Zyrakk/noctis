package runtimev2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/jackc/pgx/v5"
)

const admissionLogin = `{"username":"operator","password":"synthetic-test-password-only"}`

func admissionAPI() *API {
	a := newAPI(configv2.Config{Origin: "https://fixture.invalid"}, "operator", "synthetic-test-password-only")
	a.connect = func(context.Context, string) (*pgx.Conn, error) {
		return nil, errors.New("synthetic database unavailable")
	}
	return a
}

func admissionRequest(method, path, body, token string) *http.Request {
	r := httptest.NewRequest(method, "https://fixture.invalid/api/v2/"+path, strings.NewReader(body))
	r.Header.Set("Origin", "https://fixture.invalid")
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
	}
	return r
}

func admissionServe(a *API, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.handle(w, r)
	return w
}

func TestAPIAdmissionRejectsBeforeDatabase(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, body, token, code string
		status, connections                   int
	}{
		{"missing cookie", "GET", "auth/session", "", "", "authentication_required", 401, 0},
		{"short token", "GET", "auth/session", "", "abc", "authentication_required", 401, 0},
		{"UUID token", "GET", "auth/session", "", "5d18935f-8863-4f78-a969-e9f86f55019c", "authentication_required", 401, 0},
		{"uppercase token", "GET", "auth/session", "", strings.Repeat("A", 64), "authentication_required", 401, 0},
		{"nonhex token", "GET", "auth/session", "", strings.Repeat("g", 64), "authentication_required", 401, 0},
		{"long token", "GET", "auth/session", "", strings.Repeat("a", 65), "authentication_required", 401, 0},
		{"well formed token", "GET", "auth/session", "", strings.Repeat("a", 64), "database_unavailable", 503, 1},
		{"empty JSON", "POST", "auth/login", "", "", "invalid_login", 400, 0},
		{"malformed JSON", "POST", "auth/login", "{", "", "invalid_login", 400, 0},
		{"unknown field", "POST", "auth/login", `{"extra":true}`, "", "invalid_login", 400, 0},
		{"additional object", "POST", "auth/login", admissionLogin + " {}", "", "invalid_login", 400, 0},
		{"additional null", "POST", "auth/login", admissionLogin + " null", "", "invalid_login", 400, 0},
		{"additional garbage", "POST", "auth/login", admissionLogin + " x", "", "invalid_login", 400, 0},
		{"null object", "POST", "auth/login", "null", "", "invalid_login", 400, 0},
		{"array", "POST", "auth/login", "[]", "", "invalid_login", 400, 0},
		{"oversized", "POST", "auth/login", admissionLogin + strings.Repeat(" ", apiLoginMaxBodyBytes+1-len(admissionLogin)), "", "invalid_login", 400, 0},
		{"maximum bytes", "POST", "auth/login", admissionLogin + strings.Repeat(" ", apiLoginMaxBodyBytes-len(admissionLogin)), "", "database_unavailable", 503, 1},
		{"wrong password", "POST", "auth/login", `{"username":"operator","password":"wrong"}`, "", "invalid_credentials", 401, 0},
		{"wrong username", "POST", "auth/login", `{"username":"other","password":"synthetic-test-password-only"}`, "", "invalid_credentials", 401, 0},
		{"valid credentials", "POST", "auth/login", admissionLogin, "", "database_unavailable", 503, 1},
		{"method first", "DELETE", "auth/login", "{", "", "method_not_allowed", 405, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := admissionAPI()
			connections := 0
			a.connect = func(context.Context, string) (*pgx.Conn, error) {
				connections++
				return nil, errors.New("synthetic database unavailable")
			}
			w := admissionServe(a, admissionRequest(tt.method, tt.path, tt.body, tt.token))
			if w.Code != tt.status || !strings.Contains(w.Body.String(), `"code":"`+tt.code+`"`) || connections != tt.connections {
				t.Fatalf("status=%d body=%s connections=%d; want %d %s %d", w.Code, w.Body.String(), connections, tt.status, tt.code, tt.connections)
			}
		})
	}
}

type unreadLoginBody struct{ t *testing.T }

func (b unreadLoginBody) Read([]byte) (int, error) {
	b.t.Error("rejected request body was read")
	return 0, io.EOF
}
func (unreadLoginBody) Close() error { return nil }

func TestAPIAdmissionLoginBudgetAndPrecedence(t *testing.T) {
	now := time.Unix(1000, 0)
	a := admissionAPI()
	a.admission = newAPIAdmission(func() time.Time { return now })
	for _, tt := range []struct {
		method, origin string
		want           int
	}{
		{"DELETE", "https://attacker.invalid", 405},
		{"POST", "https://attacker.invalid", 403},
		{"POST", "", 403},
	} {
		r := admissionRequest(tt.method, "auth/login", "", "")
		r.Header.Set("Origin", tt.origin)
		r.Body = unreadLoginBody{t}
		if w := admissionServe(a, r); w.Code != tt.want {
			t.Fatalf("precedence status=%d want %d", w.Code, tt.want)
		}
	}
	// Invalid JSON, wrong credentials, and valid credentials all spend one token.
	for i := 0; i < apiLoginBurst; i++ {
		body, want := "{", 400
		if i%3 == 1 {
			body, want = `{}`, 401
		}
		if i%3 == 2 {
			body, want = admissionLogin, 503
		}
		if w := admissionServe(a, admissionRequest("POST", "auth/login", body, "")); w.Code != want {
			t.Fatalf("attempt %d: status=%d want %d", i, w.Code, want)
		}
	}
	denied := func(retry string) {
		t.Helper()
		r := admissionRequest("POST", "auth/login", "", "")
		r.Body = unreadLoginBody{t}
		w := admissionServe(a, r)
		if w.Code != 429 || w.Header().Get("Retry-After") != retry {
			t.Fatalf("status=%d retry=%q want 429/%s", w.Code, w.Header().Get("Retry-After"), retry)
		}
	}
	denied("6")
	now = now.Add(5100 * time.Millisecond)
	denied("1")
	now = now.Add(900 * time.Millisecond)
	if w := admissionServe(a, admissionRequest("POST", "auth/login", admissionLogin, "")); w.Code != 503 {
		t.Fatalf("replenished attempt status=%d", w.Code)
	}
	denied("6")
	now = now.Add(24 * time.Hour)
	for i := 0; i < apiLoginBurst; i++ {
		if wait := a.admission.takeLogin(); wait != 0 {
			t.Fatalf("restored burst %d: %s", i, wait)
		}
	}
	denied("6")
}

func TestAPIAdmissionConcurrentLoginBudget(t *testing.T) {
	a := admissionAPI()
	a.admission = newAPIAdmission(func() time.Time { return time.Unix(1000, 0) })
	var wg sync.WaitGroup
	var admitted, limited atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch w := admissionServe(a, admissionRequest("POST", "auth/login", `{}`, "")); w.Code {
			case 401:
				admitted.Add(1)
			case 429:
				limited.Add(1)
			default:
				t.Errorf("unexpected status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != apiLoginBurst || limited.Load() != 64-apiLoginBurst {
		t.Fatalf("admitted=%d limited=%d", admitted.Load(), limited.Load())
	}
}

func TestAPIAdmissionConcurrentDatabaseAndCancellation(t *testing.T) {
	a := admissionAPI()
	entered := make(chan struct{}, apiDBRequestLimit+1)
	completed := make(chan int, apiDBRequestLimit)
	var current, peak, connections atomic.Int32
	a.connect = func(ctx context.Context, _ string) (*pgx.Conn, error) {
		connections.Add(1)
		n := current.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		defer current.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < apiDBRequestLimit; i++ {
		go func() {
			completed <- admissionServe(a, admissionRequest("GET", "auth/session", "", strings.Repeat("a", 64)).WithContext(ctx)).Code
		}()
	}
	for i := 0; i < apiDBRequestLimit; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("admitted connector did not start")
		}
	}
	denied := make(chan *httptest.ResponseRecorder, 1)
	go func() { denied <- admissionServe(a, admissionRequest("GET", "auth/session", "", random())) }()
	select {
	case w := <-denied:
		if w.Code != 503 || !strings.Contains(w.Body.String(), "request_capacity_exhausted") {
			t.Fatalf("saturated: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("saturated request queued behind active connectors")
	}
	if peak.Load() != apiDBRequestLimit || connections.Load() != apiDBRequestLimit {
		t.Fatalf("peak=%d connections=%d", peak.Load(), connections.Load())
	}
	cancel()
	for i := 0; i < apiDBRequestLimit; i++ {
		select {
		case status := <-completed:
			if status != 503 {
				t.Fatalf("cancelled status=%d", status)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation did not finish")
		}
	}
	// All cancelled connection attempts must release their permits; failed attempts too.
	a.connect = func(context.Context, string) (*pgx.Conn, error) {
		connections.Add(1)
		return nil, errors.New("synthetic failure")
	}
	for i := 0; i < apiDBRequestLimit+1; i++ {
		w := admissionServe(a, admissionRequest("GET", "auth/session", "", random()))
		if w.Code != 503 || !strings.Contains(w.Body.String(), "database_unavailable") {
			t.Fatalf("permit leaked: %d %s", w.Code, w.Body.String())
		}
	}
	if connections.Load() != 2*apiDBRequestLimit+1 || len(a.admission.dbSlots) != 0 {
		t.Fatalf("connections=%d remaining permits=%d", connections.Load(), len(a.admission.dbSlots))
	}
}

type admissionCloseProbe struct{ t *testing.T }

func (p admissionCloseProbe) Close(ctx context.Context) error {
	p.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || time.Until(deadline) <= 0 || time.Until(deadline) > apiDBCloseTimeout {
		p.t.Fatalf("cleanup requires live context with bounded deadline: %v %v", deadline, ctx.Err())
	}
	return nil
}

func TestAPIAdmissionCloseHasIndependentBoundedContext(t *testing.T) {
	closeAPIConnection(admissionCloseProbe{t})
}

type admissionBlockingWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w admissionBlockingWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.release
	return w.ResponseRecorder.Write(p)
}

func TestAPIAdmissionSuccessfulLoginsAndRequestLifetimePostgres(t *testing.T) {
	dsn := productDB(t)
	a := admissionAPI()
	a.cfg.DatabaseURL, a.connect = dsn, pgx.Connect
	now := time.Unix(1000, 0)
	a.admission = newAPIAdmission(func() time.Time { return now })
	for i := 0; i < apiLoginBurst; i++ {
		if w := admissionServe(a, admissionRequest("POST", "auth/login", admissionLogin, "")); w.Code != 200 {
			t.Fatalf("successful attempt %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := admissionServe(a, admissionRequest("POST", "auth/login", admissionLogin, "")); w.Code != 429 {
		t.Fatalf("successful attempts did not consume budget: %d", w.Code)
	}
	now = now.Add(apiLoginInterval)
	if w := admissionServe(a, admissionRequest("POST", "auth/login", admissionLogin, "")); w.Code != 200 {
		t.Fatalf("login did not recover: %d %s", w.Code, w.Body.String())
	}
	// A request remains admitted through response writing, after DB authentication.
	a.admission.dbSlots = make(chan struct{}, 1)
	entered, release, done := make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	var conn *pgx.Conn
	a.connect = func(ctx context.Context, dsn string) (*pgx.Conn, error) {
		var err error
		conn, err = pgx.Connect(ctx, dsn)
		return conn, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := admissionBlockingWriter{httptest.NewRecorder(), entered, release}
	go func() {
		a.handle(w, admissionRequest("GET", "auth/session", "", random()).WithContext(ctx))
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not reach response")
	}
	if next := admissionServe(a, admissionRequest("GET", "auth/session", "", random())); next.Code != 503 || !strings.Contains(next.Body.String(), "request_capacity_exhausted") {
		t.Fatalf("handler released permit before completion: %d %s", next.Code, next.Body.String())
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled handler cleanup did not finish")
	}
	if conn == nil || !conn.IsClosed() || len(a.admission.dbSlots) != 0 {
		t.Fatal("cancelled handler did not close its connection and release its permit")
	}
	a.connect = pgx.Connect
	if next := admissionServe(a, admissionRequest("GET", "auth/session", "", random())); next.Code != 401 {
		t.Fatalf("request capacity did not recover: %d %s", next.Code, next.Body.String())
	}
}
