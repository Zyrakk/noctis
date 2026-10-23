// Package enrichmentv2 performs only explicit, quota-reserved provider queries.
// Provider judgments remain attributed data and never promote indicators.
package enrichmentv2

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var endpoints = map[string]string{"virustotal": "https://www.virustotal.com/api/v3", "abuseipdb": "https://api.abuseipdb.com/api/v2/check", "crtsh": "https://crt.sh/"}
var domain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
var hash = regexp.MustCompile(`^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)

type Request struct {
	Provider   string `json:"provider"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	DataClass  string `json:"data_class"`
	Permission bool   `json:"permission"`
}
type Result struct {
	Provider   string         `json:"provider"`
	Status     string         `json:"status"`
	Data       map[string]any `json:"data"`
	ObservedAt time.Time      `json:"observed_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Cached     bool           `json:"cached"`
}
type Store struct {
	DSN      string
	Fetcher  capture.Fetcher
	Endpoint string
	Secret   string
}

func valid(kind, value string) bool {
	switch kind {
	case "ip":
		return net.ParseIP(value) != nil
	case "domain":
		return domain.MatchString(value)
	case "hash":
		return hash.MatchString(value)
	}
	return false
}
func (s Store) Lookup(ctx context.Context, r Request) (Result, error) {
	var result Result
	if !r.Permission || r.DataClass == "" || !valid(r.Type, r.Value) || endpoints[r.Provider] == "" {
		return result, errors.New("enrichment permission, type or value denied")
	}
	if r.Provider != "crtsh" && s.Secret == "" {
		return result, errors.New("provider credential unavailable")
	}
	if r.Provider == "abuseipdb" && r.Type != "ip" || r.Provider == "crtsh" && r.Type != "domain" {
		return result, errors.New("provider type unsupported")
	}
	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = endpoints[r.Provider]
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return result, e
	}
	if endpoint != endpoints[r.Provider] && !s.Fetcher.AllowLocal[u.Host] {
		return result, errors.New("provider endpoint denied")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return result, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return result, e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return result, e
	}
	var version string
	var classes []byte
	var quota, ttl int
	e = tx.QueryRow(ctx, `SELECT version,data_classes,quota_per_day,ttl_seconds FROM noctis_v2.enrichment_policies WHERE provider=$1 AND enabled FOR UPDATE`, r.Provider).Scan(&version, &classes, &quota, &ttl)
	if e != nil {
		return result, errors.New("provider policy unavailable")
	}
	var allowed []string
	if e = json.Unmarshal(classes, &allowed); e != nil {
		return result, e
	}
	permitted := false
	for _, v := range allowed {
		if v == r.DataClass {
			permitted = true
		}
	}
	if !permitted {
		return result, errors.New("data class export denied")
	}
	var cached []byte
	e = tx.QueryRow(ctx, `SELECT body FROM noctis_v2.enrichment_cache WHERE provider=$1 AND policy_version=$2 AND observable_type=$3 AND value=$4 AND data_class=$5 AND expires_at>clock_timestamp()`, r.Provider, version, r.Type, r.Value, r.DataClass).Scan(&cached)
	if e == nil {
		e = json.Unmarshal(cached, &result)
		result.Cached = true
		return result, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return result, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.enrichment_usage(provider,day) VALUES($1,(clock_timestamp() AT TIME ZONE 'UTC')::date) ON CONFLICT DO NOTHING`, r.Provider)
	if e != nil {
		return result, e
	}
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.enrichment_usage SET used=used+1 WHERE provider=$1 AND day=(clock_timestamp() AT TIME ZONE 'UTC')::date AND used<$2`, r.Provider, quota)
	if e != nil {
		return result, e
	}
	if tag.RowsAffected() != 1 {
		return result, errors.New("provider quota exhausted")
	}
	attempt := uuid.NewString()
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.enrichment_attempts(id,provider,policy_version,observable_type,value,data_class,state) VALUES($1,$2,$3,$4,$5,$6,'reserved')`, attempt, r.Provider, version, r.Type, r.Value, r.DataClass)
	if e != nil {
		return result, e
	}
	if e = tx.Commit(ctx); e != nil {
		return result, e
	}
	headers := http.Header{"Accept": []string{"application/json"}}
	switch r.Provider {
	case "virustotal":
		if s.Secret == "" {
			return result, errors.New("provider credential unavailable")
		}
		headers.Set("x-apikey", s.Secret)
		path := map[string]string{"ip": "ip_addresses", "domain": "domains", "hash": "files"}[r.Type]
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path + "/" + url.PathEscape(r.Value)
	case "abuseipdb":
		if s.Secret == "" {
			return result, errors.New("provider credential unavailable")
		}
		headers.Set("Key", s.Secret)
		q := u.Query()
		q.Set("ipAddress", r.Value)
		q.Set("maxAgeInDays", "90")
		u.RawQuery = q.Encode()
	case "crtsh":
		q := u.Query()
		q.Set("q", r.Value)
		q.Set("output", "json")
		u.RawQuery = q.Encode()
	}
	// Recheck revocation immediately before leaving the system after reservation.
	var payload []byte
	e = intelligence.GuardProjectionIO(ctx, c, func(ioCtx context.Context) error {
		var active bool
		if e := c.QueryRow(ioCtx, `SELECT EXISTS(SELECT FROM noctis_v2.enrichment_policies WHERE provider=$1 AND version=$2 AND enabled AND data_classes ? $3)`, r.Provider, version, r.DataClass).Scan(&active); e != nil {
			return e
		}
		if !active {
			return errors.New("provider policy revoked")
		}
		var e error
		payload, e = s.Fetcher.GetWithHeaders(ioCtx, u.String(), headers)
		return e
	})
	state := "uncertain"
	if e == nil {
		result, e = Parse(r.Provider, payload)
		if e == nil {
			state = "succeeded"
		} else {
			state = "failed"
		}
	}
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, writeErr := c.Exec(finishCtx, `UPDATE noctis_v2.enrichment_attempts SET state=$2 WHERE id=$1`, attempt, state)
	if e != nil {
		return result, errors.Join(e, writeErr)
	}
	if writeErr != nil {
		return result, writeErr
	}
	result.Provider = r.Provider
	result.Status = "provider_claim"
	result.ObservedAt = time.Now().UTC()
	result.ExpiresAt = result.ObservedAt.Add(time.Duration(ttl) * time.Second)
	raw, _ := json.Marshal(result)
	tx, e = c.Begin(ctx)
	if e != nil {
		return Result{}, e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return Result{}, e
	}
	var active bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.enrichment_policies WHERE provider=$1 AND version=$2 AND enabled AND data_classes ? $3)`, r.Provider, version, r.DataClass).Scan(&active); e != nil {
		return Result{}, e
	}
	if !active {
		return Result{}, errors.New("provider policy revoked before publication")
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.enrichment_cache VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(provider,policy_version,observable_type,value,data_class) DO UPDATE SET body=EXCLUDED.body,observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at`, r.Provider, version, r.Type, r.Value, r.DataClass, string(raw), result.ObservedAt, result.ExpiresAt)
	if e != nil {
		return Result{}, e
	}
	return result, tx.Commit(ctx)
}
func Parse(provider string, payload []byte) (Result, error) {
	r := Result{Provider: provider, Data: map[string]any{}}
	if !json.Valid(payload) {
		return r, errors.New("invalid provider JSON")
	}
	switch provider {
	case "virustotal":
		var v struct {
			Data *struct {
				Attributes *struct {
					Stats *struct {
						Malicious  int `json:"malicious"`
						Suspicious int `json:"suspicious"`
						Harmless   int `json:"harmless"`
						Undetected int `json:"undetected"`
					} `json:"last_analysis_stats"`
					Reputation int `json:"reputation"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if e := json.Unmarshal(payload, &v); e != nil {
			return r, e
		}
		if v.Data == nil || v.Data.Attributes == nil || v.Data.Attributes.Stats == nil {
			return r, errors.New("provider statistics missing")
		}
		stats := v.Data.Attributes.Stats
		if stats.Malicious < 0 || stats.Suspicious < 0 || stats.Harmless < 0 || stats.Undetected < 0 {
			return r, errors.New("invalid provider count")
		}
		r.Data["stats"] = stats
		r.Data["reputation"] = v.Data.Attributes.Reputation
	case "abuseipdb":
		var v struct {
			Data *struct {
				Score   int    `json:"abuseConfidenceScore"`
				Reports int    `json:"totalReports"`
				Country string `json:"countryCode"`
				ISP     string `json:"isp"`
			} `json:"data"`
		}
		if e := json.Unmarshal(payload, &v); e != nil {
			return r, e
		}
		if v.Data == nil || v.Data.Score < 0 || v.Data.Score > 100 || v.Data.Reports < 0 {
			return r, errors.New("invalid AbuseIPDB data")
		}
		r.Data["abuse_confidence"] = v.Data.Score
		r.Data["total_reports"] = v.Data.Reports
		r.Data["country"] = v.Data.Country
		r.Data["isp"] = v.Data.ISP
	case "crtsh":
		var v []struct {
			Issuer string `json:"issuer_name"`
			Before string `json:"not_before"`
			After  string `json:"not_after"`
			Name   string `json:"common_name"`
		}
		if e := json.Unmarshal(payload, &v); e != nil {
			return r, e
		}
		if len(v) > 100000 {
			return r, errors.New("certificate count exceeds limit")
		}
		r.Data["certificates"] = v
		r.Data["certificate_count"] = len(v)
	default:
		return r, errors.New("unsupported provider")
	}
	return r, nil
}
