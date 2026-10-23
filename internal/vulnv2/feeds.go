// Package vulnv2 retains structured provider facts and their snapshot provenance.
// A CVE mention, KEV listing or EPSS score never establishes local exposure.
package vulnv2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var Endpoints = map[string]string{"nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0", "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "epss": "https://api.first.org/data/v1/epss"}

type Cursor struct {
	Offset      int       `json:"offset"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}
type Fact struct {
	CVE           string          `json:"cve"`
	Body          json.RawMessage `json:"body"`
	Applicability string          `json:"applicability"`
}
type Page struct {
	AsOf     time.Time
	Facts    []Fact
	Next     Cursor
	Complete bool
}
type Receipt struct {
	SnapshotID string `json:"snapshot_id"`
	Hash       string `json:"hash"`
	Facts      int    `json:"facts"`
	Complete   bool   `json:"complete"`
	Cursor     Cursor `json:"cursor"`
}
type Store struct {
	DSN     string
	Fetcher capture.Fetcher
}

func parseTime(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999", "2006-01-02"} {
		if t, e := time.Parse(layout, raw); e == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid feed as_of")
}
func Parse(kind string, payload []byte, current Cursor) (Page, error) {
	p := Page{Next: current}
	if !json.Valid(payload) {
		return p, errors.New("invalid feed JSON")
	}
	add := func(cve string, body json.RawMessage) error {
		if !cvePattern.MatchString(cve) {
			return errors.New("invalid feed CVE")
		}
		p.Facts = append(p.Facts, Fact{CVE: cve, Body: body, Applicability: "unknown"})
		return nil
	}
	switch kind {
	case "nvd":
		var r struct {
			Start           int    `json:"startIndex"`
			Total           int    `json:"totalResults"`
			PerPage         int    `json:"resultsPerPage"`
			Timestamp       string `json:"timestamp"`
			Vulnerabilities []struct {
				CVE json.RawMessage `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if e := json.Unmarshal(payload, &r); e != nil {
			return p, e
		}
		if r.Start != current.Offset || r.Total < 0 || len(r.Vulnerabilities) > 2000 || (len(r.Vulnerabilities) == 0 && r.Start < r.Total) {
			return p, errors.New("invalid NVD page cursor")
		}
		var e error
		p.AsOf, e = parseTime(r.Timestamp)
		if e != nil {
			return p, e
		}
		for _, v := range r.Vulnerabilities {
			var c struct {
				ID string `json:"id"`
			}
			if e = json.Unmarshal(v.CVE, &c); e != nil {
				return p, e
			}
			if e = add(c.ID, v.CVE); e != nil {
				return p, e
			}
		}
		p.Next.Offset = r.Start + len(r.Vulnerabilities)
		p.Complete = p.Next.Offset >= r.Total
	case "kev":
		var r struct {
			DateReleased    string            `json:"dateReleased"`
			Count           int               `json:"count"`
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		}
		if e := json.Unmarshal(payload, &r); e != nil {
			return p, e
		}
		if r.Count != len(r.Vulnerabilities) {
			return p, errors.New("KEV count mismatch")
		}
		var e error
		p.AsOf, e = parseTime(r.DateReleased)
		if e != nil {
			return p, e
		}
		for _, raw := range r.Vulnerabilities {
			var v struct {
				ID    string `json:"cveID"`
				Added string `json:"dateAdded"`
				Due   string `json:"dueDate"`
			}
			if e = json.Unmarshal(raw, &v); e != nil {
				return p, e
			}
			if _, e = parseTime(v.Added); e != nil {
				return p, e
			}
			if _, e = parseTime(v.Due); e != nil {
				return p, e
			}
			if e = add(v.ID, raw); e != nil {
				return p, e
			}
		}
		p.Complete = true
		p.Next.Offset = len(r.Vulnerabilities)
	case "epss":
		var r struct {
			Status string            `json:"status"`
			Total  int               `json:"total"`
			Offset int               `json:"offset"`
			Data   []json.RawMessage `json:"data"`
		}
		if e := json.Unmarshal(payload, &r); e != nil {
			return p, e
		}
		if r.Status != "OK" || r.Offset != current.Offset || r.Total < 0 || (len(r.Data) == 0 && r.Offset < r.Total) {
			return p, errors.New("invalid EPSS page")
		}
		for _, raw := range r.Data {
			var v struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			}
			if e := json.Unmarshal(raw, &v); e != nil {
				return p, e
			}
			for _, s := range []string{v.EPSS, v.Percentile} {
				f, e := strconv.ParseFloat(s, 64)
				if e != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
					return p, errors.New("invalid EPSS score")
				}
			}
			asOf, e := parseTime(v.Date)
			if e != nil {
				return p, e
			}
			if p.AsOf.IsZero() {
				p.AsOf = asOf
			} else if !p.AsOf.Equal(asOf) {
				return p, errors.New("EPSS page dates differ")
			}
			if e = add(v.CVE, raw); e != nil {
				return p, e
			}
		}
		if p.AsOf.IsZero() {
			return p, errors.New("EPSS date absent")
		}
		p.Next.Offset = r.Offset + len(r.Data)
		p.Complete = p.Next.Offset >= r.Total
	default:
		return p, errors.New("unsupported feed")
	}
	if len(p.Facts) > 100000 {
		return p, errors.New("feed record limit")
	}
	seen := map[string]bool{}
	for _, f := range p.Facts {
		if seen[f.CVE] {
			return p, errors.New("duplicate CVE in feed page")
		}
		seen[f.CVE] = true
	}
	return p, nil
}

func (s Store) PollPage(ctx context.Context, kind, endpoint string, ttl time.Duration) (Receipt, error) {
	var receipt Receipt
	if Endpoints[kind] == "" || ttl <= 0 || ttl > 7*24*time.Hour {
		return receipt, errors.New("feed kind/TTL invalid")
	}
	if endpoint == "" {
		endpoint = Endpoints[kind]
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.User != nil || u.Fragment != "" {
		return receipt, errors.New("invalid feed endpoint")
	}
	if endpoint != Endpoints[kind] && !s.Fetcher.AllowLocal[u.Host] {
		return receipt, errors.New("feed endpoint must be official or server fixture allowlist")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return receipt, e
	}
	defer c.Close(context.Background())
	current := Cursor{}
	var previous []byte
	e = c.QueryRow(ctx, `SELECT cursor FROM noctis_v2.feed_cursors WHERE kind=$1 AND url=$2`, kind, endpoint).Scan(&previous)
	if e == nil {
		if e = json.Unmarshal(previous, &current); e != nil {
			return receipt, e
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return receipt, e
	}
	now := time.Now().UTC()
	if current.WindowEnd.IsZero() {
		current.WindowEnd = now
		if current.WindowStart.IsZero() {
			current.WindowStart = now.Add(-24 * time.Hour)
		}
		if current.WindowEnd.Sub(current.WindowStart) > 120*24*time.Hour {
			current.WindowEnd = current.WindowStart.Add(120 * 24 * time.Hour)
		}
	}
	q := u.Query()
	switch kind {
	case "nvd":
		q.Set("startIndex", strconv.Itoa(current.Offset))
		q.Set("resultsPerPage", "100")
		q.Set("lastModStartDate", current.WindowStart.Format("2006-01-02T15:04:05.000"))
		q.Set("lastModEndDate", current.WindowEnd.Format("2006-01-02T15:04:05.000"))
	case "epss":
		q.Set("offset", strconv.Itoa(current.Offset))
		q.Set("limit", "100")
		q.Set("date", current.WindowEnd.Format("2006-01-02"))
	}
	u.RawQuery = q.Encode()
	payload, e := s.Fetcher.Get(ctx, u.String())
	if e != nil {
		return receipt, e
	}
	page, e := Parse(kind, payload, current)
	if e != nil {
		return receipt, e
	}
	if page.AsOf.After(now.Add(5 * time.Minute)) {
		return receipt, errors.New("feed snapshot is future dated")
	}
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	snapshot := uuid.NewSHA1(uuid.NameSpaceOID, []byte(kind+":"+endpoint+":"+hash)).String()
	next := page.Next
	if page.Complete {
		next.Offset = 0
		next.WindowStart = current.WindowEnd
		next.WindowEnd = time.Time{}
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return receipt, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,11))`, kind+":"+endpoint); e != nil {
		return receipt, e
	}
	var actual []byte
	e = tx.QueryRow(ctx, `SELECT cursor FROM noctis_v2.feed_cursors WHERE kind=$1 AND url=$2`, kind, endpoint).Scan(&actual)
	if e == nil && string(actual) != string(previous) {
		return receipt, errors.New("feed cursor changed")
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return receipt, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.feed_snapshots(id,kind,url,hash,as_of,expires_at,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, snapshot, kind, endpoint, hash, page.AsOf, page.AsOf.Add(ttl), string(payload))
	if e != nil {
		return receipt, e
	}
	for _, f := range page.Facts {
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, snapshot, strings.ToUpper(f.CVE), string(f.Body)); e != nil {
			return receipt, e
		}
		if kind == "nvd" {
			if e = RefreshApplicabilityTx(ctx, tx, f.CVE); e != nil {
				return receipt, e
			}
		}
	}
	encoded, _ := json.Marshal(next)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.feed_cursors VALUES($1,$2,$3,$4) ON CONFLICT(kind,url) DO UPDATE SET cursor=EXCLUDED.cursor,snapshot_id=EXCLUDED.snapshot_id`, kind, endpoint, string(encoded), snapshot)
	if e != nil {
		return receipt, e
	}
	if e = tx.Commit(ctx); e != nil {
		return receipt, e
	}
	return Receipt{SnapshotID: snapshot, Hash: hash, Facts: len(page.Facts), Complete: page.Complete, Cursor: next}, nil
}
