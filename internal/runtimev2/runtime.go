package runtimev2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

type Health struct {
	Database     bool     `json:"database"`
	Schema       bool     `json:"schema"`
	Mode         string   `json:"mode"`
	Functional   bool     `json:"functional"`
	AIEnabled    bool     `json:"ai_enabled"`
	Capabilities []string `json:"capabilities"`
}

func Check(ctx context.Context, dsn, mode string) (Health, error) {
	h := Health{Mode: mode, Capabilities: []string{"health_only"}}
	if mode != "api" && mode != "worker" && mode != "collector" {
		return h, fmt.Errorf("invalid v2 mode")
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return h, fmt.Errorf("v2 database unavailable")
	}
	defer c.Close(context.Background())
	if e = db.CheckDatabase(ctx, c); e != nil {
		return h, e
	}
	h.Database = true
	var count int
	e = c.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='noctis_v2' AND table_name IN ('sources','checkpoints','content_blobs','observations','jobs')`).Scan(&count)
	h.Schema = e == nil && count == 5
	if !h.Schema {
		return h, fmt.Errorf("v2 schema unavailable; run v2 migrate explicitly")
	}
	ms, e := db.Load(migrations.Files)
	if e != nil {
		return h, e
	}
	rows, e := c.Query(ctx, `SELECT name,checksum FROM public.noctis_v2_migrations ORDER BY name`)
	if e != nil {
		return h, e
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var name, checksum string
		if e = rows.Scan(&name, &checksum); e != nil {
			return h, e
		}
		if index >= len(ms) || ms[index].Name != name || ms[index].Checksum != checksum {
			return h, fmt.Errorf("v2 schema checksum/version incompatible")
		}
		index++
	}
	if e = rows.Err(); e != nil {
		return h, e
	}
	if index != len(ms) {
		return h, fmt.Errorf("v2 schema requires migration")
	}
	h.Functional = true
	if e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.ai_configs c CROSS JOIN LATERAL jsonb_array_elements(c.body->'bindings') b WHERE c.revision=(SELECT max(revision) FROM noctis_v2.ai_configs) AND (b->>'enabled')::boolean)`).Scan(&h.AIEnabled); e != nil {
		return h, e
	}
	h.Capabilities = []string{"capture", "jobs", "cases", "evidence", "auth", "brief", "inference_jobs", "typed_query"}
	return h, nil
}
func Run(ctx context.Context, cfg configv2.Config) error {
	var handler http.Handler
	var tlsConfig *tls.Config
	var e error
	if cfg.Mode == "api" {
		if e = validateOrigin(cfg.Origin); e != nil {
			return e
		}
		if tlsConfig, e = loadAPITLS(cfg); e != nil {
			return e
		}
		if handler, e = NewHandler(cfg); e != nil {
			return e
		}
	}
	if _, e := Check(ctx, cfg.DatabaseURL, cfg.Mode); e != nil {
		return e
	}
	if cfg.Mode == "worker" || cfg.Mode == "collector" {
		return runLoop(ctx, cfg)
	}
	if cfg.Mode != "api" {
		return fmt.Errorf("invalid mode")
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second}
	ln, e := net.Listen("tcp", cfg.Listen)
	if e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			done <- server.ServeTLS(ln, "", "")
		} else {
			done <- server.Serve(ln)
		}
	}()
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func runLoop(ctx context.Context, cfg configv2.Config) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	worker := intelligence.Worker{DSN: cfg.DatabaseURL, Owner: fmt.Sprintf("%s-%d", cfg.Mode, os.Getpid())}
	allow := map[string]bool{}
	for _, authority := range cfg.FixtureAuthorities {
		allow[authority] = true
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		control, connectErr := pgx.Connect(ctx, cfg.DatabaseURL)
		if connectErr != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			continue
		}
		var paused bool
		controlErr := control.QueryRow(ctx, `SELECT paused FROM noctis_v2.runtime_control`).Scan(&paused)
		control.Close(context.Background())
		if controlErr != nil || paused {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			continue
		}
		if cfg.Mode == "worker" {
			if e := (vulnv2.ApplicabilityWorker{DSN: cfg.DatabaseURL, Owner: worker.Owner + "-applicability"}).Once(ctx); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				slog.Error("v2 applicability page failed", "error", e)
			}
			if e := runAutomaticInference(ctx, cfg); e != nil {
				slog.Error("v2 inference attempt deferred")
			}
			if e := worker.Once(ctx); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				slog.Error("v2 worker attempt failed", "error", e)
			}
			if e := planAutomaticInference(ctx, cfg); e != nil {
				slog.Error("v2 semantic planning deferred")
			}
			if e := worker.Brief(ctx, time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), "mechanical-v1"); e != nil {
				slog.Error("v2 brief deferred", "error", e)
			}
			if cfg.DeliveryEndpoint != "" {
				if e := worker.DispatchOnce(ctx, cfg.DeliveryEndpoint, nil); e != nil && !errors.Is(e, pgx.ErrNoRows) {
					slog.Error("v2 dispatch attempt failed", "error", e)
				}
			}
		} else {
			c, e := pgx.Connect(ctx, cfg.DatabaseURL)
			if e != nil {
				return e
			}
			rows, e := c.Query(ctx, `SELECT id::text FROM noctis_v2.sources s WHERE `+intelligence.SourceAuthorizedSQL+` AND kind IN ('rss','atom','nvd','kev','epss','html','paste','forum') AND poll_after<=clock_timestamp() ORDER BY id`)
			if e != nil {
				c.Close(ctx)
				return e
			}
			ids := []string{}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					c.Close(ctx)
					return e
				}
				ids = append(ids, id)
			}
			e = rows.Err()
			rows.Close()
			c.Close(ctx)
			if e != nil {
				return e
			}
			for _, id := range ids {
				if e := pollSource(ctx, cfg.DatabaseURL, id, capture.Fetcher{AllowLocal: allow}); e != nil && !errors.Is(e, capture.ErrConflict) {
					c, connectErr := pgx.Connect(ctx, cfg.DatabaseURL)
					if connectErr != nil {
						return connectErr
					}
					_, writeErr := c.Exec(ctx, `UPDATE noctis_v2.sources SET last_error=$2,coverage='gap_unknown' WHERE id=$1`, id, e.Error())
					c.Close(context.Background())
					if writeErr != nil {
						return writeErr
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func runAutomaticInference(ctx context.Context, cfg configv2.Config) error {
	if !cfg.AutomaticInference && !cfg.ManualInference {
		return nil
	}
	store := inferenceStore(cfg)
	var err error
	if cfg.AutomaticInference {
		err = store.Once(ctx)
	} else {
		err = store.OnceManual(ctx)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func planAutomaticInference(ctx context.Context, cfg configv2.Config) error {
	if !cfg.AutomaticInference {
		return nil
	}
	return inferenceStore(cfg).PlanEligible(ctx)
}

func pollSource(ctx context.Context, dsn, id string, fetcher capture.Fetcher) error {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	var kind, endpoint string
	e = c.QueryRow(ctx, `SELECT kind,native_id FROM noctis_v2.sources s WHERE id=$1 AND `+intelligence.SourceAuthorizedSQL+``, id).Scan(&kind, &endpoint)
	if e != nil {
		return e
	}
	if kind == "rss" || kind == "atom" {
		return (capture.Store{DSN: dsn}).Poll(ctx, id, fetcher)
	}
	if kind == "html" || kind == "paste" || kind == "forum" {
		return (capture.Store{DSN: dsn}).PollWeb(ctx, id, fetcher)
	}
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.sources SET poll_after=clock_timestamp()+interval '30 seconds' WHERE id=$1 AND enabled AND poll_after<=clock_timestamp()`, id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	r, e := (vulnv2.Store{DSN: dsn, Fetcher: fetcher}).PollPage(ctx, kind, endpoint, 24*time.Hour)
	if e != nil {
		return e
	}
	delay := 30 * time.Second
	if r.Complete {
		delay = 24 * time.Hour
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET poll_after=clock_timestamp()+$2::interval,last_success_at=clock_timestamp(),last_error=NULL,coverage='structured_feed; applicability_requires_inventory' WHERE id=$1`, id, delay.String())
	return e
}
