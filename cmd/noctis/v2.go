package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/Zyrakk/noctis/internal/runtimev2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func newV2Cmd() *cobra.Command {
	root := &cobra.Command{Use: "v2", Short: "Independent evidence product; inference requires explicit per-function configuration"}
	var dbRef, mode, listen string
	var admin, origin, cert, key, deliveryEndpoint string
	var fixtureAuthorities []string
	var aiKeyFile, aiCAFile string
	var aiAuthorities []string
	var automaticInference bool
	root.PersistentFlags().StringVar(&dbRef, "database-secret-file", "", "File containing independent v2 database DSN")
	serve := &cobra.Command{Use: "serve", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load(mode, listen, dbRef)
		if e != nil {
			return e
		}
		cfg.AdminFile = admin
		cfg.Origin = origin
		cfg.TLSCert = cert
		cfg.TLSKey = key
		cfg.FixtureAuthorities = fixtureAuthorities
		cfg.DeliveryEndpoint = deliveryEndpoint
		cfg.AIKeyFile = aiKeyFile
		cfg.AICAFile = aiCAFile
		cfg.AIAuthorities = aiAuthorities
		cfg.AutomaticInference = automaticInference
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return runtimev2.Run(ctx, cfg)
	}}
	serve.Flags().StringVar(&mode, "mode", "api", "api, worker or collector")
	serve.Flags().BoolVar(&automaticInference, "automatic-inference", false, "Explicitly enable automatic paid inference execution and planning (worker only)")
	serve.Flags().StringVar(&aiKeyFile, "ai-master-key-file", "", "Mounted private AEAD key JSON (key_id, hex key); outside PostgreSQL")
	serve.Flags().StringVar(&aiCAFile, "ai-ca-file", "", "Server-mounted additional inference TLS trust root")
	serve.Flags().StringSliceVar(&aiAuthorities, "ai-local-authority", nil, "Server-authorized exact local inference host:port")
	serve.Flags().StringVar(&admin, "admin-secret-file", "", "Mounted JSON username/password")
	serve.Flags().StringVar(&origin, "origin", "", "Canonical browser Origin")
	serve.Flags().StringVar(&cert, "tls-cert-file", "", "TLS certificate file")
	serve.Flags().StringVar(&key, "tls-key-file", "", "TLS private key file")
	serve.Flags().StringVar(&deliveryEndpoint, "delivery-endpoint", "", "Explicit worker outbox destination; uncertain attempts never replay automatically")
	serve.Flags().StringSliceVar(&fixtureAuthorities, "fixture-authority", nil, "Explicit local fixture host:port allowlist (collector only)")
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:8081", "Health API listen address")
	migrate := &cobra.Command{Use: "migrate", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load("api", "", dbRef)
		if e != nil {
			return e
		}
		ms, e := db.Load(migrations.Files)
		if e != nil {
			return e
		}
		return db.Migrate(cmd.Context(), cfg.DatabaseURL, ms)
	}}
	connect := func(ctx context.Context) (*pgx.Conn, string, error) {
		cfg, e := configv2.Load("api", "", dbRef)
		if e != nil {
			return nil, "", e
		}
		c, e := pgx.Connect(ctx, cfg.DatabaseURL)
		return c, cfg.DatabaseURL, e
	}
	policy := &cobra.Command{Use: "policy VERSION TERMS_JSON_FILE", Args: cobra.ExactArgs(2), Short: "Create immutable PIR/watchlist version", RunE: func(cmd *cobra.Command, args []string) error {
		raw, e := os.ReadFile(args[1])
		if e != nil {
			return e
		}
		var terms []intelligence.Term
		if e = json.Unmarshal(raw, &terms); e != nil {
			return e
		}
		for _, t := range terms {
			if t.Type == "" || t.Value == "" {
				return fmt.Errorf("invalid term")
			}
		}
		c, _, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		defer c.Close(context.Background())
		_, e = c.Exec(cmd.Context(), `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,$2)`, args[0], string(raw))
		return e
	}}
	source := &cobra.Command{Use: "source KIND URL NAME POLICY", Args: cobra.ExactArgs(4), Short: "Register enabled RSS/Atom source with fresh epoch", RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "rss" && args[0] != "atom" && args[0] != "html" && args[0] != "paste" && args[0] != "forum" {
			return fmt.Errorf("unsupported source kind")
		}
		c, _, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		defer c.Close(context.Background())
		id := uuid.NewString()
		tag, e := c.Exec(cmd.Context(), `INSERT INTO noctis_v2.sources(id,kind,native_id,name,policy_version,enabled,epoch,activated_at) SELECT $1,$2,$3,$4,version,true,$6,clock_timestamp() FROM noctis_v2.policies WHERE version=$5`, id, args[0], args[1], args[2], args[3], uuid.NewString())
		if e == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("policy version not found")
		}
		if e == nil {
			if args[0] == "html" || args[0] == "paste" || args[0] == "forum" {
				_, e = c.Exec(cmd.Context(), `UPDATE noctis_v2.sources SET adapter_config='{"parser_version":"web-text-v1","max_items":100}' WHERE id=$1`, id)
				if e != nil {
					return e
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), id)
		}
		return e
	}}
	captureCmd := &cobra.Command{Use: "capture BATCH_JSON_FILE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		raw, e := os.ReadFile(args[0])
		if e != nil {
			return e
		}
		var b capture.Batch
		if e = json.Unmarshal(raw, &b); e != nil {
			return e
		}
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		receipt, e := (capture.Store{DSN: dsn}).CommitBatch(cmd.Context(), b)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(receipt)
	}}
	var pollAllow []string
	poll := &cobra.Command{Use: "poll SOURCE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		allow := map[string]bool{}
		for _, v := range pollAllow {
			allow[v] = true
		}
		return (capture.Store{DSN: dsn}).Poll(cmd.Context(), args[0], capture.Fetcher{AllowLocal: allow})
	}}
	poll.Flags().StringSliceVar(&pollAllow, "fixture-authority", nil, "Server-authorized local fixture host:port")
	run := &cobra.Command{Use: "run-once", RunE: func(cmd *cobra.Command, args []string) error {
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		return (intelligence.Worker{DSN: dsn, Owner: uuid.NewString()}).Once(cmd.Context())
	}}
	brief := &cobra.Command{Use: "brief PERIOD POLICY", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		return (intelligence.Worker{DSN: dsn}).Brief(cmd.Context(), args[0], args[1])
	}}
	replay := &cobra.Command{Use: "replay JOB_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		return (jobs.Store{DSN: dsn}).Replay(cmd.Context(), args[0])
	}}
	dispatch := &cobra.Command{Use: "dispatch-once ENDPOINT", Args: cobra.ExactArgs(1), Short: "Explicitly deliver one queued event; uncertainty never auto-retried", RunE: func(cmd *cobra.Command, args []string) error {
		c, dsn, e := connect(cmd.Context())
		if e != nil {
			return e
		}
		c.Close(context.Background())
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		return (intelligence.Worker{DSN: dsn}).DispatchOnce(ctx, args[0], nil)
	}}
	root.AddCommand(serve, migrate, policy, source, captureCmd, poll, run, brief, replay, dispatch)
	root.AddCommand(channelsCommands(&dbRef)...)
	root.AddCommand(domainCommands(&dbRef)...)
	return root
}
