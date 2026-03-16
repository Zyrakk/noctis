package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/collector"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/database"
	"github.com/Zyrakk/noctis/internal/discovery"
	"github.com/Zyrakk/noctis/internal/dispatcher"
	"github.com/Zyrakk/noctis/internal/health"
	"github.com/Zyrakk/noctis/internal/ingest"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
)

func newServeCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the noctis daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Load config
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// 2. Validate config
			if err := config.Validate(cfg); err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}

			// 3. Set up slog JSON handler with level from config
			var level slog.Level
			switch cfg.LogLevel {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				level = slog.LevelInfo
			}
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
			slog.SetDefault(logger)

			// 4. Start health server in goroutine
			healthPort := cfg.HealthPort
			if healthPort == 0 {
				healthPort = 8080
			}
			hs := health.NewServer(fmt.Sprintf(":%d", healthPort))
			go func() {
				if err := hs.ListenAndServe(); err != nil {
					slog.Error("health server error", "err", err)
				}
			}()

			// 5. Log "starting noctis" with version
			slog.Info("starting noctis", "version", version)

			// Connect to database
			pool, err := database.Connect(context.Background(), cfg.Database.DSN)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}
			defer pool.Close()

			// Run migrations
			migrations, err := database.LoadMigrations("/migrations")
			if err != nil {
				// Try local path for development
				migrations, err = database.LoadMigrations("migrations")
				if err != nil {
					return fmt.Errorf("loading migrations: %w", err)
				}
			}
			if err := database.RunMigrations(context.Background(), pool, migrations); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}
			slog.Info("database migrations applied")

			// Build archive store
			archiveStore := archive.New(pool)

			// Build LLM client
			llmClient := llm.NewOpenAICompatClient(cfg.LLM.BaseURL, cfg.LLM.APIKey, cfg.LLM.Model)

			// Build Prometheus metrics
			metrics := dispatcher.NewPrometheusMetrics(prometheus.DefaultRegisterer)

			// Build analyzer
			promptsDir := "/prompts"
			if dir := os.Getenv("NOCTIS_PROMPTS_DIR"); dir != "" {
				promptsDir = dir
			}
			llmAnalyzer := analyzer.New(llmClient, promptsDir)

			// Build discovery engine
			discoveryEngine := discovery.NewEngine(pool, cfg.Discovery)

			// Alert callback — called for real-time matched findings
			alertFn := func(ef models.EnrichedFinding) {
				metrics.RecordFinding(ef)
				for _, rule := range ef.MatchedRules {
					metrics.RecordMatcherMatch(rule)
				}
				slog.Info("ALERT: finding dispatched",
					"category", ef.Category,
					"severity", ef.Severity,
					"source", ef.Source,
					"iocs", len(ef.IOCs),
				)
			}

			// Build ingest pipeline
			ingestPipeline, err := ingest.NewIngestPipeline(
				archiveStore,
				cfg.Matching.Rules,
				llmAnalyzer,
				metrics,
				alertFn,
				cfg.Collection,
			)
			if err != nil {
				return fmt.Errorf("creating ingest pipeline: %w", err)
			}

			// Build collectors
			var collectors []collector.Collector

			if cfg.Sources.Paste.Enabled {
				pc := collector.NewPasteCollector(&cfg.Sources.Paste, &cfg.Sources.Tor)
				collectors = append(collectors, pc)
				slog.Info("paste collector enabled")
			}
			if cfg.Sources.Telegram.Enabled {
				tc := collector.NewTelegramCollector(&cfg.Sources.Telegram)
				collectors = append(collectors, tc)
				slog.Info("telegram collector enabled")
			}
			if cfg.Sources.Forums.Enabled {
				fc := collector.NewForumCollector(&cfg.Sources.Forums, &cfg.Sources.Tor)
				collectors = append(collectors, fc)
				slog.Info("forum collector enabled", "sites", len(cfg.Sources.Forums.Sites))
			}
			if cfg.Sources.Web.Enabled {
				wc := collector.NewWebCollector(&cfg.Sources.Web, &cfg.Sources.Tor)
				collectors = append(collectors, wc)
				slog.Info("web/RSS collector enabled", "feeds", len(cfg.Sources.Web.Feeds))
			}

			if len(collectors) == 0 {
				return fmt.Errorf("no collectors enabled")
			}

			// Start everything
			pipelineCtx, pipelineCancel := context.WithCancel(context.Background())
			defer pipelineCancel()

			// Start background workers (classification + entity extraction)
			go ingestPipeline.Run(pipelineCtx)
			slog.Info("background workers started",
				"classification_workers", cfg.Collection.ClassificationWorkers,
				"entity_extraction_workers", cfg.Collection.EntityExtractionWorkers,
			)

			// Start collectors — each feeds findings into the ingest pipeline
			var collectorWg sync.WaitGroup
			for _, c := range collectors {
				collectorWg.Add(1)
				coll := c
				ch := make(chan models.Finding, 50)

				// Collector goroutine
				go func() {
					defer collectorWg.Done()
					if err := coll.Start(pipelineCtx, ch); err != nil && pipelineCtx.Err() == nil {
						slog.Error("collector error", "collector", coll.Name(), "error", err)
					}
				}()

				// Fan-in: read from collector channel, process through ingest pipeline
				collectorWg.Add(1)
				go func() {
					defer collectorWg.Done()
					for f := range ch {
						if err := ingestPipeline.Process(pipelineCtx, f); err != nil {
							slog.Error("ingest error", "error", err)
						}
						// Feed content to discovery engine (inline — fast regex + single DB upsert)
						if cfg.Discovery.Enabled {
							if err := discoveryEngine.ProcessContent(pipelineCtx, f.Content, f.ID); err != nil {
								slog.Debug("discovery error", "error", err)
							}
						}
					}
				}()
			}

			hs.SetReady(true)
			slog.Info("noctis is ready",
				"collectors", len(collectors),
				"archive", cfg.Collection.ArchiveAll,
				"discovery", cfg.Discovery.Enabled,
			)

			// Wait for shutdown signal
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
			slog.Info("received shutdown signal, initiating graceful shutdown")

			// Graceful shutdown
			pipelineCancel()
			collectorWg.Wait()
			slog.Info("noctis shutdown complete")

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}
