package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/brain"
	"github.com/Zyrakk/noctis/internal/collector"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/dashboard"
	"github.com/Zyrakk/noctis/internal/database"
	"github.com/Zyrakk/noctis/internal/discovery"
	"github.com/Zyrakk/noctis/internal/dispatcher"
	"github.com/Zyrakk/noctis/internal/health"
	"github.com/Zyrakk/noctis/internal/ingest"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
	"github.com/Zyrakk/noctis/internal/enrichment"
	"github.com/Zyrakk/noctis/internal/processor"
	"github.com/Zyrakk/noctis/internal/vuln"
)

// queryEngineAdapter wraps brain.QueryEngine to satisfy dashboard.NLQueryEngine.
type queryEngineAdapter struct {
	engine *brain.QueryEngine
}

func (a *queryEngineAdapter) Query(ctx context.Context, question string) (*dashboard.NLQueryResult, error) {
	result, err := a.engine.Query(ctx, question)
	if err != nil {
		return nil, err
	}
	return &dashboard.NLQueryResult{
		Query:    result.Query,
		SQL:      result.SQL,
		Columns:  result.Columns,
		Rows:     result.Rows,
		RowCount: result.RowCount,
		Duration: result.Duration,
	}, nil
}

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
			qrAuth := &health.QRAuthState{}
			hs := health.NewServer(fmt.Sprintf(":%d", healthPort), qrAuth)
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

			// Build module registry for status tracking.
			registry := modules.NewRegistry()

			// Start dashboard server if enabled
			var dashServer *dashboard.Server
			if cfg.Dashboard.Enabled {
				dashPort := cfg.Dashboard.Port
				if dashPort == 0 {
					dashPort = 3000
				}
				dashServer = dashboard.NewServer(fmt.Sprintf(":%d", dashPort), pool, cfg.Dashboard.APIKey, registry)
				go func() {
					if err := dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						slog.Error("dashboard server error", "err", err)
					}
				}()
				slog.Info("dashboard enabled", "port", dashPort)
			}

			// Build archive store
			archiveStore := archive.New(pool)

			// Build LLM clients
			// GLM — smart model for entity extraction and sub-classification
			fullClient := llm.NewOpenAICompatClient(cfg.LLM.BaseURL, cfg.LLM.APIKey, cfg.LLM.Model)
			fullClient.SetRateLimiter(llm.NewRateLimiter(cfg.LLM.TokensPerMinute, 0))

			// Build Prometheus metrics
			metrics := dispatcher.NewPrometheusMetrics(prometheus.DefaultRegisterer)

			// Build analyzers
			promptsDir := "/prompts"
			if dir := os.Getenv("NOCTIS_PROMPTS_DIR"); dir != "" {
				promptsDir = dir
			}
			fullAnalyzer := analyzer.New(fullClient, promptsDir)

			// Fast model for classification (falls back to full if unconfigured)
			var classifyAnalyzer *analyzer.Analyzer
			if cfg.LLMFast.Model != "" {
				fastClient := llm.NewOpenAICompatClient(cfg.LLMFast.BaseURL, cfg.LLMFast.APIKey, cfg.LLMFast.Model)
				fastClient.SetRateLimiter(llm.NewRateLimiter(cfg.LLMFast.TokensPerMinute, cfg.LLMFast.TokensPerDay))
				classifyAnalyzer = analyzer.New(fastClient, promptsDir)
				slog.Info("dual LLM mode", "fast", cfg.LLMFast.Model, "full", cfg.LLM.Model)
			} else {
				classifyAnalyzer = fullAnalyzer
				slog.Info("single LLM mode", "model", cfg.LLM.Model)
			}

			// Resolve concurrency limits.
			classifyConcurrency := cfg.LLMFast.MaxConcurrency
			if classifyConcurrency <= 0 {
				classifyConcurrency = cfg.LLM.MaxConcurrent
			}
			if classifyConcurrency <= 0 {
				classifyConcurrency = 2
			}
			extractConcurrency := cfg.LLM.MaxConcurrent
			if extractConcurrency <= 0 {
				extractConcurrency = 2
			}

			// Build discovery engine
			discoveryEngine := discovery.NewEngine(pool, cfg.Discovery)

			// Register monitored Telegram channels so discovery skips them.
			if cfg.Sources.Telegram.Enabled {
				var usernames []string
				for _, ch := range cfg.Sources.Telegram.Channels {
					if ch.Username != "" {
						usernames = append(usernames, ch.Username)
					}
				}
				if len(usernames) > 0 {
					discoveryEngine.SetMonitoredChannels(usernames)
				}
			}

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

			// Resolve classify provider/model (falls back to full LLM in single-mode).
			classifyProvider := cfg.LLMFast.Provider
			classifyModel := cfg.LLMFast.Model
			if classifyModel == "" {
				classifyProvider = cfg.LLM.Provider
				classifyModel = cfg.LLM.Model
			}

			// Build processing engine (classification + entity extraction).
			processingEngine := processor.NewProcessingEngine(
				archiveStore,
				classifyAnalyzer,
				fullAnalyzer,
				cfg.Collection,
				registry,
				classifyProvider, classifyModel,
				cfg.LLM.Provider, cfg.LLM.Model,
				classifyConcurrency,
				extractConcurrency,
				cfg.IOCLifecycle,
			)

			// Brain analyzer — Gemini 3.1 Pro for analytical reasoning (falls back to full LLM).
			var brainAnalyzer *analyzer.Analyzer
			var brainProvider, brainModel string
			var brainSpending *llm.SpendingTracker
			brainConcurrency := 1
			if cfg.LLMBrain.BaseURL != "" {
				brainClient := llm.NewOpenAICompatClient(cfg.LLMBrain.BaseURL, cfg.LLMBrain.APIKey, cfg.LLMBrain.Model)
				brainClient.SetRateLimiter(llm.NewRateLimiter(cfg.LLMBrain.TokensPerMinute, 0))
				if cfg.LLMBrain.MonthlyBudgetUSD > 0 {
					brainSpending = llm.NewSpendingTracker(
						cfg.LLMBrain.InputCostPer1M,
						cfg.LLMBrain.OutputCostPer1M,
						cfg.LLMBrain.MonthlyBudgetUSD,
					)
					brainClient.SetSpendingTracker(brainSpending)
					slog.Info("brain spending tracker enabled",
						"budget_usd", cfg.LLMBrain.MonthlyBudgetUSD,
						"input_cost_per_1m", cfg.LLMBrain.InputCostPer1M,
						"output_cost_per_1m", cfg.LLMBrain.OutputCostPer1M,
					)
				}
				brainAnalyzer = analyzer.New(brainClient, promptsDir)
				brainProvider = cfg.LLMBrain.Provider
				brainModel = cfg.LLMBrain.Model
				if cfg.LLMBrain.MaxConcurrent > 0 {
					brainConcurrency = cfg.LLMBrain.MaxConcurrent
				}
				slog.Info("brain analyzer configured", "provider", brainProvider, "model", brainModel)
			} else {
				brainAnalyzer = fullAnalyzer
				brainProvider = cfg.LLM.Provider
				brainModel = cfg.LLM.Model
				slog.Info("brain analyzer: reusing full analyzer")
			}

			// Build intelligence brain (correlation + analyst engines).
			intelligenceBrain := brain.NewBrain(
				archiveStore,
				cfg.Correlation,
				cfg.Analyst,
				brainAnalyzer,
				archiveStore,
				registry,
				brainProvider, brainModel,
				brainConcurrency,
				cfg.BriefGenerator,
			)

			// Create natural language query engine (on-demand, not periodic).
			queryEngine := brain.NewQueryEngine(brainAnalyzer, pool, brainConcurrency, brainProvider, brainModel)
			registry.Register(queryEngine.Status())
			if dashServer != nil {
				dashServer.SetQueryEngine(&queryEngineAdapter{engine: queryEngine})
				if brainSpending != nil {
					dashServer.SetSpendingTracker(brainSpending)
				}
			}

			// Build ingest pipeline (real-time matching + alert path only).
			ingestPipeline, err := ingest.NewIngestPipeline(
				archiveStore,
				cfg.Matching.Rules,
				classifyAnalyzer,
				fullAnalyzer,
				metrics,
				alertFn,
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
				tc := collector.NewTelegramCollector(&cfg.Sources.Telegram, qrAuth, discoveryEngine)
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

			// Start processing engine (classification + entity extraction workers).
			go processingEngine.Run(pipelineCtx)
			slog.Info("processing engine started",
				"classification_workers", cfg.Collection.ClassificationWorkers,
				"entity_extraction_workers", cfg.Collection.EntityExtractionWorkers,
			)

			// Start intelligence brain (correlation + analyst engines).
			go intelligenceBrain.Run(pipelineCtx)

			// Start source value analyzer.
			sourceAnalyzer := collector.NewSourceValueAnalyzer(pool)
			registry.Register(sourceAnalyzer.Status())
			go sourceAnalyzer.Run(pipelineCtx)

			// Start vulnerability intelligence ingestor.
			vulnIngestor := vuln.NewVulnIngestor(archiveStore, cfg.Vuln)
			registry.Register(vulnIngestor.Status())
			go vulnIngestor.Run(pipelineCtx)

			// Start IOC enrichment pipeline.
			var enrichProviders []enrichment.EnrichmentProvider
			if cfg.Enrichment.AbuseIPDBKey != "" {
				enrichProviders = append(enrichProviders, enrichment.NewAbuseIPDBProvider(cfg.Enrichment.AbuseIPDBKey))
			}
			if cfg.Enrichment.VirusTotalKey != "" {
				enrichProviders = append(enrichProviders, enrichment.NewVirusTotalProvider(cfg.Enrichment.VirusTotalKey))
			}
			enrichProviders = append(enrichProviders, enrichment.NewCRTShProvider())

			enricher := enrichment.NewEnricher(archiveStore, cfg.Enrichment, enrichProviders)
			registry.Register(enricher.Status())
			go enricher.Run(pipelineCtx)

			// Start source triage worker (AI classification of unknown URLs).
			if cfg.Discovery.TriageEnabled {
				triageWorker := discovery.NewTriageWorker(pool, classifyAnalyzer, cfg.Discovery.TriageBatchSize, classifyModel, discoveryEngine)
				registry.Register(triageWorker.Status())
				go triageWorker.Run(pipelineCtx)
				slog.Info("triage worker enabled", "batch_size", cfg.Discovery.TriageBatchSize)
			}

			// Build collector manager with status tracking.
			collectorMgr := collector.NewCollectorManager(
				collectors,
				registry,
				func(ctx context.Context, f models.Finding) error {
					return ingestPipeline.Process(ctx, f)
				},
				func(ctx context.Context, content string, findingID string) error {
					if cfg.Discovery.Enabled {
						return discoveryEngine.ProcessContent(ctx, content, findingID)
					}
					return nil
				},
			)

			// Start collectors.
			collectorDone := make(chan struct{})
			go func() {
				collectorMgr.Run(pipelineCtx)
				close(collectorDone)
			}()

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
			if dashServer != nil {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				dashServer.Shutdown(shutdownCtx)
			}
			pipelineCancel()
			<-collectorDone
			slog.Info("noctis shutdown complete")

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}
