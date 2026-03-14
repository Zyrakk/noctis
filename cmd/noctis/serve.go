package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/collector"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/dispatcher"
	"github.com/Zyrakk/noctis/internal/health"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/pipeline"
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

			// Build collectors
			var collectors []collector.Collector

			if cfg.Sources.Paste.Enabled {
				pc := collector.NewPasteCollector(&cfg.Sources.Paste, &cfg.Sources.Tor)
				collectors = append(collectors, pc)
			}
			if cfg.Sources.Telegram.Enabled {
				tc := collector.NewTelegramCollector(&cfg.Sources.Telegram)
				collectors = append(collectors, tc)
			}

			if len(collectors) == 0 {
				return fmt.Errorf("no collectors enabled")
			}

			// Build LLM client
			llmClient := llm.NewOpenAICompatClient(cfg.LLM.BaseURL, cfg.LLM.APIKey, cfg.LLM.Model)

			// Build Prometheus metrics
			metrics := dispatcher.NewPrometheusMetrics(prometheus.DefaultRegisterer)

			// Build pipeline
			dispatchFn := func(ef models.EnrichedFinding) {
				metrics.RecordFinding(ef)
				for _, rule := range ef.MatchedRules {
					metrics.RecordMatcherMatch(rule)
				}
				slog.Info("finding dispatched",
					"category", ef.Category,
					"severity", ef.Severity,
					"source", ef.Source,
					"iocs", len(ef.IOCs),
				)
			}

			promptsDir := "/prompts" // container path; override via env for local dev
			if dir := os.Getenv("NOCTIS_PROMPTS_DIR"); dir != "" {
				promptsDir = dir
			}

			p, err := pipeline.NewPipeline(collectors, cfg.Matching.Rules, llmClient, promptsDir, dispatchFn)
			if err != nil {
				return fmt.Errorf("creating pipeline: %w", err)
			}

			// Start pipeline in background
			pipelineCtx, pipelineCancel := context.WithCancel(context.Background())
			defer pipelineCancel()
			go p.Run(pipelineCtx)

			hs.SetReady(true)
			slog.Info("noctis is ready")

			// 6. Wait for SIGINT/SIGTERM
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
			slog.Info("received shutdown signal")

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}
