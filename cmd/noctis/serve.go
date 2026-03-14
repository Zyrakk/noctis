package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/health"
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

			// 6. Set health to ready
			hs.SetReady(true)

			// 7. Log "noctis is ready"
			slog.Info("noctis is ready")

			// Pipeline wiring added in Phase 1 (Task 20)

			// 8. Wait for SIGINT/SIGTERM
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
