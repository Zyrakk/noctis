package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/database"
	"github.com/Zyrakk/noctis/internal/discovery"
)

func newSourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Manage threat intelligence sources",
	}

	cmd.AddCommand(newSourceListCmd())
	cmd.AddCommand(newSourceAddCmd())
	cmd.AddCommand(newSourceApproveCmd())
	cmd.AddCommand(newSourcePauseCmd())
	cmd.AddCommand(newSourceRemoveCmd())

	return cmd
}

func newSourceListCmd() *cobra.Command {
	var configPath string
	var status string
	var sourceType string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all known sources",
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			sources, err := eng.ListSources(ctx, status, sourceType)
			if err != nil {
				return fmt.Errorf("listing sources: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTYPE\tIDENTIFIER\tSTATUS\tLAST COLLECTED\tERRORS")
			fmt.Fprintln(w, "--\t----\t----------\t------\t--------------\t------")

			for _, s := range sources {
				shortID := s.ID
				if len(shortID) > 8 {
					shortID = shortID[:8]
				}

				lastCollected := "never"
				if s.LastCollected != nil {
					lastCollected = s.LastCollected.Format("2006-01-02 15:04")
				}

				identifier := s.Identifier
				if len(identifier) > 40 {
					identifier = identifier[:37] + "..."
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
					shortID,
					s.Type,
					identifier,
					s.Status,
					lastCollected,
					s.ErrorCount,
				)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().StringVar(&status, "status", "", "filter by status (discovered, approved, active, paused, dead, banned)")
	cmd.Flags().StringVar(&sourceType, "type", "", "filter by type (telegram_channel, telegram_group, forum, paste_site, web, rss)")

	return cmd
}

func newSourceApproveCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a discovered source for collection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			if err := eng.ApproveSource(ctx, args[0]); err != nil {
				return fmt.Errorf("approving source: %w", err)
			}

			fmt.Printf("source %s approved\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}

func newSourcePauseCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "pause <id>",
		Short: "Pause collection from a source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			if err := eng.PauseSource(ctx, args[0]); err != nil {
				return fmt.Errorf("pausing source: %w", err)
			}

			fmt.Printf("source %s paused\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}

func newSourceRemoveCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "remove <id>",
		Short: "Permanently remove a source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			if err := eng.RemoveSource(ctx, args[0]); err != nil {
				return fmt.Errorf("removing source: %w", err)
			}

			fmt.Printf("source %s removed\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}

func newSourceAddCmd() *cobra.Command {
	var configPath string
	var sourceType string
	var identifier string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new source for collection",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sourceType == "" {
				return fmt.Errorf("--type is required")
			}
			if identifier == "" {
				return fmt.Errorf("--identifier is required")
			}

			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			id, err := eng.AddSource(ctx, sourceType, identifier)
			if err != nil {
				return fmt.Errorf("adding source: %w", err)
			}

			shortID := id
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			fmt.Printf("source %s added (type=%s, identifier=%s, status=active)\n", shortID, sourceType, identifier)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().StringVar(&sourceType, "type", "", "source type (telegram_channel, telegram_group, forum, paste_site, web, rss)")
	cmd.Flags().StringVar(&identifier, "identifier", "", "source identifier (username for telegram, URL for others)")

	return cmd
}

// getDiscoveryEngine loads config, connects to the database, and returns a
// ready-to-use discovery.Engine along with a cleanup function that closes the
// connection pool. The caller must call cleanup() when done.
func getDiscoveryEngine(configPath string) (*discovery.Engine, func(), error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}

	ctx := context.Background()
	pool, err := database.Connect(ctx, cfg.Database.DSN)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to database: %w", err)
	}

	cleanup := func() { pool.Close() }
	eng := discovery.NewEngine(pool, cfg.Discovery)
	return eng, cleanup, nil
}
