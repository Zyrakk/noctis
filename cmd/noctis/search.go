package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/database"
)

func newSearchCmd() *cobra.Command {
	var configPath string
	var category string
	var tags []string
	var since string
	var author string
	var limit int

	cmd := &cobra.Command{
		Use:   "search [text]",
		Short: "Search the archive for threat intelligence content",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx := context.Background()
			pool, err := database.Connect(ctx, cfg.Database.DSN)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}
			defer pool.Close()

			store := archive.New(pool)

			q := archive.SearchQuery{
				Category: category,
				Tags:     tags,
				Author:   author,
				Limit:    limit,
			}

			if len(args) > 0 {
				q.Text = args[0]
			}

			if since != "" {
				t, err := parseSince(since)
				if err != nil {
					return fmt.Errorf("invalid --since value %q: %w", since, err)
				}
				q.Since = &t
			}

			results, err := store.Search(ctx, q)
			if err != nil {
				return fmt.Errorf("searching archive: %w", err)
			}

			if len(results) == 0 {
				fmt.Println("no results found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tSOURCE\tCATEGORY\tSEVERITY\tCONTENT")
			fmt.Fprintln(w, "---------\t------\t--------\t--------\t-------")

			for _, rc := range results {
				content := rc.Content
				if len(content) > 80 {
					content = content[:80] + "..."
				}

				category := rc.Category
				if category == "" {
					category = "-"
				}
				severity := rc.Severity
				if severity == "" {
					severity = "-"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					rc.CollectedAt.Format("2006-01-02 15:04"),
					rc.SourceType,
					category,
					severity,
					content,
				)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().StringVar(&category, "category", "", "filter by category (e.g. credential_leak, malware)")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "filter by tag (repeatable)")
	cmd.Flags().StringVar(&since, "since", "", "only show content collected since this duration (e.g. 7d, 24h, 1h, 30d)")
	cmd.Flags().StringVar(&author, "author", "", "filter by author/actor handle")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of results (default 50)")

	return cmd
}

func newStatsCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show archive collection statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx := context.Background()
			pool, err := database.Connect(ctx, cfg.Database.DSN)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}
			defer pool.Close()

			store := archive.New(pool)
			stats, err := store.Stats(ctx)
			if err != nil {
				return fmt.Errorf("fetching stats: %w", err)
			}

			fmt.Println("Archive Statistics")
			fmt.Println("==================")
			fmt.Printf("Total content:    %s\n", formatInt(stats.TotalCount))
			fmt.Printf("Classified:        %s\n", formatInt(stats.ClassifiedCount))

			if len(stats.BySource) > 0 {
				fmt.Println()
				fmt.Println("By Source:")
				for src, cnt := range stats.BySource {
					fmt.Printf("  %-16s %s\n", src+":", formatInt(cnt))
				}
			}

			if len(stats.ByCategory) > 0 {
				fmt.Println()
				fmt.Println("By Category:")
				for cat, cnt := range stats.ByCategory {
					fmt.Printf("  %-20s %s\n", cat+":", formatInt(cnt))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}

// parseSince converts a duration string like "7d", "24h", "1h", "30d" into a
// time.Time representing time.Now() minus that duration.
func parseSince(s string) (time.Time, error) {
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("too short: expected a number followed by a unit (h or d)")
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]

	n, err := strconv.Atoi(numStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid number %q: %w", numStr, err)
	}
	if n <= 0 {
		return time.Time{}, fmt.Errorf("duration must be positive, got %d", n)
	}

	switch unit {
	case 'h':
		return time.Now().Add(-time.Duration(n) * time.Hour), nil
	case 'd':
		return time.Now().Add(-time.Duration(n) * 24 * time.Hour), nil
	default:
		return time.Time{}, fmt.Errorf("unknown unit %q: use h (hours) or d (days)", string(unit))
	}
}

// formatInt formats an int64 with comma separators for readability.
func formatInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	// Insert commas every 3 digits from the right.
	result := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range s {
		pos := len(s) - i
		if i > 0 && pos%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
