package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/database"
	"github.com/Zyrakk/noctis/internal/models"
)

func newIOCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ioc",
		Short: "Manage indicators of compromise",
	}

	cmd.AddCommand(newIOCCleanupCmd())

	return cmd
}

func newIOCCleanupCmd() *cobra.Command {
	var configPath string
	var dnsTimeout time.Duration
	var concurrency int

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Deactivate placeholder/fake IOCs via pattern matching and DNS resolution",
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

			// Phase 1: SQL pattern cleanup.
			fmt.Println("Phase 1: pattern-based cleanup...")
			patternCount, err := store.CleanupIOCsByPattern(ctx)
			if err != nil {
				return fmt.Errorf("pattern cleanup: %w", err)
			}
			fmt.Printf("  deactivated %d IOCs by pattern\n", patternCount)

			// Phase 2: DNS resolution for remaining domain/url IOCs.
			fmt.Println("Phase 2: DNS resolution cleanup...")
			iocs, err := store.ListActiveIOCsByType(ctx, []string{
				models.IOCTypeDomain,
				models.IOCTypeURL,
			})
			if err != nil {
				return fmt.Errorf("listing active IOCs: %w", err)
			}

			fmt.Printf("  checking %d domain/url IOCs...\n", len(iocs))

			var dnsDeactivated atomic.Int64
			var kept atomic.Int64
			sem := make(chan struct{}, concurrency)
			var wg sync.WaitGroup
			resolver := &net.Resolver{}

			for _, ioc := range iocs {
				domain := extractIOCDomain(ioc.Value, ioc.Type)
				if domain == "" {
					continue
				}

				// Skip .onion domains.
				if strings.HasSuffix(strings.ToLower(domain), ".onion") {
					kept.Add(1)
					continue
				}

				// Skip if domain is an IP address.
				if net.ParseIP(domain) != nil {
					kept.Add(1)
					continue
				}

				wg.Add(1)
				go func(iocType, iocValue, host string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					dnsCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
					defer cancel()

					addrs, err := resolver.LookupHost(dnsCtx, host)
					if err != nil || len(addrs) == 0 {
						// NXDOMAIN — deactivate.
						if dbErr := store.DeactivateIOC(ctx, iocType, iocValue); dbErr != nil {
							log.Printf("  error deactivating %s %s: %v", iocType, iocValue, dbErr)
							return
						}
						dnsDeactivated.Add(1)
						return
					}
					kept.Add(1)
				}(ioc.Type, ioc.Value, domain)
			}

			wg.Wait()

			fmt.Printf("  deactivated %d IOCs by DNS (NXDOMAIN)\n", dnsDeactivated.Load())
			fmt.Printf("  kept %d IOCs\n", kept.Load())
			fmt.Println()
			fmt.Printf("Total: %d deactivated (%d pattern + %d DNS)\n",
				patternCount+dnsDeactivated.Load(), patternCount, dnsDeactivated.Load())

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().DurationVar(&dnsTimeout, "dns-timeout", 3*time.Second, "timeout per DNS lookup")
	cmd.Flags().IntVar(&concurrency, "concurrency", 10, "max concurrent DNS lookups")

	return cmd
}

// extractIOCDomain extracts hostname from an IOC value. Mirrors the logic
// in internal/analyzer/ioc_validate.go but avoids importing that package.
func extractIOCDomain(val, iocType string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}

	if iocType == models.IOCTypeDomain {
		host, _, err := net.SplitHostPort(val)
		if err == nil && host != "" {
			return host
		}
		return val
	}

	if iocType == models.IOCTypeURL {
		u := val
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		// Quick parse: strip scheme, take host before path.
		after := u
		if idx := strings.Index(after, "://"); idx >= 0 {
			after = after[idx+3:]
		}
		if idx := strings.Index(after, "/"); idx >= 0 {
			after = after[:idx]
		}
		if host, _, err := net.SplitHostPort(after); err == nil && host != "" {
			return host
		}
		return after
	}

	return ""
}
