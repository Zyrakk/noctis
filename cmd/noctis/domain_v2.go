package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/enrichmentv2"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/spf13/cobra"
)

func domainCommands(dbRef *string) []*cobra.Command {
	var endpoint string
	var fixture []string
	var ttl time.Duration
	feed := &cobra.Command{Use: "feed-poll KIND", Args: cobra.ExactArgs(1), Short: "Commit one NVD/KEV/EPSS page with snapshot and durable cursor", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load("collector", "", *dbRef)
		if e != nil {
			return e
		}
		allow := map[string]bool{}
		for _, v := range fixture {
			allow[v] = true
		}
		r, e := (vulnv2.Store{DSN: cfg.DatabaseURL, Fetcher: capture.Fetcher{AllowLocal: allow}}).PollPage(cmd.Context(), args[0], endpoint, ttl)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
	}}
	feed.Flags().StringVar(&endpoint, "endpoint", "", "Official endpoint by default; alternate only server fixture authorities")
	feed.Flags().StringSliceVar(&fixture, "fixture-authority", nil, "Explicit synthetic local fixture host:port")
	feed.Flags().DurationVar(&ttl, "ttl", 24*time.Hour, "Snapshot freshness maximum 7 days")
	var keyFile, enrichEndpoint string
	var enrichFixtures []string
	enrich := &cobra.Command{Use: "enrich REQUEST_JSON", Args: cobra.ExactArgs(1), Short: "Explicit permission-checked observable lookup under persisted quota/TTL policy", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load("worker", "", *dbRef)
		if e != nil {
			return e
		}
		var request enrichmentv2.Request
		if e = readBoundedJSON(args[0], &request); e != nil {
			return e
		}
		secret := ""
		if keyFile != "" {
			info, e := os.Lstat(keyFile)
			if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errors.New("provider key requires protected file")
			}
			raw, e := os.ReadFile(keyFile)
			if e != nil {
				return errors.New("provider key unavailable")
			}
			secret = strings.TrimSpace(string(raw))
		}
		allow := map[string]bool{}
		for _, v := range enrichFixtures {
			allow[v] = true
		}
		r, e := (enrichmentv2.Store{DSN: cfg.DatabaseURL, Fetcher: capture.Fetcher{AllowLocal: allow}, Endpoint: enrichEndpoint, Secret: secret}).Lookup(cmd.Context(), request)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
	}}
	enrich.Flags().StringVar(&keyFile, "key-file", "", "Protected provider API key file")
	enrich.Flags().StringVar(&enrichEndpoint, "endpoint", "", "Official provider endpoint by default")
	enrich.Flags().StringSliceVar(&enrichFixtures, "fixture-authority", nil, "Explicit synthetic local fixture host:port")
	return []*cobra.Command{feed, enrich}
}
