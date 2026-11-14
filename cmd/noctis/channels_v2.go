package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/legacyimport"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/spf13/cobra"
)

func channelsCommands(dbRef *string) []*cobra.Command {
	var apply bool
	imp := &cobra.Command{Use: "source-import MANIFEST_JSON", Args: cobra.ExactArgs(1), Short: "Validate complete source dispositions; dry-run unless --apply", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		var m legacyimport.SourceManifest
		if e = readBoundedJSON(args[0], &m); e != nil {
			return e
		}
		r, e := (legacyimport.Store{DSN: cfg.DatabaseURL}).ImportManifest(cmd.Context(), m, !apply)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
	}}
	imp.Flags().BoolVar(&apply, "apply", false, "Persist resolved sources and dispositions; never overwrite later policy")
	var historyApply bool
	history := &cobra.Command{Use: "history-import BATCH_JSON", Args: cobra.ExactArgs(1), Short: "Import one checkpointed archival page without historical alerts", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		var b legacyimport.HistoryBatch
		if e = readBoundedJSON(args[0], &b); e != nil {
			return e
		}
		r, e := (legacyimport.Store{DSN: cfg.DatabaseURL}).ImportHistory(cmd.Context(), b, !historyApply)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
	}}
	history.Flags().BoolVar(&historyApply, "apply", false, "Persist the bounded archive page")
	var secretFile, sessionFile, qrFile, passwordFile, capturePolicyFile string
	telegram := &cobra.Command{Use: "telegram", Short: "Exclusive PostgreSQL-fenced Telegram v2 client; never joins channels"}
	telegram.PersistentFlags().StringVar(&secretFile, "credential-file", "", "Protected JSON account/api_id/api_hash file")
	telegram.PersistentFlags().StringVar(&sessionFile, "session-file", "", "Absolute session file in mode0700 directory")
	telegram.PersistentFlags().StringVar(&qrFile, "qr-token-file", "", "Protected short-lived QR token file (auth only)")
	telegram.PersistentFlags().StringVar(&passwordFile, "password-file", "", "Protected 2FA password file (optional)")
	telegram.PersistentFlags().StringVar(&capturePolicyFile, "capture-policy-file", "", "Required protected immutable capture policy for collect/resolve-source/backfill")
	run := func(cmd *cobra.Command, auth bool, action func(context.Context, *telegramv2.Coordinator) error) error {
		info, e := os.Lstat(secretFile)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("Telegram credential file requires mode0600")
		}
		var secret struct {
			Account string `json:"account"`
			APIID   int    `json:"api_id"`
			APIHash string `json:"api_hash"`
		}
		if e = readBoundedJSON(secretFile, &secret); e != nil {
			return errors.New("invalid Telegram credential file")
		}
		cfg, e := configv2.Load("collector", "", *dbRef)
		if e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return (telegramv2.Store{DSN: cfg.DatabaseURL}).RunClient(ctx, telegramv2.ClientConfig{Account: secret.Account, APIID: secret.APIID, APIHash: secret.APIHash, SessionFile: sessionFile, Authenticate: auth, QRTokenFile: qrFile, PasswordFile: passwordFile, CapturePolicyFile: capturePolicyFile}, action)
	}
	inventory := func(cmd *cobra.Command, action func(context.Context, *telegramv2.Inventory) error) error {
		info, e := os.Lstat(secretFile)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("Telegram credential file requires mode0600")
		}
		var secret struct {
			Account string `json:"account"`
			APIID   int    `json:"api_id"`
			APIHash string `json:"api_hash"`
		}
		if e = readBoundedJSON(secretFile, &secret); e != nil {
			return errors.New("invalid Telegram credential file")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return telegramv2.RunInventory(ctx, telegramv2.ClientConfig{Account: secret.Account, APIID: secret.APIID, APIHash: secret.APIHash, SessionFile: sessionFile}, action)
	}
	telegram.AddCommand(&cobra.Command{Use: "collect", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return run(cmd, false, nil) }}, &cobra.Command{Use: "auth", Args: cobra.NoArgs, Short: "Authenticate through a protected expiring QR file", RunE: func(cmd *cobra.Command, _ []string) error { return run(cmd, true, nil) }}, &cobra.Command{Use: "resolve USERNAME", Args: cobra.ExactArgs(1), Short: "Resolve a username without joining or enabling collection", RunE: func(cmd *cobra.Command, args []string) error {
		return inventory(cmd, func(ctx context.Context, c *telegramv2.Inventory) error {
			r, e := c.Resolve(ctx, args[0])
			if e != nil {
				return e
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(r.Peer)
		})
	}}, &cobra.Command{Use: "dialogs", Args: cobra.NoArgs, Short: "Inventory paginated active and archived dialogs without joining", RunE: func(cmd *cobra.Command, _ []string) error {
		return inventory(cmd, func(ctx context.Context, c *telegramv2.Inventory) error {
			return c.WalkDialogs(ctx, 1000, func(v telegramv2.DialogCandidate) error { return json.NewEncoder(cmd.OutOrStdout()).Encode(v) })
		})
	}})
	telegram.AddCommand(&cobra.Command{Use: "resolve-source SOURCE_UUID USERNAME", Args: cobra.ExactArgs(2), Short: "Bind an enabled source's exact peer identity and auth-generation access hash", RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd, false, func(ctx context.Context, c *telegramv2.Coordinator) error {
			return c.ResolveSource(ctx, args[0], args[1])
		})
	}}, &cobra.Command{Use: "backfill SOURCE_UUID", Args: cobra.ExactArgs(1), Short: "Capture one checkpointed bootstrap history page; never alerts", RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd, false, func(ctx context.Context, c *telegramv2.Coordinator) error {
			complete, e := c.BackfillPage(ctx, args[0], 100)
			if e != nil {
				return e
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"complete": complete, "mode": "bootstrap"})
		})
	}})
	telegram.AddCommand(&cobra.Command{Use: "capture-policy-validate", Args: cobra.NoArgs, Short: "Validate protected capture policy without client or database writes", RunE: func(cmd *cobra.Command, _ []string) error {
		_, e := telegramv2.ReadCapturePolicy(capturePolicyFile)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"valid": true})
	}}, &cobra.Command{Use: "capture-status", Args: cobra.NoArgs, Short: "Read durable capture counters without starting a Telegram client", RunE: func(cmd *cobra.Command, _ []string) error {
		p, e := telegramv2.ReadCapturePolicy(capturePolicyFile)
		if e != nil {
			return e
		}
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		v, e := (telegramv2.Store{DSN: cfg.DatabaseURL}).CaptureBudgetStatus(cmd.Context(), p)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(v)
	}})
	var inventoryActor string
	invImport := &cobra.Command{Use: "inventory-import", Args: cobra.NoArgs, Short: "Read current dialogs into private identity candidates; no source activation or history", RunE: func(cmd *cobra.Command, _ []string) error {
		if info, e := os.Lstat(secretFile); e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("Telegram credential file requires mode0600")
		}
		var secret struct {
			Account string `json:"account"`
			APIID   int    `json:"api_id"`
			APIHash string `json:"api_hash"`
		}
		if e := readBoundedJSON(secretFile, &secret); e != nil {
			return errors.New("invalid Telegram credential file")
		}
		cfg, e := configv2.Load("collector", "", *dbRef)
		if e != nil {
			return e
		}
		id, e := (telegramv2.Store{DSN: cfg.DatabaseURL}).InventoryImport(cmd.Context(), telegramv2.ClientConfig{Account: secret.Account, APIID: secret.APIID, APIHash: secret.APIHash, SessionFile: sessionFile}, inventoryActor)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"snapshot_id": id, "sources_activated": false})
	}}
	invImport.Flags().StringVar(&inventoryActor, "actor", "", "Required operator identity for inventory audit")
	telegram.AddCommand(invImport)
	var consentAccount, consentActor, consentReason string
	proposal := &cobra.Command{Use: "capture-consent-propose", Args: cobra.NoArgs, Short: "Write a protected seven-day hourly production proposal from explicitly activated current channels", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		return (telegramv2.Store{DSN: cfg.DatabaseURL}).ProposeProductionConsent(cmd.Context(), consentAccount, consentActor, consentReason, capturePolicyFile)
	}}
	proposal.Flags().StringVar(&consentAccount, "account", "", "Explicit inventoried Telegram account")
	proposal.Flags().StringVar(&consentActor, "actor", "", "Operator identity")
	proposal.Flags().StringVar(&consentReason, "reason", "", "Explicit capture purpose")
	telegram.AddCommand(proposal)
	var transitionAccount, transitionActor, transitionReason, transitionFile string
	transitionProposal := &cobra.Command{Use: "capture-generation-propose", Args: cobra.NoArgs, Short: "Write a protected generation transition CAS after authenticated session closure", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		return (telegramv2.Store{DSN: cfg.DatabaseURL}).ProposeGenerationTransition(cmd.Context(), transitionAccount, transitionActor, transitionReason, transitionFile)
	}}
	transitionProposal.Flags().StringVar(&transitionAccount, "account", "", "Production Telegram account")
	transitionProposal.Flags().StringVar(&transitionActor, "actor", "", "Operator identity")
	transitionProposal.Flags().StringVar(&transitionReason, "reason", "", "Explicit session replacement or repair reason")
	transitionProposal.Flags().StringVar(&transitionFile, "transition-file", "", "Protected reviewable transition JSON output")
	telegram.AddCommand(transitionProposal, &cobra.Command{Use: "capture-generation-transition TRANSITION_JSON", Args: cobra.ExactArgs(1), Short: "Apply the exact reviewed generation transition; keeps capture blocked pending new consent", RunE: func(cmd *cobra.Command, args []string) error {
		r, e := telegramv2.ReadGenerationTransition(args[0])
		if e != nil {
			return e
		}
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		if e = (telegramv2.Store{DSN: cfg.DatabaseURL}).TransitionGeneration(cmd.Context(), sessionFile, r); e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"transition_id": r.ID, "capture_pending": true})
	}})
	var failureRevision int64
	var resumeActor, resumeReason string
	resume := &cobra.Command{Use: "capture-resume", Args: cobra.NoArgs, Short: "Manually acknowledge one terminal failure CAS after proving closure; never resets quotas or cursors", RunE: func(cmd *cobra.Command, _ []string) error {
		p, e := telegramv2.ReadCapturePolicy(capturePolicyFile)
		if e != nil {
			return e
		}
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		return (telegramv2.Store{DSN: cfg.DatabaseURL}).ResumeProduction(cmd.Context(), p, failureRevision, resumeActor, resumeReason)
	}}
	resume.Flags().Int64Var(&failureRevision, "failure-revision", 0, "Exact blocked revision from capture-status")
	resume.Flags().StringVar(&resumeActor, "actor", "", "Operator acknowledging diagnosed failure")
	resume.Flags().StringVar(&resumeReason, "reason", "", "Diagnosis and explicit resume reason")
	telegram.AddCommand(resume)
	telegram.AddCommand(&cobra.Command{Use: "capture-consent-install", Args: cobra.NoArgs, Short: "Explicitly install or renew production consent using immutable policy CAS; requires closed owner", RunE: func(cmd *cobra.Command, _ []string) error {
		p, e := telegramv2.ReadCapturePolicy(capturePolicyFile)
		if e != nil {
			return e
		}
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		if e = (telegramv2.Store{DSN: cfg.DatabaseURL}).InstallProductionConsent(cmd.Context(), p); e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"installed": true, "revision": p.Revision})
	}}, &cobra.Command{Use: "capture-consent-revoke", Args: cobra.NoArgs, Short: "Revoke exact production consent and revision", RunE: func(cmd *cobra.Command, _ []string) error {
		p, e := telegramv2.ReadCapturePolicy(capturePolicyFile)
		if e != nil {
			return e
		}
		cfg, e := configv2.Load("api", "", *dbRef)
		if e != nil {
			return e
		}
		return (telegramv2.Store{DSN: cfg.DatabaseURL}).RevokeProductionConsent(cmd.Context(), p.Account, p.BudgetID, p.Revision)
	}})
	return []*cobra.Command{imp, history, telegram}
}
func readBoundedJSON(path string, out any) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	if info.Size() > 32<<20 {
		return errors.New("input file exceeds limit")
	}
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
