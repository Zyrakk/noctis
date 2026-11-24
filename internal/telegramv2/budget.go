package telegramv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrBudget = errors.New("native capture budget unavailable, changed, expired or exhausted")
var ErrQuota = errors.New("native capture period quota exhausted")

type quotaDenial struct {
	Until  time.Time
	Reason string
}

func (e *quotaDenial) Error() string   { return ErrQuota.Error() }
func (e *quotaDenial) Unwrap() []error { return []error{ErrQuota, ErrBudget} }

type CaptureLimits struct {
	API           int64 `json:"api"`
	Observations  int64 `json:"observations"`
	PayloadBytes  int64 `json:"payload_bytes"`
	MetadataBytes int64 `json:"metadata_bytes"`
}
type CapturePeer struct {
	SourceID       string `json:"source_id"`
	Type           string `json:"peer_type"`
	ID             int64  `json:"peer_id"`
	LiveEpoch      string `json:"live_epoch"`
	BootstrapEpoch string `json:"bootstrap_epoch"`
}
type CapturePolicy struct {
	Version        int                      `json:"version"`
	BudgetID       string                   `json:"budget_id"`
	Account        string                   `json:"account"`
	Generation     string                   `json:"auth_generation"`
	WindowSeconds  int                      `json:"window_seconds"`
	ProcessSeconds int                      `json:"process_seconds"`
	Global         CaptureLimits            `json:"global"`
	Phases         map[string]CaptureLimits `json:"phases"`
	Peers          []CapturePeer            `json:"peers"`
	PeriodAnchor   time.Time                `json:"period_anchor,omitempty"`
	ExpiresAt      time.Time                `json:"expires_at,omitempty"`
	Predecessor    string                   `json:"predecessor,omitempty"`
	Revision       int64                    `json:"revision,omitempty"`
	Actor          string                   `json:"actor,omitempty"`
	Reason         string                   `json:"reason,omitempty"`
	TransitionID   string                   `json:"generation_transition,omitempty"`
}

// Keep the v1 canonical bytes stable: its existing protected files and stored
// digests must not change when production-only time fields are introduced.
func (p CapturePolicy) MarshalJSON() ([]byte, error) {
	type plain CapturePolicy
	if p.Version != 1 {
		return json.Marshal(plain(p))
	}
	return json.Marshal(struct {
		Version        int                      `json:"version"`
		BudgetID       string                   `json:"budget_id"`
		Account        string                   `json:"account"`
		Generation     string                   `json:"auth_generation"`
		WindowSeconds  int                      `json:"window_seconds"`
		ProcessSeconds int                      `json:"process_seconds"`
		Global         CaptureLimits            `json:"global"`
		Phases         map[string]CaptureLimits `json:"phases"`
		Peers          []CapturePeer            `json:"peers"`
	}{p.Version, p.BudgetID, p.Account, p.Generation, p.WindowSeconds, p.ProcessSeconds, p.Global, p.Phases, p.Peers})
}

func (p CapturePolicy) validate() error {
	if p.Version == 1 && (!p.PeriodAnchor.IsZero() || !p.ExpiresAt.IsZero() || p.Predecessor != "" || p.Revision != 0 || p.Actor != "" || p.Reason != "" || p.TransitionID != "") {
		return ErrBudget
	}
	maxWindow := 600
	if p.Version == 2 {
		maxWindow = 3600
		if p.WindowSeconds != 3600 || p.PeriodAnchor.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.PeriodAnchor) || p.Revision < 1 || p.Actor == "" || p.Reason == "" || p.Phases["bootstrap"].Observations != 0 || p.Phases["bootstrap"].PayloadBytes != 0 {
			return ErrBudget
		}
		if p.Predecessor != "" {
			if _, e := uuid.Parse(p.Predecessor); e != nil {
				return ErrBudget
			}
		}
		if p.TransitionID != "" {
			if _, e := uuid.Parse(p.TransitionID); e != nil || p.Predecessor == "" {
				return ErrBudget
			}
		}
	}
	if (p.Version != 1 && p.Version != 2) || p.Account == "" || p.WindowSeconds < 1 || p.WindowSeconds > maxWindow || p.ProcessSeconds < 1 || p.ProcessSeconds > 300 || len(p.Peers) < 1 || len(p.Peers) > 1000 || len(p.Phases) != 3 {
		return ErrBudget
	}
	if _, e := uuid.Parse(p.BudgetID); e != nil {
		return ErrBudget
	}
	if _, e := uuid.Parse(p.Generation); e != nil {
		return ErrBudget
	}
	limits := []CaptureLimits{p.Global}
	for _, phase := range []string{"control", "bootstrap", "live"} {
		v, ok := p.Phases[phase]
		if !ok {
			return ErrBudget
		}
		limits = append(limits, v)
	}
	for _, v := range limits {
		if v.API < 0 || v.API > 256 || v.Observations < 0 || v.Observations > 1000 || v.PayloadBytes < 0 || v.PayloadBytes > 64<<20 || v.MetadataBytes < 0 || v.MetadataBytes > 4<<20 {
			return ErrBudget
		}
	}
	if p.Global.API == 0 {
		return ErrBudget
	}
	seen := map[string]bool{}
	for _, v := range p.Peers {
		if p.Version == 2 && v.Type != "channel" {
			return ErrBudget
		}
		if v.ID <= 0 || (v.Type != "channel" && v.Type != "user" && v.Type != "chat") || seen[v.SourceID] {
			return ErrBudget
		}
		seen[v.SourceID] = true
		for _, id := range []string{v.SourceID, v.LiveEpoch, v.BootstrapEpoch} {
			if _, e := uuid.Parse(id); e != nil {
				return ErrBudget
			}
		}
	}
	return nil
}
func ReadCapturePolicy(path string) (CapturePolicy, error) {
	var p CapturePolicy
	if e := protectedPath(path, true); e != nil {
		return p, errors.New("capture policy requires protected regular mode0600 file")
	}
	info, e := os.Lstat(path)
	if e != nil || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return p, errors.New("capture policy requires mode0600")
	}
	f, e := os.Open(path)
	if e != nil {
		return p, ErrBudget
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20+1))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, ErrBudget
	}
	return p, p.validate()
}

func (b captureBudget) captureAllowed(ctx context.Context, tx pgx.Tx, target Peer, mode string) (bool, error) {
	if b.Policy.Version == 2 && mode == "bootstrap" {
		return false, nil
	}
	for _, p := range b.Policy.Peers {
		if p.Type == target.Type && p.ID == target.ID {
			return true, b.allowSource(ctx, tx, p, mode)
		}
	}
	return false, nil
}
func policyBytes(p CapturePolicy) ([]byte, string) {
	b, _ := json.Marshal(p)
	return b, fmt.Sprintf("%x", sha256.Sum256(b))
}

func strictCapturePolicy(raw []byte, p *CapturePolicy) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(p) != nil || d.Decode(new(any)) != io.EOF {
		return ErrBudget
	}
	return p.validate()
}

type captureBudget struct {
	Policy      CapturePolicy
	Counters    map[string]CaptureLimits
	Expires     time.Time
	State       string
	PeriodStart time.Time
}

func budgetTx(ctx context.Context, tx pgx.Tx, o Owner) (captureBudget, error) {
	var production, blocked bool
	if e := tx.QueryRow(ctx, `SELECT active_capture_consent IS NOT NULL,authentication_in_progress OR prepared_auth_generation IS NOT NULL OR pending_generation_transition IS NOT NULL OR capture_failure_revision<>capture_resume_revision FROM noctis_v2.telegram_accounts WHERE id=$1`, o.Account).Scan(&production, &blocked); e != nil {
		return captureBudget{}, e
	}
	if blocked {
		return captureBudget{}, ErrBudget
	}
	if production {
		return productionBudgetTx(ctx, tx, o)
	}
	var b captureBudget
	var raw, counters []byte
	var gen, digest string
	e := tx.QueryRow(ctx, `SELECT b.policy,b.counters,b.expires_at,b.state,b.auth_generation::text,b.policy_digest FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_budgets b ON b.id=a.active_capture_budget AND b.account_id=a.id WHERE a.id=$1 AND a.owner=$2 AND a.owner_fence=$3 AND a.auth_generation=$4 AND NOT a.closed AND a.status='running' AND a.lease_expires_at>clock_timestamp() FOR UPDATE OF b`, o.Account, o.ID, o.Fence, o.Generation).Scan(&raw, &counters, &b.Expires, &b.State, &gen, &digest)
	if e != nil {
		return b, queryFailure(ctx, e, ErrBudget, stageBudget)
	}
	if strictCapturePolicy(raw, &b.Policy) != nil || json.Unmarshal(counters, &b.Counters) != nil || gen != o.Generation || b.Policy.Account != o.Account || b.Policy.Generation != o.Generation {
		return b, ErrBudget
	}
	_, expectedDigest := policyBytes(b.Policy)
	if expectedDigest != digest {
		return b, ErrBudget
	}
	return b, nil
}
func (b captureBudget) active(ctx context.Context, tx pgx.Tx) error {
	var active bool
	if e := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, b.Expires).Scan(&active); e != nil {
		return e
	}
	if !active || b.State != "active" {
		return ErrBudget
	}
	return nil
}
func (b captureBudget) allowSource(ctx context.Context, tx pgx.Tx, p CapturePeer, mode string) error {
	var valid bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.sources s JOIN noctis_v2.telegram_peers p ON p.source_id=s.id WHERE s.id=$1 AND s.kind='telegram' AND s.epoch=$2 AND p.bootstrap_epoch=$3 AND p.account_id=$4 AND p.peer_type=$5 AND p.peer_id=$6 AND p.auth_generation=$7 AND p.allowed AND `+intelligence.SourceAuthorizedSQL+`)`, p.SourceID, p.LiveEpoch, p.BootstrapEpoch, b.Policy.Account, p.Type, p.ID, b.Policy.Generation).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return errors.New("native capture source policy or epoch changed")
	}
	return nil
}
func (b captureBudget) charge(ctx context.Context, tx pgx.Tx, phase string, delta CaptureLimits) error {
	if e := b.active(ctx, tx); e != nil {
		return e
	}
	limit, ok := b.Policy.Phases[phase]
	if !ok {
		return ErrBudget
	}
	total := CaptureLimits{}
	for _, v := range b.Counters {
		total = addLimits(total, v)
	}
	current := addLimits(b.Counters[phase], delta)
	total = addLimits(total, delta)
	if exceeds(current, limit) || exceeds(total, b.Policy.Global) {
		if b.Policy.Version == 2 {
			return &quotaDenial{Until: b.PeriodStart.Add(time.Duration(b.Policy.WindowSeconds) * time.Second), Reason: "phase_or_global_limit"}
		}
		return errors.Join(ErrBudget, ErrQuota)
	}
	b.Counters[phase] = current
	raw, _ := json.Marshal(b.Counters)
	if b.Policy.Version == 2 {
		_, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_capture_usage SET counters=$4 WHERE account_id=$1 AND auth_generation=$2 AND period_start=$3`, b.Policy.Account, b.Policy.Generation, b.PeriodStart, string(raw))
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_capture_budgets SET counters=$2 WHERE id=$1`, b.Policy.BudgetID, string(raw))
	return e
}
func addLimits(a, b CaptureLimits) CaptureLimits {
	return CaptureLimits{a.API + b.API, a.Observations + b.Observations, a.PayloadBytes + b.PayloadBytes, a.MetadataBytes + b.MetadataBytes}
}
func exceeds(a, b CaptureLimits) bool {
	return a.API > b.API || a.Observations > b.Observations || a.PayloadBytes > b.PayloadBytes || a.MetadataBytes > b.MetadataBytes
}

func (budget captureBudget) batchCost(ctx context.Context, tx pgx.Tx, o Owner, b Envelope) (CaptureLimits, error) {
	delta := CaptureLimits{}
	inboxSeen := map[string]bool{}
	observationSeen := map[string]bool{}
	for i, event := range b.Events {
		if event.Kind == "delete" && event.Peer.Type == "unknown" {
			e := tx.QueryRow(ctx, `SELECT peer_type,peer_id FROM noctis_v2.telegram_inbox WHERE account_id=$1 AND message_id=$2 AND peer_type IN ('chat','user') AND disposition='captured' ORDER BY created_at DESC LIMIT 1`, o.Account, event.MessageID).Scan(&event.Peer.Type, &event.Peer.ID)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return delta, e
			}
		}
		identity, _ := json.Marshal([]any{event.Peer.Type, event.Peer.ID, event.MessageID, event.Revision})
		key := string(identity)
		if inboxSeen[key] {
			continue
		}
		inboxSeen[key] = true
		var disposed bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_inbox WHERE account_id=$1 AND peer_type=$2 AND peer_id=$3 AND message_id=$4 AND revision=$5)`, o.Account, event.Peer.Type, event.Peer.ID, event.MessageID, event.Revision).Scan(&disposed); e != nil {
			return delta, e
		}
		if disposed {
			continue
		}
		metadata := json.RawMessage(`{}`)
		var source string
		e := tx.QueryRow(ctx, `SELECT s.id::text FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.peer_type=$2 AND p.peer_id=$3 AND p.auth_generation=$4 AND p.allowed AND s.kind='telegram' AND `+intelligence.SourceAuthorizedSQL, o.Account, event.Peer.Type, event.Peer.ID, o.Generation).Scan(&source)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return delta, e
		}
		allowed := e == nil
		if allowed {
			allowed, e = budget.captureAllowed(ctx, tx, event.Peer, string(b.Mode))
			if e != nil {
				return delta, e
			}
		}
		if allowed && event.Kind != "protocol_disposition" {
			if event.Metadata != nil {
				metadata, e = event.Metadata()
				if e != nil {
					return delta, e
				}
				if len(metadata) > 64<<10 || !json.Valid(metadata) {
					return delta, errors.New("invalid Telegram metadata")
				}
				b.Events[i].Metadata = func() (json.RawMessage, error) { return metadata, nil }
			}
			if event.Kind != "delete" {
				if event.Text == nil {
					return delta, errors.New("message payload missing")
				}
				payload, e := event.Text()
				if e != nil {
					return delta, e
				}
				if len(payload) > 8<<20 {
					return delta, errors.New("telegram payload limit")
				}
				observationKey := source + ":" + fmt.Sprint(event.MessageID) + ":" + event.Revision
				var exists bool
				if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.observations WHERE source_id=$1 AND native_id=$2 AND revision=$3)`, source, fmt.Sprint(event.MessageID), event.Revision).Scan(&exists); e != nil {
					return delta, e
				}
				if !exists && !observationSeen[observationKey] {
					delta.Observations++
					delta.PayloadBytes += int64(len(payload))
					observationSeen[observationKey] = true
				}
			}
		}
		delta.MetadataBytes += int64(len(metadata) + len(event.Revision) + len(event.Kind) + len(event.Peer.Type) + 32)
	}
	return delta, nil
}

// BindCapturePolicy is the sole first-start path; a bound account can never swap
// IDs or reset counters, including when exhausted. Status/validation do not bind.
func (s Store) BindCapturePolicy(ctx context.Context, p CapturePolicy) (time.Time, error) {
	if p.Version == 2 {
		return s.bindProductionPolicy(ctx, p)
	}
	if e := p.validate(); e != nil {
		return time.Time{}, e
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return time.Time{}, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return time.Time{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451003)`); e != nil {
		return time.Time{}, e
	}
	var gen string
	var bound *string
	var production bool
	if e = tx.QueryRow(ctx, `SELECT auth_generation::text,active_capture_budget::text,consent_revision>0 OR authentication_in_progress OR prepared_auth_generation IS NOT NULL OR pending_generation_transition IS NOT NULL FROM noctis_v2.telegram_accounts WHERE id=$1 FOR UPDATE`, p.Account).Scan(&gen, &bound, &production); e != nil {
		return time.Time{}, e
	}
	if gen != p.Generation || production {
		return time.Time{}, ErrBudget
	}
	raw, digest := policyBytes(p)
	var expiry time.Time
	for _, peer := range p.Peers {
		if e = (captureBudget{Policy: p}).allowSource(ctx, tx, peer, "live"); e != nil {
			return time.Time{}, e
		}
	}
	if bound == nil {
		e = tx.QueryRow(ctx, `WITH start AS (SELECT clock_timestamp() AS at) INSERT INTO noctis_v2.telegram_capture_budgets(id,account_id,auth_generation,policy_digest,policy,started_at,expires_at) SELECT $1,$2,$3,$4,$5,at,at+$6::interval FROM start RETURNING expires_at`, p.BudgetID, p.Account, p.Generation, digest, string(raw), fmt.Sprintf("%d seconds", p.WindowSeconds)).Scan(&expiry)
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET active_capture_budget=$2 WHERE id=$1`, p.Account, p.BudgetID)
		}
	} else {
		var stored string
		var state string
		var active bool
		e = tx.QueryRow(ctx, `SELECT policy_digest,expires_at,state,expires_at>clock_timestamp() FROM noctis_v2.telegram_capture_budgets WHERE id=$1 AND account_id=$2 AND auth_generation=$3`, *bound, p.Account, p.Generation).Scan(&stored, &expiry, &state, &active)
		if e == nil && (*bound != p.BudgetID || stored != digest || state != "active" || !active) {
			e = ErrBudget
		}
	}
	if e != nil {
		return time.Time{}, e
	}
	return expiry, tx.Commit(ctx)
}

// CaptureBudgetStatus exposes only counters and expiry, never identity digests.
func (s Store) CaptureBudgetStatus(ctx context.Context, p CapturePolicy) (map[string]any, error) {
	if p.Version == 2 {
		return s.productionStatus(ctx, p)
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return nil, e
	}
	defer c.Close(context.Background())
	_, digest := policyBytes(p)
	var counters []byte
	var expires time.Time
	var state string
	e = c.QueryRow(ctx, `SELECT b.counters,b.expires_at,b.state FROM noctis_v2.telegram_capture_budgets b JOIN noctis_v2.telegram_accounts a ON a.active_capture_budget=b.id WHERE a.id=$1 AND b.id=$2 AND b.policy_digest=$3 AND a.auth_generation=$4`, p.Account, p.BudgetID, digest, p.Generation).Scan(&counters, &expires, &state)
	if e != nil {
		return nil, ErrBudget
	}
	var v any
	_ = json.Unmarshal(counters, &v)
	return map[string]any{"state": state, "expires_at": expires, "counters": v}, nil
}
