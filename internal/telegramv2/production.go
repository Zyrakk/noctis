package telegramv2

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"time"

	"github.com/jackc/pgx/v5"
)

var errProcessWindow = errors.New("production capture planned process window ended")

// Roll back native work to the savepoint taken after the account row lock,
// then persist only its rejection fence before releasing that same lock.
// No rejected payload, inbox, cursor or counter increment survives.
// The rejected period comes from admission, so crossing a period boundary while
// recording the reason cannot accidentally exhaust the following period.
func finishNativeTransaction(tx pgx.Tx, o Owner, failure error) (err error) {
	defer func() {
		_ = tx.Rollback(context.Background())
		if err != nil {
			err = errors.Join(ErrOwnership, err)
		}
	}()
	var denial *quotaDenial
	if !errors.As(failure, &denial) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_capture_work`); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET quota_wait_until=GREATEST(COALESCE(quota_wait_until,$2),$2),quota_wait_reason=$3 WHERE id=$1 AND owner=$4 AND owner_fence=$5 AND auth_generation=$6 AND NOT closed AND status='running' AND active_capture_consent IS NOT NULL`, o.Account, denial.Until, denial.Reason, o.ID, o.Fence, o.Generation)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrOwnership
	}
	return tx.Commit(ctx)
}

// ProposeProductionConsent writes only a protected reviewable file. It does
// not install consent, grant source access, or start a Telegram client.
func (s Store) ProposeProductionConsent(ctx context.Context, account, actor, reason, path string) error {
	if account == "" || actor == "" || reason == "" {
		return errors.New("account, actor and reason required")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := CapturePolicy{Version: 2, BudgetID: uuid.NewString(), Account: account, WindowSeconds: 3600, ProcessSeconds: 300, PeriodAnchor: now, ExpiresAt: now.Add(7*24*time.Hour - time.Second), Actor: actor, Reason: reason, Global: CaptureLimits{API: 256, Observations: 1000, PayloadBytes: 64 << 20, MetadataBytes: 4 << 20}, Phases: map[string]CaptureLimits{"control": {API: 64}, "bootstrap": {}, "live": {API: 192, Observations: 1000, PayloadBytes: 64 << 20, MetadataBytes: 4 << 20}}}
	var priorRaw []byte
	e = c.QueryRow(ctx, `SELECT a.auth_generation::text,a.consent_revision+1,COALESCE(a.active_capture_consent::text,t.consent_id::text,''),b.policy,COALESCE(a.pending_generation_transition::text,'') FROM noctis_v2.telegram_accounts a LEFT JOIN noctis_v2.telegram_generation_transitions t ON t.id=a.pending_generation_transition LEFT JOIN noctis_v2.telegram_capture_consents b ON b.id=COALESCE(a.active_capture_consent,t.consent_id) WHERE a.id=$1 AND a.prepared_auth_generation IS NULL AND NOT a.authentication_in_progress AND a.active_capture_budget IS NULL`, account).Scan(&p.Generation, &p.Revision, &p.Predecessor, &priorRaw, &p.TransitionID)
	if e != nil {
		return e
	}
	if p.Predecessor != "" {
		var prior CapturePolicy
		if strictCapturePolicy(priorRaw, &prior) != nil {
			return ErrBudget
		}
		p.PeriodAnchor = prior.PeriodAnchor
		p.WindowSeconds = prior.WindowSeconds
		p.Global = prior.Global
		p.Phases = prior.Phases
	}
	rows, e := c.Query(ctx, `SELECT p.source_id::text,p.peer_type,p.peer_id,s.epoch::text,p.bootstrap_epoch::text FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.auth_generation=$2 AND p.allowed AND s.enabled AND s.epoch IS NOT NULL AND p.inventory_snapshot IS NOT NULL ORDER BY p.source_id`, account, p.Generation)
	if e != nil {
		return e
	}
	for rows.Next() {
		var peer CapturePeer
		if e = rows.Scan(&peer.SourceID, &peer.Type, &peer.ID, &peer.LiveEpoch, &peer.BootstrapEpoch); e != nil {
			rows.Close()
			return e
		}
		p.Peers = append(p.Peers, peer)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	if e = p.validate(); e != nil {
		return e
	}
	raw, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	return protectedWrite(path, append(raw, '\n'))
}

// Production consent installation is an explicit operator operation, never a
// side effect of starting or restarting the collector. CAS and closed-owner
// proof prevent renewal while a previous client can still perform I/O.
func (s Store) InstallProductionConsent(ctx context.Context, p CapturePolicy) error {
	if p.Version != 2 || p.validate() != nil {
		return ErrBudget
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	var gen string
	var closed bool
	var current *string
	var pending *string
	var revision int64
	if e = tx.QueryRow(ctx, `SELECT auth_generation::text,closed AND owner IS NULL AND lease_expires_at IS NULL AND NOT authentication_in_progress AND prepared_auth_generation IS NULL AND active_capture_budget IS NULL,active_capture_consent::text,consent_revision,pending_generation_transition::text FROM noctis_v2.telegram_accounts WHERE id=$1 FOR UPDATE`, p.Account).Scan(&gen, &closed, &current, &revision, &pending); e != nil {
		return e
	}
	raw, digest := policyBytes(p)
	var existing string
	e = tx.QueryRow(ctx, `SELECT policy_digest FROM noctis_v2.telegram_capture_consents WHERE id=$1`, p.BudgetID).Scan(&existing)
	if e == nil {
		if current != nil && *current == p.BudgetID && existing == digest {
			return tx.Commit(ctx)
		}
		return ErrBudget
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	predecessor := current
	if pending != nil {
		if current != nil || p.TransitionID != *pending {
			return ErrBudget
		}
		var previous string
		if e = tx.QueryRow(ctx, `SELECT t.consent_id::text FROM noctis_v2.telegram_generation_transitions t JOIN noctis_v2.telegram_accounts a ON a.id=t.account_id WHERE t.id=$1 AND t.account_id=$2 AND t.to_generation=$3 AND t.consent_revision=$4 AND a.capture_failure_revision=a.capture_resume_revision`, *pending, p.Account, p.Generation, revision).Scan(&previous); e != nil {
			return errors.Join(ErrBudget, e)
		}
		predecessor = &previous
	} else if p.TransitionID != "" {
		return ErrBudget
	}
	if !closed || gen != p.Generation || p.Revision != revision+1 || (predecessor == nil && p.Predecessor != "") || (predecessor != nil && *predecessor != p.Predecessor) {
		return ErrBudget
	}
	var valid bool
	if e = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp() AND $1::timestamptz<=clock_timestamp()+interval '7 days' AND $2::timestamptz<=clock_timestamp()`, p.ExpiresAt, p.PeriodAnchor).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return ErrBudget
	}
	if predecessor != nil {
		var priorRaw []byte
		var prior CapturePolicy
		if e = tx.QueryRow(ctx, `SELECT policy FROM noctis_v2.telegram_capture_consents WHERE id=$1`, *predecessor).Scan(&priorRaw); e != nil {
			return e
		}
		if strictCapturePolicy(priorRaw, &prior) != nil || (pending == nil && prior.Generation != p.Generation) || prior.WindowSeconds != p.WindowSeconds || !prior.PeriodAnchor.Equal(p.PeriodAnchor) || prior.Global != p.Global {
			return ErrBudget
		}
		for phase, v := range prior.Phases {
			if p.Phases[phase] != v {
				return ErrBudget
			}
		}
	}
	for _, peer := range p.Peers {
		var current bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers x JOIN noctis_v2.telegram_inventory_snapshots n ON n.id=x.inventory_snapshot JOIN noctis_v2.telegram_inventory_candidates i ON i.snapshot_id=n.id AND i.peer_id=x.peer_id JOIN noctis_v2.telegram_channel_states cs ON cs.account_id=x.account_id AND cs.channel_id=x.peer_id WHERE x.source_id=$1 AND x.account_id=$3 AND x.auth_generation=$2 AND n.auth_generation=$2 AND i.pts>0 AND cs.pts>0 AND n.id=(SELECT z.id FROM noctis_v2.telegram_inventory_snapshots z WHERE z.account_id=x.account_id ORDER BY z.created_at DESC,z.id DESC LIMIT 1))`, peer.SourceID, p.Generation, p.Account).Scan(&current); e != nil {
			return e
		}
		if !current {
			return errors.New("current inventory channel baseline required for production consent")
		}
		if e = (captureBudget{Policy: p}).allowSource(ctx, tx, peer, "live"); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_capture_consents(id,account_id,auth_generation,predecessor,revision,policy_digest,policy,expires_at,actor,reason) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10)`, p.BudgetID, p.Account, p.Generation, p.Predecessor, p.Revision, digest, string(raw), p.ExpiresAt, p.Actor, p.Reason)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET active_capture_consent=$2,consent_revision=$3,pending_generation_transition=NULL WHERE id=$1`, p.Account, p.BudgetID, p.Revision)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s Store) bindProductionPolicy(ctx context.Context, p CapturePolicy) (time.Time, error) {
	if p.validate() != nil {
		return time.Time{}, ErrBudget
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return time.Time{}, e
	}
	defer c.Close(context.Background())
	_, digest := policyBytes(p)
	var expiry time.Time
	e = c.QueryRow(ctx, `SELECT b.expires_at FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent WHERE a.id=$1 AND a.auth_generation=$2 AND b.auth_generation=a.auth_generation AND b.id=$3 AND b.policy_digest=$4 AND NOT a.authentication_in_progress AND a.prepared_auth_generation IS NULL AND a.pending_generation_transition IS NULL AND a.capture_failure_revision=a.capture_resume_revision AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp()`, p.Account, p.Generation, p.BudgetID, digest).Scan(&expiry)
	if e != nil {
		return time.Time{}, errors.Join(ErrBudget, e)
	}
	return expiry, nil
}

func productionBudgetTx(ctx context.Context, tx pgx.Tx, o Owner) (captureBudget, error) {
	b := captureBudget{State: "active"}
	var raw []byte
	var digest string
	e := tx.QueryRow(ctx, `SELECT b.policy,b.policy_digest,b.expires_at FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent AND b.account_id=a.id WHERE a.id=$1 AND a.owner=$2 AND a.owner_fence=$3 AND a.auth_generation=$4 AND NOT a.closed AND a.status='running' AND a.lease_expires_at>clock_timestamp() AND (a.quota_wait_until IS NULL OR a.quota_wait_until<=clock_timestamp()) AND b.auth_generation=a.auth_generation AND b.revoked_at IS NULL FOR UPDATE OF b`, o.Account, o.ID, o.Fence, o.Generation).Scan(&raw, &digest, &b.Expires)
	if e != nil {
		return b, queryFailure(ctx, e, ErrBudget, stageBudget)
	}
	if strictCapturePolicy(raw, &b.Policy) != nil || b.Policy.Version != 2 || b.Policy.Account != o.Account || b.Policy.Generation != o.Generation || !b.Policy.ExpiresAt.Truncate(time.Microsecond).Equal(b.Expires) {
		return b, ErrBudget
	}
	_, want := policyBytes(b.Policy)
	if want != digest {
		return b, ErrBudget
	}
	if e = b.active(ctx, tx); e != nil {
		return b, e
	}
	e = tx.QueryRow(ctx, `SELECT date_bin(make_interval(secs=>$1),clock_timestamp(),$2::timestamptz)`, b.Policy.WindowSeconds, b.Policy.PeriodAnchor).Scan(&b.PeriodStart)
	if e != nil {
		return b, e
	}
	empty, _ := json.Marshal(map[string]CaptureLimits{"control": {}, "bootstrap": {}, "live": {}})
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_capture_usage(account_id,auth_generation,period_start,counters) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, o.Account, o.Generation, b.PeriodStart, string(empty))
	if e != nil {
		return b, e
	}
	e = tx.QueryRow(ctx, `SELECT counters FROM noctis_v2.telegram_capture_usage WHERE account_id=$1 AND auth_generation=$2 AND period_start=$3 FOR UPDATE`, o.Account, o.Generation, b.PeriodStart).Scan(&raw)
	if e == nil {
		e = json.Unmarshal(raw, &b.Counters)
	}
	return b, e
}

func (s Store) productionCapture(ctx context.Context, o Owner) (bool, error) {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return false, e
	}
	defer c.Close(context.Background())
	var production bool
	e = c.QueryRow(ctx, `SELECT active_capture_consent IS NOT NULL FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND auth_generation=$4 AND NOT closed AND lease_expires_at>clock_timestamp()`, o.Account, o.ID, o.Fence, o.Generation).Scan(&production)
	return production, e
}

func (s Store) RevokeProductionConsent(ctx context.Context, account, id string, revision int64) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_capture_consents b SET revoked_at=clock_timestamp() FROM noctis_v2.telegram_accounts a WHERE a.id=$1 AND a.active_capture_consent=b.id AND b.id=$2 AND a.consent_revision=$3 AND b.revoked_at IS NULL`, account, id, revision)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrBudget
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s Store) productionStatus(ctx context.Context, p CapturePolicy) (map[string]any, error) {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return nil, e
	}
	defer c.Close(context.Background())
	var raw []byte
	var expiry, start time.Time
	var revoked bool
	var waiting bool
	var blocked bool
	var failureRevision int64
	var waitUntil *time.Time
	var waitReason *string
	_, digest := policyBytes(p)
	e = c.QueryRow(ctx, `SELECT b.expires_at,b.revoked_at IS NOT NULL,date_bin(make_interval(secs=>$5),clock_timestamp(),$6::timestamptz),COALESCE(a.quota_wait_until>clock_timestamp(),false),a.quota_wait_until,a.quota_wait_reason,a.capture_failure_revision>a.capture_resume_revision OR a.authentication_in_progress OR a.prepared_auth_generation IS NOT NULL OR a.pending_generation_transition IS NOT NULL OR b.auth_generation<>a.auth_generation,a.capture_failure_revision FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent WHERE a.id=$1 AND a.auth_generation=$2 AND b.id=$3 AND b.policy_digest=$4`, p.Account, p.Generation, p.BudgetID, digest, p.WindowSeconds, p.PeriodAnchor).Scan(&expiry, &revoked, &start, &waiting, &waitUntil, &waitReason, &blocked, &failureRevision)
	if e != nil {
		return nil, e
	}
	counters := map[string]CaptureLimits{"control": {}, "bootstrap": {}, "live": {}}
	e = c.QueryRow(ctx, `SELECT counters FROM noctis_v2.telegram_capture_usage WHERE account_id=$1 AND auth_generation=$2 AND period_start=$3`, p.Account, p.Generation, start).Scan(&raw)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	if e == nil {
		if e = json.Unmarshal(raw, &counters); e != nil {
			return nil, e
		}
	}
	state := "active"
	if revoked {
		state = "revoked"
	} else if !time.Now().Before(expiry) {
		state = "expired"
	} else if blocked {
		state = "blocked"
	} else if waiting {
		state = "exhausted"
	} else {
		total := CaptureLimits{}
		for _, v := range counters {
			total = addLimits(total, v)
		}
		if total.API >= p.Global.API || total.Observations >= p.Global.Observations || total.PayloadBytes >= p.Global.PayloadBytes || total.MetadataBytes >= p.Global.MetadataBytes {
			state = "exhausted"
		}
	}
	return map[string]any{"state": state, "expires_at": expiry, "period_start": start, "next_period_at": start.Add(time.Duration(p.WindowSeconds) * time.Second), "counters": counters, "revision": p.Revision, "quota_wait_until": waitUntil, "quota_wait_reason": waitReason, "failure_revision": failureRevision}, nil
}

// Each iteration establishes a new fenced owner only after Run returned and
// recorded closure. Unknown errors stop; only planned period waits, the bounded
// process deadline and Telegram FloodWait permit supervised reopening.
func (s Store) superviseProduction(ctx context.Context, cfg ClientConfig, p CapturePolicy) error {
	for {
		status, e := s.productionStatus(ctx, p)
		if e != nil {
			return e
		}
		state := status["state"].(string)
		if state == "blocked" {
			return ErrOwnership
		}
		if state == "expired" || state == "revoked" {
			return ErrBudget
		}
		if state == "exhausted" {
			if e = waitUntil(ctx, productionWaitUntil(status)); e != nil {
				return e
			}
			continue
		}
		e = s.runClientOnce(ctx, cfg, nil)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c, ce := pgx.Connect(ctx, s.DSN)
		if ce != nil {
			return errors.Join(e, ce)
		}
		var closed bool
		var blocked bool
		var accountState string
		var retry *time.Time
		ce = c.QueryRow(ctx, `SELECT closed,status,retry_at,capture_failure_revision>capture_resume_revision FROM noctis_v2.telegram_accounts WHERE id=$1`, p.Account).Scan(&closed, &accountState, &retry, &blocked)
		c.Close(context.Background())
		if ce != nil || !closed || blocked {
			return errors.Join(e, ce, ErrOwnership)
		}
		if errors.Is(e, ErrOwnership) {
			return e
		}
		if accountState == "revoked" {
			return errors.Join(e, ErrBudget)
		}
		if accountState == "flood_wait" && retry != nil {
			if ce = waitUntil(ctx, *retry); ce != nil {
				return ce
			}
			continue
		}
		if errors.Is(e, ErrBudget) {
			status, ce = s.productionStatus(ctx, p)
			if ce != nil {
				return ce
			}
			if errors.Is(e, ErrQuota) {
				if ce = waitUntil(ctx, productionWaitUntil(status)); ce != nil {
					return ce
				}
				continue
			}
			if status["state"] != "active" {
				continue
			}
			return e
		}
		if !pureProcessClose(e) {
			return e
		}
	}
}

func productionWaitUntil(status map[string]any) time.Time {
	at := status["next_period_at"].(time.Time)
	if until, ok := status["quota_wait_until"].(*time.Time); ok && until != nil && until.After(at) {
		at = *until
	}
	return at
}

func waitUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
