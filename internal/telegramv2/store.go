// Package telegramv2 coordinates native Telegram state in PostgreSQL. No gotd
// updates.Manager participates in cursor authority or database commits.
package telegramv2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrGap = errors.New("telegram native sequence gap: difference required")
var ErrOwnership = errors.New("telegram owner unavailable or uncertain")

type State struct {
	Pts  int `json:"pts"`
	Qts  int `json:"qts"`
	Date int `json:"date"`
	Seq  int `json:"seq"`
}
type Owner struct {
	Account    string
	ID         string
	Fence      int64
	Generation string
}
type Peer struct {
	Type string
	ID   int64
}
type Event struct {
	Peer        Peer
	MessageID   int
	Revision    string
	Kind        string
	Pts         int
	PtsCount    int
	Qts         int
	PublishedAt *time.Time
	// Payload is encoded only after allowlist lookup. Excluded payload is not read.
	Text     func() ([]byte, error)
	Metadata func() (json.RawMessage, error)
}
type Envelope struct {
	BatchID       string
	Expected      State
	Next          State
	Events        []Event
	Difference    bool
	Gap           bool
	Mode          capture.Mode
	History       *HistoryCursor
	Authorization SourceAuthorizations
}
type HistoryCursor struct {
	SourceID string
	Epoch    string
	Expected int
	Next     int
	Complete bool
}
type Receipt struct {
	BatchID     string    `json:"batch_id"`
	State       State     `json:"state"`
	Included    int       `json:"included"`
	Excluded    int       `json:"excluded"`
	CommittedAt time.Time `json:"committed_at"`
}
type Store struct{ DSN string }

func (s Store) Acquire(ctx context.Context, account, id string, duration time.Duration) (Owner, error) {
	o := Owner{Account: account, ID: id}
	if account == "" || id == "" || duration <= 0 {
		return o, ErrOwnership
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return o, e
	}
	defer c.Close(context.Background())
	e = c.QueryRow(ctx, `UPDATE noctis_v2.telegram_accounts SET owner=$2,owner_fence=owner_fence+1,closed=false,lease_expires_at=clock_timestamp()+$3::interval,status='running' WHERE id=$1 AND closed AND capture_failure_revision=capture_resume_revision AND (retry_at IS NULL OR retry_at<=clock_timestamp()) AND status<>'revoked' RETURNING owner_fence,auth_generation::text`, account, id, duration.String()).Scan(&o.Fence, &o.Generation)
	if errors.Is(e, pgx.ErrNoRows) {
		return o, ErrOwnership
	}
	return o, e
}
func (s Store) heartbeat(ctx context.Context, o Owner, d time.Duration) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET lease_expires_at=clock_timestamp()+$4::interval WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND NOT closed AND status='running' AND lease_expires_at>clock_timestamp()`, o.Account, o.ID, o.Fence, d.String())
	if e == nil && tag.RowsAffected() != 1 {
		return ErrOwnership
	}
	return e
}

// RunOwned cancels the complete RPC Run on lease loss and records closure only
// after Run returned. Expiry alone cannot grant a second client this session.
func (s Store) RunOwned(ctx context.Context, account string, run func(context.Context, Owner) error) error {
	return s.runOwnedWithHeartbeat(ctx, account, 5*time.Second, run)
}

func (s Store) runOwnedWithHeartbeat(ctx context.Context, account string, interval time.Duration, run func(context.Context, Owner) error) error {
	o, e := s.Acquire(ctx, account, uuid.NewString(), 30*time.Second)
	if e != nil {
		return e
	}
	started := time.Now()
	rpcCtx, cancel := context.WithCancelCause(ctx)
	rpcCtx = context.WithValue(rpcCtx, captureRootKey{}, ctx)
	defer cancel(context.Canceled)
	done := make(chan struct{})
	hbErr := make(chan error, 1)
	var stopping atomic.Bool
	go func() {
		defer close(done)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-rpcCtx.Done():
				return
			case <-tick.C:
				if e := s.heartbeat(rpcCtx, o, 30*time.Second); e != nil {
					// Parent cancellation while heartbeat SQL is blocked is not a
					// lost lease. Preserve genuine/mixed failures even then.
					e = cancellationAt(rpcCtx, e, stageLease)
					c, canceled := e.(*causalCancellation)
					inherited := canceled && (c.cause == errProcessWindow || c.shutdown || stopping.Load() && c.cause == context.Canceled)
					if !inherited {
						hbErr <- errors.Join(errLeaseLoss, e)
						cancel(errLeaseLoss)
					}
					return
				}
			}
		}
	}()
	e = run(rpcCtx, o)
	e = processClose(cancellationAt(rpcCtx, e, stageRun))
	stopping.Store(true)
	cancel(context.Canceled)
	<-done
	select {
	case he := <-hbErr:
		e = errors.Join(e, he)
	default:
	}
	logCaptureFailure(e, stageRun, started)
	closeCtx, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	c, ce := pgx.Connect(closeCtx, s.DSN)
	if ce != nil {
		return errors.Join(e, ce)
	}
	defer c.Close(context.Background())
	ce = s.closeOwned(closeCtx, c, o, ctx, e)
	return errors.Join(e, ce)
}
func (s Store) State(ctx context.Context, account string) (State, error) {
	var state State
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return state, e
	}
	defer c.Close(context.Background())
	var raw []byte
	e = c.QueryRow(ctx, `SELECT state FROM noctis_v2.telegram_accounts WHERE id=$1`, account).Scan(&raw)
	if e == nil {
		e = json.Unmarshal(raw, &state)
	}
	return state, e
}

func (s Store) CommitUpdates(ctx context.Context, o Owner, b Envelope) (result Receipt, err error) {
	r := Receipt{BatchID: b.BatchID, State: b.Next}
	if _, e := uuid.Parse(b.BatchID); e != nil {
		return r, e
	}
	if len(b.Events) > 10000 {
		return r, errors.New("telegram batch limit")
	}
	if b.Mode != capture.Live && b.Mode != capture.Bootstrap {
		return r, errors.New("invalid Telegram epoch mode")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return r, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return r, e
	}
	defer func() { err = errors.Join(err, finishNativeTransaction(tx, o, err)) }()
	var raw []byte
	// Authorize before any payload callback, fenced against PIR/source pause.
	// Take the projection guard before native account/peer rows, matching revoke.
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return r, e
	}
	e = tx.QueryRow(ctx, `SELECT state FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND auth_generation=$4 AND NOT closed AND status='running' AND lease_expires_at>clock_timestamp() FOR UPDATE`, o.Account, o.ID, o.Fence, o.Generation).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, ErrOwnership
	}
	if e != nil {
		return r, e
	}
	if _, e = tx.Exec(ctx, `SAVEPOINT native_capture_work`); e != nil {
		return r, e
	}
	budget, e := budgetTx(ctx, tx, o)
	if e != nil {
		return r, e
	}
	if e = budget.active(ctx, tx); e != nil {
		return r, e
	}
	if e = validateAuthorization(ctx, tx, b.Authorization); e != nil {
		return r, e
	}
	for source := range b.Authorization {
		found := false
		for _, peer := range budget.Policy.Peers {
			if peer.SourceID == source {
				found = true
				if e = budget.allowSource(ctx, tx, peer, string(b.Mode)); e != nil {
					return r, e
				}
			}
		}
		if !found {
			return r, ErrBudget
		}
	}
	var state State
	if e = json.Unmarshal(raw, &state); e != nil {
		return r, e
	}
	if h := b.History; h != nil {
		var authorized bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.source_id=$2 AND p.bootstrap_epoch=$3 AND p.allowed AND p.auth_generation=$4 AND `+intelligence.SourceAuthorizedSQL+`)`, o.Account, h.SourceID, h.Epoch, o.Generation).Scan(&authorized); e != nil {
			return r, e
		}
		if !authorized {
			return r, errors.New("history source authorization changed")
		}
	}
	// Receipt replay is checked before cursor CAS; it confirms the previous commit.
	// Hash only allowlisted payloads. Excluded callbacks are never invoked, even
	// while fingerprinting a replay. Protocol identities remain in the digest.
	type fingerprintEvent struct {
		Peer                      Peer
		ID                        int
		Revision, Kind            string
		Pts, Count, Qts           int
		PayloadHash, MetadataHash string
	}
	fingerprints := []fingerprintEvent{}
	var materializedPayload, materializedMetadata int64
	for i, event := range b.Events {
		f := fingerprintEvent{Peer: event.Peer, ID: event.MessageID, Revision: event.Revision, Kind: event.Kind, Pts: event.Pts, Count: event.PtsCount, Qts: event.Qts}
		var allowed bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.peer_type=$2 AND p.peer_id=$3 AND p.allowed AND p.auth_generation=$4 AND `+intelligence.SourceAuthorizedSQL+` AND s.kind='telegram')`, o.Account, event.Peer.Type, event.Peer.ID, o.Generation).Scan(&allowed); e != nil {
			return r, e
		}
		if allowed && event.Kind != "protocol_disposition" {
			allowed, e = budget.captureAllowed(ctx, tx, event.Peer, string(b.Mode))
			if e != nil {
				return r, e
			}
		}
		if allowed && event.Kind != "protocol_disposition" {
			if event.Text != nil {
				payload, e := event.Text()
				if e != nil {
					return r, e
				}
				if len(payload) > 8<<20 {
					return r, errors.New("telegram payload limit")
				}
				materializedPayload += int64(len(payload))
				if materializedPayload > 64<<20 {
					return r, ErrBudget
				}
				f.PayloadHash = fmt.Sprintf("%x", sha256.Sum256(payload))
				b.Events[i].Text = func() ([]byte, error) { return payload, nil }
			}
			if event.Metadata != nil {
				metadata, e := event.Metadata()
				if e != nil {
					return r, e
				}
				if len(metadata) > 64<<10 || !json.Valid(metadata) {
					return r, errors.New("invalid Telegram metadata")
				}
				materializedMetadata += int64(len(metadata))
				if materializedMetadata > 4<<20 {
					return r, ErrBudget
				}
				f.MetadataHash = fmt.Sprintf("%x", sha256.Sum256(metadata))
				b.Events[i].Metadata = func() (json.RawMessage, error) { return metadata, nil }
			}
		}
		fingerprints = append(fingerprints, f)
	}
	fingerprint, _ := json.Marshal(struct {
		Expected, Next  State
		Events          []fingerprintEvent
		Mode            capture.Mode
		Difference, Gap bool
		History         *HistoryCursor
		Authorization   SourceAuthorizations
	}{b.Expected, b.Next, fingerprints, b.Mode, b.Difference, b.Gap, b.History, b.Authorization})
	digest := fmt.Sprintf("%x", sha256.Sum256(fingerprint))
	var previous []byte
	var previousDigest string
	e = tx.QueryRow(ctx, `SELECT receipt,digest FROM noctis_v2.telegram_commits WHERE account_id=$1 AND batch_id=$2`, o.Account, b.BatchID).Scan(&previous, &previousDigest)
	if e == nil {
		if digest != previousDigest {
			return r, capture.ErrConflict
		}
		e = json.Unmarshal(previous, &r)
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return r, e
	}
	if state != b.Expected {
		return r, capture.ErrConflict
	}
	if b.Next.Pts < state.Pts || b.Next.Qts < state.Qts || b.Next.Seq < state.Seq || b.Next.Date < state.Date {
		return r, ErrGap
	}
	// Preflight the complete retained batch before native/capture writes. The
	// account lock and projection guard make these dedup reads stable until commit.
	delta, e := budget.batchCost(ctx, tx, o, b)
	if e != nil {
		return r, e
	}
	if e = budget.charge(ctx, tx, string(b.Mode), delta); e != nil {
		return r, e
	}
	pts, qts := state.Pts, state.Qts
	for _, event := range b.Events {
		if event.Kind == "delete" && event.Peer.Type == "unknown" {
			var kind string
			var id int64
			e = tx.QueryRow(ctx, `SELECT peer_type,peer_id FROM noctis_v2.telegram_inbox WHERE account_id=$1 AND message_id=$2 AND peer_type IN ('chat','user') AND disposition='captured' ORDER BY created_at DESC LIMIT 1`, o.Account, event.MessageID).Scan(&kind, &id)
			if e == nil {
				event.Peer = Peer{Type: kind, ID: id}
			} else if !errors.Is(e, pgx.ErrNoRows) {
				return r, e
			}
		}
		if event.MessageID <= 0 || event.Revision == "" {
			return r, errors.New("invalid Telegram event identity")
		}
		switch event.Peer.Type {
		case "channel", "chat", "user", "unknown":
		default:
			return r, errors.New("invalid Telegram peer type")
		}
		channel := event.Peer.Type == "channel"
		current := pts
		if channel {
			e = tx.QueryRow(ctx, `SELECT pts FROM noctis_v2.telegram_channel_states WHERE account_id=$1 AND channel_id=$2`, o.Account, event.Peer.ID).Scan(&current)
			if errors.Is(e, pgx.ErrNoRows) {
				current = 0
			} else if e != nil {
				return r, e
			}
			var allowed bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.peer_type='channel' AND p.peer_id=$2 AND p.allowed AND p.auth_generation=$3 AND `+intelligence.SourceAuthorizedSQL+`)`, o.Account, event.Peer.ID, o.Generation).Scan(&allowed); e != nil {
				return r, e
			}
			// Excluded channels have minimal native dispositions; never fetch
			// their history just to reconcile payload we are forbidden to retain.
			if !allowed && current == 0 {
				current = max(0, event.Pts-event.PtsCount)
			}
		}
		if !b.Difference && event.PtsCount > 0 && event.Pts != current+event.PtsCount {
			if event.Pts <= current {
				continue
			}
			return r, ErrGap
		}
		if event.Qts > 0 && !b.Difference && event.Qts != qts+1 {
			if event.Qts <= qts {
				continue
			}
			return r, ErrGap
		}
		if event.PtsCount > 0 {
			if channel {
				_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_channel_states(account_id,channel_id,pts) VALUES($1,$2,$3) ON CONFLICT(account_id,channel_id) DO UPDATE SET pts=GREATEST(noctis_v2.telegram_channel_states.pts,EXCLUDED.pts)`, o.Account, event.Peer.ID, event.Pts)
				if e != nil {
					return r, e
				}
			} else {
				pts = max(pts, event.Pts)
			}
		}
		qts = max(qts, event.Qts)
		var disposed bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_inbox WHERE account_id=$1 AND peer_type=$2 AND peer_id=$3 AND message_id=$4 AND revision=$5)`, o.Account, event.Peer.Type, event.Peer.ID, event.MessageID, event.Revision).Scan(&disposed); e != nil {
			return r, e
		}
		if disposed {
			continue
		}
		var sourceID, epoch string
		e = tx.QueryRow(ctx, `SELECT s.id::text,CASE WHEN $5='bootstrap' THEN p.bootstrap_epoch ELSE s.epoch END::text FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.peer_type=$2 AND p.peer_id=$3 AND p.allowed AND p.auth_generation=$4 AND `+intelligence.SourceAuthorizedSQL+` AND s.kind='telegram'`, o.Account, event.Peer.Type, event.Peer.ID, o.Generation, string(b.Mode)).Scan(&sourceID, &epoch)
		included := e == nil
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return r, e
		}
		if included {
			included, e = budget.captureAllowed(ctx, tx, event.Peer, string(b.Mode))
			if e != nil {
				return r, e
			}
		}
		disposition := "excluded_by_allowlist"
		metadata := json.RawMessage(`{}`)
		if included && event.Kind != "protocol_disposition" {
			disposition = "captured"
			r.Included++
			if event.Metadata != nil {
				metadata, e = event.Metadata()
				if e != nil {
					return r, e
				}
				if !json.Valid(metadata) || len(metadata) > 64<<10 {
					return r, errors.New("invalid Telegram metadata")
				}
			}
			if event.Kind == "delete" {
				disposition = "deleted"
				if e = invalidateMessageTx(ctx, tx, sourceID, fmt.Sprint(event.MessageID), event.Revision, true); e != nil {
					return r, e
				}
			} else {
				if event.Text == nil {
					return r, errors.New("message payload missing")
				}
				text, e := event.Text()
				if e != nil {
					return r, e
				}
				if len(text) > 8<<20 {
					return r, errors.New("telegram payload limit")
				}
				expected := capture.Checkpoint{Value: json.RawMessage(`null`)}
				var value []byte
				e = tx.QueryRow(ctx, `SELECT version,value FROM noctis_v2.checkpoints WHERE source_id=$1 AND epoch=$2 AND mode=$3`, sourceID, epoch, b.Mode).Scan(&expected.Version, &value)
				if e == nil {
					expected.Value = value
				} else if !errors.Is(e, pgx.ErrNoRows) {
					return r, e
				}
				next := capture.Checkpoint{Version: expected.Version + 1, Value: json.RawMessage(fmt.Sprint(event.MessageID))}
				hash := fmt.Sprintf("sha256:%x", sha256.Sum256(text))
				_, e = capture.CommitBatchTx(ctx, tx, capture.Batch{BatchID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(b.BatchID+":"+sourceID+":"+fmt.Sprint(event.MessageID)+":"+event.Revision)).String(), Version: "1", SourceID: sourceID, Epoch: epoch, Mode: b.Mode, Expected: expected, Next: next, Items: []capture.Item{{NativeID: fmt.Sprint(event.MessageID), Revision: event.Revision, Hash: hash, Representation: "text/plain;utf8;v1", Payload: text, PublishedAt: event.PublishedAt, CollectedAt: time.Now().UTC()}}})
				if e != nil {
					return r, e
				}
				if event.Kind == "edit" && b.Mode == capture.Live {
					if e = invalidateMessageTx(ctx, tx, sourceID, fmt.Sprint(event.MessageID), event.Revision, false); e != nil {
						return r, e
					}
				}
			}
		} else {
			if event.Kind == "protocol_disposition" {
				disposition = "protocol_only"
			}
			r.Excluded++
		}
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_inbox(account_id,peer_type,peer_id,message_id,revision,event,disposition,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, o.Account, event.Peer.Type, event.Peer.ID, event.MessageID, event.Revision, event.Kind, disposition, string(metadata)); e != nil {
			return r, e
		}
	}
	if !b.Difference && (pts != b.Next.Pts || qts != b.Next.Qts) {
		return r, ErrGap
	}
	if h := b.History; h != nil {
		if b.Mode != capture.Bootstrap || h.Expected < 0 || h.Next < 0 || h.Expected > 0 && h.Next > h.Expected {
			return r, errors.New("invalid bootstrap history cursor")
		}
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_history_cursors(source_id,epoch,offset_id) SELECT p.source_id,p.bootstrap_epoch,0 FROM noctis_v2.telegram_peers p WHERE p.account_id=$1 AND p.source_id=$2 AND p.bootstrap_epoch=$3 AND p.allowed AND p.auth_generation=$4 ON CONFLICT DO NOTHING`, o.Account, h.SourceID, h.Epoch, o.Generation); e != nil {
			return r, e
		}
		tag, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_history_cursors SET offset_id=$4,complete=$5 WHERE source_id=$1 AND epoch=$2 AND offset_id=$3 AND NOT complete`, h.SourceID, h.Epoch, h.Expected, h.Next, h.Complete)
		if e != nil {
			return r, e
		}
		if tag.RowsAffected() != 1 {
			return r, capture.ErrConflict
		}
	}
	encoded, _ := json.Marshal(b.Next)
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET state=$4,gap=gap OR $5,updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND lease_expires_at>clock_timestamp()`, o.Account, o.ID, o.Fence, string(encoded), b.Gap)
	if e != nil {
		return r, e
	}
	if tag.RowsAffected() != 1 {
		return r, ErrOwnership
	}
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&r.CommittedAt); e != nil {
		return r, e
	}
	receipt, _ := json.Marshal(r)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_commits VALUES($1,$2,$3,$4)`, o.Account, b.BatchID, digest, string(receipt))
	if e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return r, e
	}
	return r, nil
}

func (s Store) Pause(ctx context.Context, o Owner, status string, retryAt *time.Time) error {
	if status != "revoked" && status != "flood_wait" && status != "ownership_uncertain" {
		return errors.New("invalid Telegram pause")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET status=$4,retry_at=$5 WHERE id=$1 AND owner=$2 AND owner_fence=$3`, o.Account, o.ID, o.Fence, status, retryAt)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrOwnership
	}
	return e
}
