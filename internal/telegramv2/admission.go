package telegramv2

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/jackc/pgx/v5"
)

type reservedAPIKey struct{}
type apiAdmission struct {
	conn  *pgx.Conn
	mu    sync.Mutex
	used  bool
	owner Owner
	phase string
}
type phaseKey struct{}
type authorizationKey struct{}
type SourceAuthorization struct {
	PolicyVersion  string `json:"policy_version"`
	PolicyRevision int64  `json:"policy_revision"`
}
type SourceAuthorizations map[string]SourceAuthorization

func authorizationFrom(ctx context.Context) SourceAuthorizations {
	v, _ := ctx.Value(authorizationKey{}).(SourceAuthorizations)
	return v
}
func validateAuthorization(ctx context.Context, tx pgx.Tx, expected SourceAuthorizations) error {
	for source, want := range expected {
		var got SourceAuthorization
		if e := tx.QueryRow(ctx, `SELECT s.policy_version,s.policy_revision FROM noctis_v2.sources s WHERE s.id=$1 AND `+intelligence.SourceAuthorizedSQL, source).Scan(&got.PolicyVersion, &got.PolicyRevision); e != nil {
			return queryFailure(ctx, e, errors.New("native response authorization changed"), stageAuthorization)
		}
		if got != want {
			return errors.New("native response policy changed")
		}
	}
	return nil
}

func phaseContext(ctx context.Context, phase string) context.Context {
	return context.WithValue(ctx, phaseKey{}, phase)
}

// Reserve on the same stable connection as the projection guard, committing
// before invoke. A crash or uncertain invoke consumes its admission forever.
func reserveAPI(ctx context.Context, c *pgx.Conn, o Owner, phase, source string, target *Peer, hash *int64, snapshot SourceAuthorizations) (err error) {
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, finishNativeTransaction(tx, o, err)) }()
	var active bool
	e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND auth_generation=$4 AND NOT closed AND status='running' AND lease_expires_at>clock_timestamp() FOR UPDATE`, o.Account, o.ID, o.Fence, o.Generation).Scan(&active)
	if e != nil {
		return queryFailure(ctx, e, ErrOwnership, stageOwnership)
	}
	if _, e = tx.Exec(ctx, `SAVEPOINT native_capture_work`); e != nil {
		return e
	}
	b, e := budgetTx(ctx, tx, o)
	if e != nil {
		return e
	}
	if b.Policy.Version == 2 && phase == "bootstrap" && target != nil {
		return errors.New("production bootstrap history disabled; current channel baseline required")
	}
	found := source == "" && target == nil
	for _, p := range b.Policy.Peers {
		if source != "" && source != p.SourceID || target != nil && (p.Type != target.Type || p.ID != target.ID) {
			continue
		}
		if e = b.allowSource(ctx, tx, p, phase); e != nil {
			return e
		}
		if snapshot != nil {
			var current SourceAuthorization
			if e = tx.QueryRow(ctx, `SELECT policy_version,policy_revision FROM noctis_v2.sources WHERE id=$1`, p.SourceID).Scan(&current.PolicyVersion, &current.PolicyRevision); e != nil {
				return e
			}
			snapshot[p.SourceID] = current
		}
		if hash != nil {
			var valid bool
			if e = tx.QueryRow(ctx, `SELECT access_hash=$4 FROM noctis_v2.telegram_peers WHERE account_id=$1 AND peer_type=$2 AND peer_id=$3`, o.Account, p.Type, p.ID, *hash).Scan(&valid); e != nil {
				return e
			}
			if !valid {
				return errors.New("native peer access binding changed")
			}
		}
		found = true
	}
	if !found {
		return errors.New("native RPC target outside immutable capture policy")
	}
	if e = b.charge(ctx, tx, phase, CaptureLimits{API: 1}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s Store) guardAPI(ctx context.Context, o Owner, phase, source string, target *Peer, hash *int64, fn func(context.Context) error) error {
	return s.guardAPIWithTimeout(ctx, o, phase, source, target, hash, 20*time.Second, fn)
}

func (s Store) guardAPIWithTimeout(ctx context.Context, o Owner, phase, source string, target *Peer, hash *int64, budget time.Duration, fn func(context.Context) error) (result error) {
	started := time.Now()
	defer func() {
		if result != nil {
			logCaptureFailure(result, stageProjection, started)
		}
	}()
	ctx, cancel := context.WithTimeoutCause(ctx, budget, errOperationTimeout)
	defer cancel()
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return cancellationAt(ctx, e, stageConnect)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = c.Close(cleanup)
	}()
	result = intelligence.GuardProjectionIO(ctx, c, func(ioCtx context.Context) error {
		snapshot := SourceAuthorizations{}
		if e := reserveAPI(ioCtx, c, o, phase, source, target, hash, snapshot); e != nil {
			return e
		}
		ioCtx = context.WithValue(phaseContext(ioCtx, phase), reservedAPIKey{}, &apiAdmission{conn: c, owner: o, phase: phase})
		ioCtx = context.WithValue(ioCtx, authorizationKey{}, snapshot)
		return cancellationAt(ioCtx, fn(ioCtx), stageInvoke)
	})
	return cancellationAt(ctx, result, stageProjection)
}

func (s Store) captureMiddleware(o Owner) telegram.Middleware {
	return telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		return func(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
			if admission, _ := ctx.Value(reservedAPIKey{}).(*apiAdmission); admission != nil {
				switch input.(type) {
				case *tg.HelpGetConfigRequest, *tg.UsersGetUsersRequest, *tg.UpdatesGetStateRequest, *tg.UpdatesGetDifferenceRequest, *tg.UpdatesGetChannelDifferenceRequest, *tg.MessagesGetHistoryRequest, *tg.MessagesGetDialogsRequest, *tg.ContactsResolveUsernameRequest:
				default:
					return errors.New("RPC outside native capture admission allowlist")
				}
				admission.mu.Lock()
				var e error
				if admission.used {
					e = reserveAPI(ctx, admission.conn, admission.owner, admission.phase, "", nil, nil, nil)
				} else {
					admission.used = true
				}
				admission.mu.Unlock()
				if e != nil {
					return e
				}
				return next.Invoke(ctx, input, output)
			}
			// Explicit coordinator calls carry a reserved context. Housekeeping and
			// startup calls consume the control phase as well as the global API cap.
			switch input.(type) {
			case *tg.HelpGetConfigRequest, *tg.UsersGetUsersRequest, *tg.UpdatesGetStateRequest:
			default:
				return errors.New("native RPC requires explicit guarded coordinator admission")
			}
			phase := "control"
			if p, ok := ctx.Value(phaseKey{}).(string); ok {
				phase = p
			}
			return s.guardAPI(ctx, o, phase, "", nil, nil, func(ioCtx context.Context) error { return next.Invoke(ioCtx, input, output) })
		}
	})
}
