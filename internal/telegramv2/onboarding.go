package telegramv2

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strconv"
	"time"
)

// InventoryImport serializes read-only Telegram discovery against every native
// collector through the same durable closed-owner fence and session flock.
// It imports identities only; source creation and activation remain explicit.
func (s Store) InventoryImport(ctx context.Context, cfg ClientConfig, actor string) (string, error) {
	if actor == "" || cfg.Account == "" {
		return "", errors.New("account and inventory actor required")
	}
	generation, e := (&ProtectedSession{Path: cfg.SessionFile}).Generation(ctx)
	if e != nil {
		return "", e
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return "", e
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES($1,$2) ON CONFLICT DO NOTHING`, cfg.Account, generation)
	c.Close(context.Background())
	if e != nil {
		return "", e
	}
	id := uuid.NewString()
	e = s.runOwnedRequest(ctx, cfg.Account, 5*time.Second, ownerRequest{inventoryGeneration: generation}, func(ctx context.Context, o Owner) error {
		if o.Generation != generation {
			return ErrOwnership
		}
		return RunInventory(ctx, cfg, func(ctx context.Context, i *Inventory) error {
			candidates := []DialogCandidate{}
			if e := i.WalkDialogs(ctx, 1000, func(v DialogCandidate) error {
				if v.Type == "channel" && v.AccessHash != 0 {
					candidates = append(candidates, v)
				}
				return nil
			}); e != nil {
				return e
			}
			return s.SaveInventorySnapshot(ctx, o, id, actor, candidates)
		})
	})
	return id, e
}

func (s Store) SaveInventorySnapshot(ctx context.Context, o Owner, id, actor string, candidates []DialogCandidate) error {
	if _, e := uuid.Parse(id); e != nil {
		return e
	}
	if actor == "" || len(candidates) > 10000 {
		return errors.New("invalid inventory snapshot")
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
	var valid bool
	e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND auth_generation=$4 AND NOT closed AND NOT authentication_in_progress AND prepared_auth_generation IS NULL AND status='running' AND lease_expires_at>clock_timestamp() FOR UPDATE`, o.Account, o.ID, o.Fence, o.Generation).Scan(&valid)
	if e != nil {
		return errors.Join(ErrOwnership, e)
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_inventory_snapshots(id,account_id,auth_generation,actor) VALUES($1,$2,$3,$4)`, id, o.Account, o.Generation, actor)
	if e != nil {
		return e
	}
	for _, v := range candidates {
		peerID, e := strconv.ParseInt(v.ID, 10, 64)
		if e != nil || peerID <= 0 || v.Type != "channel" || v.Account != o.Account || v.AccessHash == 0 || len(v.Name) > 1024 {
			return errors.New("invalid inventory channel")
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_inventory_candidates(snapshot_id,peer_type,peer_id,name,access_hash,folder,pts) VALUES($1,'channel',$2,$3,$4,$5,$6)`, id, peerID, v.Name, v.AccessHash, v.Folder, v.Pts)
		if e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
