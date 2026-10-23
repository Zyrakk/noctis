package telegramv2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// InventoryRPC excludes history, update state, membership and policy operations.
type InventoryRPC interface {
	MessagesGetDialogs(context.Context, *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error)
	ContactsResolveUsername(context.Context, *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error)
}

// Inventory has no Store: discovery cannot initialize cursors or persist policy.
type Inventory struct {
	Account string
	RPC     InventoryRPC
}

func (i *Inventory) Resolve(ctx context.Context, username string) (*tg.ContactsResolvedPeer, error) {
	if len(username) < 1 || len(username) > 64 {
		return nil, errors.New("invalid Telegram alias")
	}
	return i.RPC.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: username})
}

func (i *Inventory) WalkDialogs(ctx context.Context, maxPages int, emit func(DialogCandidate) error) error {
	return walkDialogs(ctx, i.RPC, i.Account, maxPages, emit)
}

// Transport housekeeping is read-only too. The allowlist fails closed before
// forwarding any unexpected RPC, including login, history and update recovery.
func inventoryMiddleware(budget int) telegram.Middleware {
	var mu sync.Mutex
	return telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		return func(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
			switch input.(type) {
			case *tg.HelpGetConfigRequest, *tg.UsersGetUsersRequest, *tg.ContactsResolveUsernameRequest, *tg.MessagesGetDialogsRequest:
			default:
				return errors.New("RPC forbidden in read-only Telegram inventory")
			}
			mu.Lock()
			if budget <= 0 {
				mu.Unlock()
				return errors.New("Telegram inventory RPC budget exhausted")
			}
			budget--
			mu.Unlock()
			return next.Invoke(ctx, input, output)
		}
	})
}

// RunInventory reads an existing protected session into memory. It never opens
// PostgreSQL, logs in, starts an update handler, catches up Differences, or writes
// the session file. Caller must establish exclusive account use across hosts.
func RunInventory(ctx context.Context, cfg ClientConfig, action func(context.Context, *Inventory) error) error {
	if cfg.APIID <= 0 || cfg.APIHash == "" || cfg.Authenticate || action == nil {
		return errors.New("read-only inventory requires existing API credentials and action; authentication forbidden")
	}
	if err := protectedPath(cfg.SessionFile, true); err != nil {
		return err
	}
	unlock, err := lockSession(cfg.SessionFile)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(cfg.SessionFile)
	if err != nil {
		return errors.New("protected session unavailable")
	}
	storage := &session.StorageMemory{}
	if err = storage.StoreSession(ctx, data); err != nil {
		return err
	}
	loaded, err := (&session.Loader{Storage: storage}).Load(ctx)
	if err != nil || len(loaded.AuthKey) != 256 {
		return errors.New("existing Telegram session invalid; login forbidden")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := telegram.NewClient(cfg.APIID, cfg.APIHash, telegram.Options{
		SessionStorage: storage, NoUpdates: true, MaxRetries: 1,
		Middlewares: []telegram.Middleware{inventoryMiddleware(128)},
	})
	return client.Run(ctx, func(ctx context.Context) error {
		status, err := client.Auth().Status(ctx)
		if err != nil {
			return errors.New("Telegram inventory authentication check failed; no login attempted")
		}
		if !status.Authorized || status.User == nil {
			return errors.New("Telegram authorization revoked; login forbidden")
		}
		account := fmt.Sprint(status.User.ID)
		if cfg.Account != "" && cfg.Account != account {
			return errors.New("Telegram authenticated account mismatch")
		}
		return action(ctx, &Inventory{Account: account, RPC: client.API()})
	})
}
