package telegramv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/jackc/pgx/v5"
)

type ProtectedSession struct {
	Path string
	mu   sync.Mutex
}

func protectedPath(path string, exists bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("protected file requires absolute path")
	}
	d, e := os.Lstat(filepath.Dir(path))
	if e != nil || !d.IsDir() || d.Mode().Perm()&0077 != 0 {
		return errors.New("protected directory requires mode 0700")
	}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) && !exists {
		return nil
	}
	if e != nil {
		return errors.New("protected file unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("protected file requires regular file mode 0600")
	}
	return nil
}
func protectedWrite(path string, data []byte) error {
	if e := protectedPath(path, false); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".private-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (s *ProtectedSession) LoadSession(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := protectedPath(s.Path, false); e != nil {
		return nil, e
	}
	data, e := os.ReadFile(s.Path)
	if os.IsNotExist(e) {
		return nil, session.ErrNotFound
	}
	if e != nil {
		return nil, errors.New("protected session unavailable")
	}
	return data, nil
}
func (s *ProtectedSession) StoreSession(_ context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return protectedWrite(s.Path, data)
}
func (s *ProtectedSession) Generation(ctx context.Context) (string, error) {
	data, e := (&session.Loader{Storage: s}).Load(ctx)
	if e != nil {
		return "", e
	}
	if len(data.AuthKey) == 0 {
		return "", errors.New("session auth key unavailable")
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, data.AuthKey).String(), nil
}

type ClientConfig struct {
	Account           string
	APIID             int
	APIHash           string
	SessionFile       string
	Authenticate      bool
	QRTokenFile       string
	PasswordFile      string
	CapturePolicyFile string
}

// RunClient wires real gotd transport and tg RPC to the PostgreSQL coordinator.
// QR tokens are available only in a protected local file and removed on exit.
// A logical receipt after commit makes no promise about MTProto transport ACKs.
func (s Store) RunClient(ctx context.Context, cfg ClientConfig, action func(context.Context, *Coordinator) error) error {
	if !cfg.Authenticate && action == nil && cfg.CapturePolicyFile != "" {
		p, e := ReadCapturePolicy(cfg.CapturePolicyFile)
		if e != nil {
			return e
		}
		if p.Version == 2 {
			return s.superviseProduction(ctx, cfg, p)
		}
	}
	return s.runClientOnce(ctx, cfg, action)
}

func (s Store) runClientOnce(ctx context.Context, cfg ClientConfig, action func(context.Context, *Coordinator) error) error {
	if cfg.Account == "" || cfg.APIID <= 0 || cfg.APIHash == "" {
		return errors.New("Telegram account and API credentials required")
	}
	unlock, e := lockSession(cfg.SessionFile)
	if e != nil {
		return e
	}
	defer unlock()
	var policy CapturePolicy
	if !cfg.Authenticate {
		policy, e = ReadCapturePolicy(cfg.CapturePolicyFile)
		if e != nil {
			return e
		}
		if policy.Account != cfg.Account {
			return ErrBudget
		}
	}
	storage := &ProtectedSession{Path: cfg.SessionFile}
	if e := protectedPath(cfg.SessionFile, false); e != nil {
		return e
	}
	generation, e := storage.Generation(ctx)
	if e != nil {
		if !cfg.Authenticate {
			return errors.New("Telegram authentication required")
		}
		generation = uuid.NewString()
	}
	if cfg.Authenticate {
		if e = protectedPath(cfg.QRTokenFile, false); e != nil {
			return e
		}
		defer os.Remove(cfg.QRTokenFile)
	}
	db, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	_, e = db.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES($1,$2) ON CONFLICT DO NOTHING`, cfg.Account, generation)
	db.Close(context.Background())
	if e != nil {
		return e
	}
	if !cfg.Authenticate {
		if policy.Generation != generation {
			return ErrBudget
		}
		expires, err := s.BindCapturePolicy(ctx, policy)
		if err != nil {
			return err
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, expires)
		defer cancel()
		ctx, cancel = context.WithTimeoutCause(ctx, time.Duration(policy.ProcessSeconds)*time.Second, errProcessWindow)
		defer cancel()
		slog.Info("native_capture_start", "kind", "process", "stage", string(stageRun), "started_at", time.Now().UTC(), "process_timeout_ms", int64(policy.ProcessSeconds)*1000)
	}
	result := s.runOwnedRequest(ctx, cfg.Account, 5*time.Second, ownerRequest{authenticate: cfg.Authenticate}, func(runCtx context.Context, o Owner) error {
		if !cfg.Authenticate && o.Generation != generation {
			return errors.New("Telegram auth generation changed; explicit protected auth required")
		}
		runCtx, cancel := context.WithCancel(runCtx)
		defer cancel()
		coordinator := &Coordinator{Store: s, Owner: o, authenticationOnly: cfg.Authenticate}
		dispatcher := tg.NewUpdateDispatcher()
		loggedIn := qrlogin.OnLoginToken(dispatcher)
		var ready bool
		var mu sync.Mutex
		updatesErr := make(chan error, 1)
		handler := telegram.UpdateHandlerFunc(func(updateCtx context.Context, updates tg.UpdatesClass) error {
			if cfg.Authenticate {
				if e := dispatcher.Handle(updateCtx, updates); e != nil {
					return e
				}
			}
			mu.Lock()
			isReady := ready
			mu.Unlock()
			if !isReady {
				return nil
			} // startup Difference reconciles all native state
			if e := coordinator.Handle(updateCtx, updates); e != nil {
				e = cancellationAt(updateCtx, e, stageCallback)
				select {
				case updatesErr <- e:
				default:
				}
				cancel()
				return e
			}
			return nil
		})
		options := telegram.Options{SessionStorage: storage, UpdateHandler: handler, MaxRetries: 1}
		callback := func(clientCtx context.Context, client *telegram.Client) error {
			coordinator.RPC = client.API()
			status, e := client.Auth().Status(clientCtx)
			if e != nil {
				return coordinator.failure(clientCtx, e)
			}
			if !status.Authorized {
				if !cfg.Authenticate {
					return errors.Join(errors.New("Telegram authorization revoked; paused"), s.Pause(clientCtx, o, "revoked", nil))
				}
				authCtx, end := context.WithTimeout(clientCtx, 5*time.Minute)
				defer end()
				_, e = client.QR().Auth(authCtx, loggedIn, func(_ context.Context, token qrlogin.Token) error {
					return protectedWrite(cfg.QRTokenFile, []byte(token.URL()))
				})
				if tgerr.Is(e, "SESSION_PASSWORD_NEEDED") {
					if e = protectedPath(cfg.PasswordFile, true); e != nil {
						return e
					}
					password, e := os.ReadFile(cfg.PasswordFile)
					if e != nil {
						return errors.New("2FA secret unavailable")
					}
					_, e = client.Auth().Password(clientCtx, string(password))
					for i := range password {
						password[i] = 0
					}
					if e != nil {
						return coordinator.failure(clientCtx, e)
					}
				} else if e != nil {
					return coordinator.failure(clientCtx, e)
				}
				status, e = client.Auth().Status(clientCtx)
				if e != nil {
					return coordinator.failure(clientCtx, e)
				}
			}
			if status.User == nil || fmt.Sprint(status.User.ID) != cfg.Account {
				return errors.New("Telegram authenticated account mismatch")
			}
			actual, e := storage.Generation(clientCtx)
			if e != nil {
				return e
			}
			if cfg.Authenticate {
				return s.prepareAuthenticatedGeneration(clientCtx, o, actual)
			}
			if actual != o.Generation {
				return errors.New("Telegram key rotation requires explicit auth")
			}
			current, e := s.State(clientCtx, cfg.Account)
			if e != nil {
				return e
			}
			if current.Pts == 0 {
				var remote *tg.UpdatesState
				var admission SourceAuthorizations
				phase := "bootstrap"
				if policy.Version == 2 {
					phase = "control"
				}
				e := s.guardAPI(clientCtx, coordinator.Owner, phase, "", nil, nil, func(ioCtx context.Context) error {
					admission = authorizationFrom(ioCtx)
					var callErr error
					remote, callErr = client.API().UpdatesGetState(ioCtx)
					return callErr
				})
				if e != nil {
					return coordinator.failure(clientCtx, e)
				}
				if _, e = s.CommitUpdates(clientCtx, coordinator.Owner, Envelope{BatchID: uuid.NewString(), Expected: current, Next: state(*remote), Difference: true, Gap: true, Mode: "bootstrap", Authorization: admission}); e != nil {
					return e
				}
			}
			if e = coordinator.Difference(clientCtx); e != nil {
				return e
			}
			mu.Lock()
			ready = true
			mu.Unlock()
			if action != nil {
				return action(clientCtx, coordinator)
			}
			tick := time.NewTicker(15 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-clientCtx.Done():
					return clientCtx.Err()
				case <-tick.C:
					if e = coordinator.Difference(clientCtx); e != nil {
						return e
					}
				}
			}
		}
		var e error
		if cfg.Authenticate {
			client := telegram.NewClient(cfg.APIID, cfg.APIHash, options)
			var callbackResult error
			e = client.Run(runCtx, func(ctx context.Context) error {
				callbackResult = callback(ctx, client)
				return callbackResult
			})
			e = errors.Join(e, callbackResult)
		} else {
			e = s.runCaptureClient(runCtx, o, cfg.APIID, cfg.APIHash, options, callback)
		}
		select {
		case updateError := <-updatesErr:
			e = errors.Join(e, updateError)
		default:
		}
		if policy.Version == 2 {
			return processClose(cancellationAt(runCtx, e, stageRun))
		}
		return e
	})
	return result
}
