package telegramv2

import (
	"context"
	"errors"
	"sync"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/transport"
)

var errCaptureEstablishmentDenied = errors.New("native capture permits only one primary establishment")

// One control admission covers initial establishment, including SDK-internal
// initialization/retries. Public application operations are admitted separately.
// A bounded capture never reconnects, migrates, or opens media/CDN connections.
type captureResolver struct {
	base   dcs.Resolver
	cancel context.CancelFunc
	mu     sync.Mutex
	used   bool
	err    error
}

func (r *captureResolver) deny() (transport.Conn, error) {
	r.mu.Lock()
	r.err = errors.Join(r.err, errCaptureEstablishmentDenied)
	err := r.err
	r.mu.Unlock()
	r.cancel()
	return nil, err
}
func (r *captureResolver) error() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
func (r *captureResolver) Primary(ctx context.Context, dc int, list dcs.List) (transport.Conn, error) {
	r.mu.Lock()
	used := r.used
	r.used = true
	r.mu.Unlock()
	if used {
		return r.deny()
	}
	conn, err := r.base.Primary(ctx, dc, list)
	if err != nil {
		r.mu.Lock()
		r.err = errors.Join(r.err, cancellationAt(ctx, err, stageStartup))
		r.mu.Unlock()
	}
	return conn, err
}
func (r *captureResolver) MediaOnly(context.Context, int, dcs.List) (transport.Conn, error) {
	return r.deny()
}
func (r *captureResolver) CDN(context.Context, int, dcs.List) (transport.Conn, error) {
	return r.deny()
}

func (s Store) runCaptureClient(ctx context.Context, o Owner, apiID int, apiHash string, options telegram.Options, callback func(context.Context, *telegram.Client) error) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	allow := make(chan struct{})
	ready := make(chan struct{})
	finished := make(chan struct{})
	var result error
	base := options.Resolver
	if base == nil {
		base = dcs.DefaultResolver()
	}
	resolver := &captureResolver{base: base, cancel: cancel}
	options.Resolver = resolver
	// gotd starts Self concurrently with establishment. Wait before acquiring
	// the projection guard, otherwise Self deadlocks the ready callback.
	options.Middlewares = append(options.Middlewares, telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		guarded := s.captureMiddleware(o).Handle(next)
		return func(ctx context.Context, in bin.Encoder, out bin.Decoder) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-allow:
				return guarded.Invoke(ctx, in, out)
			}
		}
	}))
	client := telegram.NewClient(apiID, apiHash, options)
	started := false
	err := s.guardAPI(ctx, o, "control", "", nil, nil, func(initCtx context.Context) error {
		started = true
		go func() {
			// Do not propagate the startup reservation context into Run: public
			// operations must acquire their own guard and durable admission.
			var callbackResult error
			result = client.Run(runCtx, func(ctx context.Context) (err error) {
				defer func() { callbackResult = cancellationAt(ctx, err, stageCallback) }()
				close(ready)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-allow:
					return callback(ctx, client)
				}
			})
			result = errors.Join(cancellationAt(runCtx, result, stageStartup), callbackResult)
			close(finished)
		}()
		select {
		case <-ready:
			return nil
		case <-finished:
			if runCtx.Err() != nil && safeProductionClose(ctx, result, "", nil) {
				return cancellationAt(runCtx, runCtx.Err(), stageStartup)
			}
			return errors.Join(errors.New("native client closed before ready"), result)
		case <-initCtx.Done():
			cancel()
			<-finished // Close SDK transport before releasing projection/flock.
			return cancellationAt(initCtx, initCtx.Err(), stageStartup)
		}
	})
	if err != nil {
		cancel()
		if started {
			<-finished
		}
		return errors.Join(err, result, resolver.error())
	}
	close(allow) // guardAPI has released the establishment guard.
	<-finished
	return errors.Join(result, resolver.error())
}
