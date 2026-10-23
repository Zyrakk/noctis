package telegramv2

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

var errOperationTimeout = errors.New("native API operation deadline ended")
var errLeaseLoss = errors.New("native capture lease lost")

type failureStage string

const (
	stageConnect       failureStage = "connect"
	stageProjection    failureStage = "projection_guard"
	stageOwnership     failureStage = "ownership"
	stageBudget        failureStage = "budget"
	stageAuthorization failureStage = "authorization"
	stageInvoke        failureStage = "invoke"
	stageStartup       failureStage = "startup"
	stageCallback      failureStage = "callback"
	stageLease         failureStage = "lease"
	stageRun           failureStage = "run"
)

// This is an atomic classification leaf. Unwrap preserves errors.Is without
// allowing later parent cancellation to overwrite the cause captured here.
type causalCancellation struct {
	err      error
	cause    error
	stage    failureStage
	shutdown bool
}

type captureRootKey struct{}

func (e *causalCancellation) Error() string { return "native capture cancellation" }
func (e *causalCancellation) Unwrap() error { return e.err }

func cancellationAt(ctx context.Context, err error, stage failureStage) error {
	if err == nil || !pureCancellation(err) {
		return err
	}
	root, _ := ctx.Value(captureRootKey{}).(context.Context)
	cause := context.Cause(ctx)
	shutdown := root != nil && root.Err() != nil && (cause == context.Canceled || cause == context.DeadlineExceeded) && context.Cause(root) == cause
	return &causalCancellation{err: err, cause: cause, stage: stage, shutdown: shutdown}
}

// A failed query proves a business denial only if it was not canceled.
func queryFailure(ctx context.Context, err, denial error, stage failureStage) error {
	marked := cancellationAt(ctx, err, stage)
	if _, ok := marked.(*causalCancellation); ok {
		return marked
	}
	return errors.Join(denial, err)
}

func processClose(err error) error {
	if err != nil && everyError(err, func(e error) bool {
		c, ok := e.(*causalCancellation)
		return e == errProcessWindow || ok && c.cause == errProcessWindow
	}) {
		return errProcessWindow
	}
	return err
}

// Diagnostics contain only fixed kinds/stages and timing, never error strings
// or connection/account/source/transport data.
func logCaptureFailure(err error, stage failureStage, started time.Time) {
	kind := "success"
	cause := "none"
	if err != nil {
		kind = "failure"
		unknown := false
		everyError(err, func(e error) bool {
			next := "none"
			if c, ok := e.(*causalCancellation); ok {
				if cause == "none" {
					stage = c.stage
				}
				switch c.cause {
				case errProcessWindow:
					next = "process_window"
				case errOperationTimeout:
					next = "operation_timeout"
				case errLeaseLoss:
					next = "lease_loss"
				default:
					if c.shutdown {
						next = "external_shutdown"
					} else {
						next = "unproven"
					}
				}
			} else if e == errProcessWindow {
				next = "process_window"
			} else if e == errLeaseLoss {
				next = "lease_loss"
				stage = stageLease
			} else {
				unknown = true
			}
			if next != "none" {
				if cause == "none" {
					cause = next
				} else if cause != next {
					cause = "mixed"
				}
			}
			return true
		})
		if cause != "none" {
			kind = cause
			if unknown || cause == "mixed" {
				kind = "mixed_failure"
			}
		}
	}
	slog.Info("native_capture_end", "kind", kind, "cause", cause, "stage", string(stage), "started_at", started.UTC(), "ended_at", time.Now().UTC(), "duration_ms", time.Since(started).Milliseconds())
}
