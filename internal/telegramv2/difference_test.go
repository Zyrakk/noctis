package telegramv2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/gotd/td/tg"
	"github.com/jackc/pgx/v5"
)

type differenceRPC struct {
	RPC
	global  func(context.Context, *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error)
	channel func(context.Context, *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error)
}

func (r *differenceRPC) UpdatesGetDifference(ctx context.Context, req *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
	return r.global(ctx, req)
}
func (r *differenceRPC) UpdatesGetChannelDifference(ctx context.Context, req *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
	return r.channel(ctx, req)
}

func newDifferenceFixture(t *testing.T, mutate func(*CapturePolicy)) *budgetFixture {
	t.Helper()
	f := newBudgetFixture(t, mutate)
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET state='{"pts":10,"qts":0,"date":20,"seq":1}'`)
	for _, peer := range f.policy.Peers {
		f.exec(t, `INSERT INTO noctis_v2.telegram_channel_states(account_id,channel_id,pts) VALUES($1,$2,100)`, f.owner.Account, peer.ID)
	}
	return f
}

func differenceMessage(channel int64, id int) tg.MessageClass {
	return &tg.Message{ID: id, PeerID: &tg.PeerChannel{ChannelID: channel}, Date: 20, Message: "synthetic recovered message"}
}

func globalChannelGap(next int, channels ...int64) *tg.UpdatesDifference {
	d := &tg.UpdatesDifference{State: tg.UpdatesState{Pts: next, Date: 21, Seq: 2}}
	for _, channel := range channels {
		d.OtherUpdates = append(d.OtherUpdates, &tg.UpdateChannelTooLong{ChannelID: channel, Pts: 200})
	}
	return d
}

func assertDifferenceProgress(t *testing.T, f *budgetFixture, global, observations int, channels map[int64]int) {
	t.Helper()
	ctx := context.Background()
	state, err := f.State(ctx, f.owner.Account)
	wantState := State{Pts: global, Date: 21, Seq: 2}
	if global == 10 {
		wantState = State{Pts: 10, Date: 20, Seq: 1}
	}
	if err != nil || state != wantState {
		t.Fatalf("global state=%+v, want %+v: %v", state, wantState, err)
	}
	var count int
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&count); err != nil || count != observations {
		t.Fatalf("observations=%d, want %d: %v", count, observations, err)
	}
	for channel, want := range channels {
		var pts int
		if err = f.c.QueryRow(ctx, `SELECT pts FROM noctis_v2.telegram_channel_states WHERE account_id=$1 AND channel_id=$2`, f.owner.Account, channel).Scan(&pts); err != nil || pts != want {
			t.Fatalf("channel %d pts=%d, want %d: %v", channel, pts, want, err)
		}
	}
}

func TestDifferenceRecoversChannelBeforeGlobalPagePostgres(t *testing.T) {
	for _, sliced := range []bool{false, true} {
		name := "final"
		if sliced {
			name = "slice"
		}
		t.Run(name, func(t *testing.T) {
			f := newDifferenceFixture(t, nil)
			globalCalls, channelCalls := 0, 0
			rpc := &differenceRPC{}
			rpc.global = func(_ context.Context, req *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
				globalCalls++
				if req.Pts != 9+globalCalls {
					t.Fatal("global request did not use durable cursor", req.Pts)
				}
				d := globalChannelGap(req.Pts+1, 77, 77, 999, 999)
				d.NewMessages = []tg.MessageClass{differenceMessage(77, 500+globalCalls), differenceMessage(999, 900)}
				if sliced && globalCalls == 1 {
					return &tg.UpdatesDifferenceSlice{IntermediateState: d.State, OtherUpdates: d.OtherUpdates, NewMessages: d.NewMessages}, nil
				}
				return d, nil
			}
			rpc.channel = func(_ context.Context, req *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
				channelCalls++
				channel := req.Channel.(*tg.InputChannel)
				if channel.ChannelID != 77 || channel.AccessHash != 123 || req.Pts != 99+channelCalls {
					t.Fatal("wrong channel recovery request", req)
				}
				// The first global page remains uncommitted through both channel pages.
				wantGlobal, wantObservations := 10, channelCalls-1
				if globalCalls == 2 {
					wantGlobal, wantObservations = 11, 3
				}
				assertDifferenceProgress(t, f, wantGlobal, wantObservations, map[int64]int{77: req.Pts})
				return &tg.UpdatesChannelDifference{Pts: req.Pts + 1, Final: channelCalls != 1, NewMessages: []tg.MessageClass{differenceMessage(77, channelCalls)}}, nil
			}
			co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
			if err := co.Difference(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantGlobal, wantChannel := 1, 2
			if sliced {
				wantGlobal, wantChannel = 2, 3
			}
			if globalCalls != wantGlobal || channelCalls != wantChannel {
				t.Fatal("duplicate or missing recovery", globalCalls, channelCalls)
			}
			assertDifferenceProgress(t, f, 10+wantGlobal, wantGlobal+wantChannel, map[int64]int{77: 100 + wantChannel})
			var excludedPayload int
			if err := f.c.QueryRow(context.Background(), `SELECT count(*) FROM noctis_v2.telegram_inbox WHERE peer_id=999 AND disposition='captured'`).Scan(&excludedPayload); err != nil || excludedPayload != 0 {
				t.Fatal("excluded content materialized", excludedPayload, err)
			}
		})
	}
}

func TestDifferenceFailureRetainsChannelProgressPostgres(t *testing.T) {
	for _, failure := range []string{"rpc", "cancellation", "budget", "page_limit"} {
		t.Run(failure, func(t *testing.T) {
			f := newDifferenceFixture(t, func(p *CapturePolicy) {
				if failure == "budget" {
					p.Global.API = 2 // Global response and the first durable channel page.
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, retry := 0, false
			syntheticErr := errors.New("synthetic channel RPC failure")
			rpc := &differenceRPC{global: func(_ context.Context, req *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
				if req.Pts != 10 {
					t.Fatal("failed page advanced global cursor", req.Pts)
				}
				return globalChannelGap(11, 77), nil
			}}
			rpc.channel = func(ioCtx context.Context, req *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
				calls++
				if retry {
					want := 101
					if failure == "page_limit" {
						want = 200
					}
					if req.Pts != want {
						t.Fatal("retry ignored durable channel progress", req.Pts, want)
					}
					// Replay page-one content alongside a new message: only the latter is new.
					return &tg.UpdatesChannelDifference{Pts: req.Pts + 1, Final: true, NewMessages: []tg.MessageClass{differenceMessage(77, 1), differenceMessage(77, 2)}}, nil
				}
				if calls == 2 && failure != "page_limit" {
					if failure == "cancellation" {
						cancel()
						return nil, ioCtx.Err()
					}
					return nil, syntheticErr
				}
				return &tg.UpdatesChannelDifference{Pts: req.Pts + 1, Final: false, NewMessages: []tg.MessageClass{differenceMessage(77, 1)}}, nil
			}
			co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
			err := co.Difference(ctx)
			if err == nil {
				t.Fatal("failure advanced global page")
			}
			wantPts, wantCalls := 101, 2
			switch failure {
			case "rpc":
				if !errors.Is(err, syntheticErr) {
					t.Fatal(err)
				}
			case "cancellation":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "budget":
				wantCalls = 1
				if !errors.Is(err, ErrBudget) {
					t.Fatal(err)
				}
			case "page_limit":
				wantPts, wantCalls = 200, 100
				if !strings.Contains(err.Error(), "channel difference page limit") {
					t.Fatal(err)
				}
			}
			if calls != wantCalls {
				t.Fatal("unexpected channel calls", calls, wantCalls)
			}
			assertDifferenceProgress(t, f, 10, 1, map[int64]int{77: wantPts})
			if failure != "budget" {
				retry = true
				if err = co.Difference(context.Background()); err != nil {
					t.Fatal("retry failed", err)
				}
				assertDifferenceProgress(t, f, 11, 2, map[int64]int{77: wantPts + 1})
			} else {
				if err = co.Difference(context.Background()); !errors.Is(err, ErrBudget) || calls != wantCalls {
					t.Fatal("exhausted retry invoked channel RPC", err, calls)
				}
				assertDifferenceProgress(t, f, 10, 1, map[int64]int{77: wantPts})
			}
		})
	}
}

func TestDifferenceSecondChannelFailureRetainsFirstPostgres(t *testing.T) {
	f := newDifferenceFixture(t, func(p *CapturePolicy) {
		p.Peers = append(p.Peers, CapturePeer{SourceID: uuid.NewString(), Type: "channel", ID: 88, LiveEpoch: uuid.NewString(), BootstrapEpoch: uuid.NewString()})
	})
	retry := false
	calls := map[int64]int{}
	syntheticErr := errors.New("second channel unavailable")
	rpc := &differenceRPC{global: func(_ context.Context, req *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
		if req.Pts != 10 {
			t.Fatal("partial recovery advanced global cursor", req.Pts)
		}
		return globalChannelGap(11, 77, 88, 77, 88), nil
	}}
	rpc.channel = func(_ context.Context, req *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
		id := req.Channel.(*tg.InputChannel).ChannelID
		calls[id]++
		if id == 88 && !retry {
			return nil, syntheticErr
		}
		want := 100
		if id == 77 && retry {
			want = 101
		}
		if req.Pts != want {
			t.Fatal("channel retry lost progress", id, req.Pts, want)
		}
		return &tg.UpdatesChannelDifference{Pts: 101, Final: true, NewMessages: []tg.MessageClass{differenceMessage(id, 1)}}, nil
	}
	co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
	if err := co.Difference(context.Background()); !errors.Is(err, syntheticErr) {
		t.Fatal(err)
	}
	assertDifferenceProgress(t, f, 10, 1, map[int64]int{77: 101, 88: 100})
	retry = true
	if err := co.Difference(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls[77] != 2 || calls[88] != 2 {
		t.Fatal("repeated marker caused extra recovery", calls)
	}
	assertDifferenceProgress(t, f, 11, 2, map[int64]int{77: 101, 88: 101})
}

func TestDifferencePreservesGlobalAuthorizationPostgres(t *testing.T) {
	for _, mutation := range []string{"revision", "policy", "revocation"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDifferenceFixture(t, nil)
			f.exec(t, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p2','[]')`)
			policyVersion := "p1"
			if mutation == "policy" {
				policyVersion = "p2"
			}
			changed := make(chan error, 1)
			channelCalls := 0
			rpc := &differenceRPC{global: func(context.Context, *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
				// Queue the real projection guard while the global RPC owns it.
				// The mutation wins before channel admission; its new authorization
				// must never replace the one under which the global response arrived.
				go func() {
					ctx := context.Background()
					c, err := pgx.Connect(ctx, f.DSN)
					if err != nil {
						changed <- err
						return
					}
					defer c.Close(ctx)
					tx, err := c.Begin(ctx)
					if err == nil {
						defer tx.Rollback(ctx)
						err = intelligence.LockProjectionTx(ctx, tx)
					}
					if err == nil {
						_, err = tx.Exec(ctx, `UPDATE noctis_v2.sources SET policy_revision=policy_revision+1,enabled=$2,policy_version=$3 WHERE id=$1`, f.policy.Peers[0].SourceID, mutation != "revocation", policyVersion)
					}
					if err == nil {
						err = tx.Commit(ctx)
					}
					changed <- err
				}()
				waitNativeLock(t, f.c, "SELECT pg_advisory_xact_lock(76238451003)%")
				d := globalChannelGap(11, 77)
				d.NewMessages = []tg.MessageClass{differenceMessage(77, 9)}
				return d, nil
			}}
			rpc.channel = func(ioCtx context.Context, _ *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
				channelCalls++
				if got := authorizationFrom(ioCtx)[f.policy.Peers[0].SourceID]; got.PolicyRevision != 2 {
					t.Fatal("channel did not receive current authorization", got)
				}
				return &tg.UpdatesChannelDifference{Pts: 101, Final: true, NewMessages: []tg.MessageClass{differenceMessage(77, 1)}}, nil
			}
			co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
			if err := co.Difference(context.Background()); err == nil {
				t.Fatal("obsolete global authorization accepted")
			}
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			wantCalls, wantPts := 1, 101
			if mutation == "revocation" {
				wantCalls, wantPts = 0, 100
			}
			if channelCalls != wantCalls {
				t.Fatal("unexpected channel admission", channelCalls, wantCalls)
			}
			assertDifferenceProgress(t, f, 10, wantCalls, map[int64]int{77: wantPts})
		})
	}
}

func TestDifferenceRejectsStaleOwnerPostgres(t *testing.T) {
	for _, stale := range []string{"fence", "generation", "fence_during_channel"} {
		t.Run(stale, func(t *testing.T) {
			f := newDifferenceFixture(t, nil)
			globalCalls, channelCalls := 0, 0
			rpc := &differenceRPC{global: func(context.Context, *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
				globalCalls++
				return globalChannelGap(11, 77), nil
			}, channel: func(context.Context, *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
				channelCalls++
				f.exec(t, `UPDATE noctis_v2.telegram_accounts SET owner_fence=owner_fence+1`)
				return &tg.UpdatesChannelDifference{Pts: 101, Final: true, NewMessages: []tg.MessageClass{differenceMessage(77, 1)}}, nil
			}}
			co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
			switch stale {
			case "fence":
				co.Owner.Fence++
			case "generation":
				co.Owner.Generation = uuid.NewString()
			}
			if err := co.Difference(context.Background()); !errors.Is(err, ErrOwnership) {
				t.Fatal("stale owner not rejected", err)
			}
			want := 0
			if stale == "fence_during_channel" {
				want = 1
			}
			if globalCalls != want || channelCalls != want {
				t.Fatal("stale owner invoked RPC", globalCalls, channelCalls)
			}
			assertDifferenceProgress(t, f, 10, 0, map[int64]int{77: 100})
		})
	}
}
