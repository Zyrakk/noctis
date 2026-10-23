package runtimev2

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/legacyimport"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/jackc/pgx/v5"
)

func TestManifestHistoryDryRunAndStatePreservationPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"alert"}]')`)
	must(e)
	native := "https://fixture.invalid/feed"
	m := legacyimport.SourceManifest{Version: "sources-manifest-v1", ManifestID: "inventory1", Sources: []legacyimport.ManifestSource{{Identity: "config:known", Kind: "rss", NativeID: &native, PolicyVersion: "p1", Provenance: []string{"synthetic:config"}, LegacyStatus: "enabled", Authorization: "approved", ResolutionStatus: "resolved", Disposition: "paused"}, {Identity: "config:unknown", Kind: "telegram", Provenance: []string{"synthetic:config"}, Authorization: "previously_configured", ResolutionStatus: "pending_verification", Disposition: "pending"}}}
	store := legacyimport.Store{DSN: dsn}
	r, e := store.ImportManifest(ctx, m, true)
	must(e)
	if r.Created != 1 || r.Unresolved != 1 {
		t.Fatal(r)
	}
	var n int
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.sources`).Scan(&n))
	if n != 0 {
		t.Fatal("dryrun mutated")
	}
	_, e = store.ImportManifest(ctx, m, false)
	must(e)
	_, e = store.ImportManifest(ctx, m, false)
	must(e)
	var source string
	must(c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.sources`).Scan(&source))
	_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false,policy_version='later-policy'`)
	must(e)
	m.ManifestID = "inventory2"
	m.Sources[0].Disposition = "enabled"
	_, e = store.ImportManifest(ctx, m, false)
	must(e)
	var enabled bool
	var policy string
	must(c.QueryRow(ctx, `SELECT enabled,policy_version FROM noctis_v2.sources`).Scan(&enabled, &policy))
	if enabled || policy != "later-policy" {
		t.Fatal("import overwrote later policy")
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET policy_version='p1'`)
	must(e)
	now := time.Now().UTC()
	batch := legacyimport.HistoryBatch{ImportedAt: now, SourceID: source, ArchiveDigest: "sha256:synthetic-archive", Table: "findings", Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`{"last_id":"9007199254740993123"}`)}, Records: []legacyimport.HistoryRecord{{SourceID: source, ArchiveDigest: "sha256:synthetic-archive", Table: "findings", LegacyID: "9007199254740993123", Text: "alert legacy allegation", LegacyJudgment: json.RawMessage(`{"confidence":1,"status":"confirmed"}`)}}}
	_, e = store.ImportHistory(ctx, batch, true)
	must(e)
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&n))
	if n != 0 {
		t.Fatal("history dryrun mutated")
	}
	first, e := store.ImportHistory(ctx, batch, false)
	must(e)
	again, e := store.ImportHistory(ctx, batch, false)
	must(e)
	if first.BatchID != again.BatchID {
		t.Fatal("history replay identity changed")
	}
	must((intelligence.Worker{DSN: dsn, Owner: "history"}).Once(ctx))
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.outbox`).Scan(&n))
	if n != 0 {
		t.Fatal("historical alert")
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.legacy_records WHERE legacy_id='9007199254740993123'`).Scan(&n))
	if n != 1 {
		t.Fatal("legacy ID precision lost")
	}
	batch.Records[0].Text = "changed historical row"
	if _, e = store.ImportHistory(ctx, batch, false); e == nil {
		t.Fatal("legacy overwrite accepted")
	}
}

func TestTelegramLeaseLossClosesBeforeTakeoverAndFloodWaitPersistsPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	for _, id := range []string{"lease", "flood", "revoked"} {
		if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES($1,$2)`, id, uuid.NewString()); e != nil {
			t.Fatal(e)
		}
	}
	store := telegramv2.Store{DSN: dsn}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- store.RunOwned(ctx, "lease", func(ctx context.Context, o telegramv2.Owner) error { close(started); <-ctx.Done(); return ctx.Err() })
	}()
	<-started
	if _, e = c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id='lease'`); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if !errors.Is(e, telegramv2.ErrOwnership) {
			t.Fatal("lease loss not reported", e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("lease loss did not cancel RPC Run")
	}
	var closed bool
	if e = c.QueryRow(ctx, `SELECT closed FROM noctis_v2.telegram_accounts WHERE id='lease'`).Scan(&closed); e != nil || !closed {
		t.Fatal("RPC closure receipt missing", e)
	}
	if _, e = store.Acquire(ctx, "lease", "replacement", time.Minute); e != nil {
		t.Fatal("closed run could not transfer owner", e)
	}
	for _, test := range []struct {
		account, message, status string
		code                     int
	}{{"flood", "FLOOD_WAIT_60", "flood_wait", 420}, {"revoked", "SESSION_REVOKED", "revoked", 401}} {
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('native-failure','[]') ON CONFLICT DO NOTHING`)
		if e != nil {
			t.Fatal(e)
		}
		source := uuid.NewString()
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch) VALUES($1,'telegram',$2,'native-failure',true,$3)`, source, test.account+":channel:77", uuid.NewString())
		if e != nil {
			t.Fatal(e)
		}
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,allowed) SELECT id,'channel',77,$2,auth_generation,true FROM noctis_v2.telegram_accounts WHERE id=$1`, test.account, source)
		if e != nil {
			t.Fatal(e)
		}
		provisionNativeBudget(t, dsn, c, test.account)
		e = store.RunOwned(ctx, test.account, func(ctx context.Context, o telegramv2.Owner) error {
			co := telegramv2.Coordinator{Store: store, Owner: o, RPC: &protocolFixture{difference: func(*tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
				return nil, tgerr.New(test.code, test.message)
			}}}
			return co.Difference(ctx)
		})
		if e == nil {
			t.Fatal("RPC failure hidden")
		}
		var status string
		var retryAt *time.Time
		if e = c.QueryRow(ctx, `SELECT status,retry_at,closed FROM noctis_v2.telegram_accounts WHERE id=$1`, test.account).Scan(&status, &retryAt, &closed); e != nil {
			t.Fatal(e)
		}
		if status != test.status || !closed {
			t.Fatal("pause/closure not durable", status, closed)
		}
		if test.status == "flood_wait" && (retryAt == nil || !retryAt.After(time.Now())) {
			t.Fatal("FloodWait retry missing")
		}
		if _, e = store.Acquire(ctx, test.account, "premature", time.Minute); !errors.Is(e, telegramv2.ErrOwnership) {
			t.Fatal("paused session resumed", e)
		}
	}
}

type protocolFixture struct {
	difference                              func(*tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error)
	channel                                 func(*tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error)
	historyCalls, dialogCalls, resolveCalls atomic.Int32
}

func (f *protocolFixture) UpdatesGetState(context.Context) (*tg.UpdatesState, error) {
	return &tg.UpdatesState{Pts: 10, Date: 100, Seq: 1}, nil
}
func (f *protocolFixture) UpdatesGetDifference(_ context.Context, r *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
	return f.difference(r)
}
func (f *protocolFixture) UpdatesGetChannelDifference(_ context.Context, r *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
	return f.channel(r)
}
func (f *protocolFixture) MessagesGetHistory(_ context.Context, r *tg.MessagesGetHistoryRequest) (tg.MessagesMessagesClass, error) {
	f.historyCalls.Add(1)
	return &tg.MessagesMessages{Messages: []tg.MessageClass{&tg.Message{ID: 9, PeerID: &tg.PeerChannel{ChannelID: 77}, Date: 100, Message: "synthetic archive"}}}, nil
}
func (f *protocolFixture) MessagesGetDialogs(_ context.Context, r *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
	f.dialogCalls.Add(1)
	return &tg.MessagesDialogs{Dialogs: []tg.DialogClass{&tg.Dialog{Peer: &tg.PeerChannel{ChannelID: 77}, TopMessage: 9}}}, nil
}
func (f *protocolFixture) ContactsResolveUsername(context.Context, *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error) {
	f.resolveCalls.Add(1)
	return &tg.ContactsResolvedPeer{Peer: &tg.PeerChannel{ChannelID: 77}, Chats: []tg.ChatClass{&tg.Channel{ID: 77, AccessHash: 123}}}, nil
}

func TestTelegramAtomicAllowlistNativeStateAndOwnershipPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	source, epoch, generation := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[]')`)
	must(e)
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch) VALUES($1,'telegram','acct:channel:77','p1',true,$2)`, source, epoch)
	must(e)
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation,state) VALUES('acct',$1,'{"pts":10,"qts":0,"date":100,"seq":1}')`, generation)
	must(e)
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,access_hash,allowed) VALUES('acct','channel',77,$1,$2,123,true)`, source, generation)
	must(e)
	store := telegramv2.Store{DSN: dsn}
	provisionNativeBudget(t, dsn, c, "acct")
	owner, e := store.Acquire(ctx, "acct", "owner1", time.Minute)
	must(e)
	if _, e = store.Acquire(ctx, "acct", "owner2", time.Minute); !errors.Is(e, telegramv2.ErrOwnership) {
		t.Fatal("second owner acquired", e)
	}
	old := telegramv2.State{Pts: 10, Date: 100, Seq: 1}
	next := old
	next.Pts = 11
	excludedCalled := false
	batch := telegramv2.Envelope{BatchID: uuid.NewString(), Expected: old, Next: next, Mode: capture.Live, Events: []telegramv2.Event{{Peer: telegramv2.Peer{Type: "user", ID: 999}, MessageID: 1, Revision: "1", Kind: "message", Pts: 11, PtsCount: 1, Text: func() ([]byte, error) { excludedCalled = true; return []byte("DO NOT SERIALIZE"), nil }}}}
	r, e := store.CommitUpdates(ctx, owner, batch)
	must(e)
	if excludedCalled || r.Excluded != 1 {
		t.Fatal("excluded payload inspected")
	}
	_, e = store.CommitUpdates(ctx, owner, batch)
	must(e)
	batch.Next.Pts = 12
	if _, e = store.CommitUpdates(ctx, owner, batch); !errors.Is(e, capture.ErrConflict) {
		t.Fatal("batch equivocation accepted", e)
	}
	var n int
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.content_blobs`).Scan(&n))
	if n != 0 {
		t.Fatal("excluded payload persisted")
	}
	// Fault after inbox/capture insertion must roll back native cursor and jobs.
	_, e = c.Exec(ctx, `CREATE FUNCTION noctis_v2.fail_native() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic native fault';END$$;CREATE TRIGGER native_fault BEFORE UPDATE OF state ON noctis_v2.telegram_accounts FOR EACH ROW EXECUTE FUNCTION noctis_v2.fail_native()`)
	must(e)
	b2 := telegramv2.Envelope{BatchID: uuid.NewString(), Expected: next, Next: next, Mode: capture.Live, Difference: true, Events: []telegramv2.Event{{Peer: telegramv2.Peer{Type: "channel", ID: 77}, MessageID: 50, Revision: "1", Kind: "message", Text: func() ([]byte, error) { return []byte("synthetic allowed"), nil }}}}
	if _, e = store.CommitUpdates(ctx, owner, b2); e == nil {
		t.Fatal("fault not injected")
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&n))
	if n != 0 {
		t.Fatal("capture escaped native rollback")
	}
	_, e = c.Exec(ctx, `DROP TRIGGER native_fault ON noctis_v2.telegram_accounts`)
	must(e)
	_, e = store.CommitUpdates(ctx, owner, b2)
	must(e)
	// Real native constructors, difference recovery and RPC parameter contract.
	fixture := &protocolFixture{difference: func(req *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error) {
		if req.Pts != 11 {
			t.Fatalf("wrong native pts %d", req.Pts)
		}
		return &tg.UpdatesDifference{State: tg.UpdatesState{Pts: 13, Date: 102, Seq: 3}, NewMessages: []tg.MessageClass{&tg.Message{ID: 51, PeerID: &tg.PeerChannel{ChannelID: 77}, Date: 102, Message: "synthetic difference message"}}}, nil
	}, channel: func(req *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
		return &tg.UpdatesChannelDifference{Pts: 21, Final: true, NewMessages: []tg.MessageClass{&tg.Message{ID: 52, PeerID: &tg.PeerChannel{ChannelID: 77}, Date: 103, Message: "synthetic channel difference"}}}, nil
	}}
	coordinator := &telegramv2.Coordinator{Store: store, Owner: owner, RPC: fixture}
	must(coordinator.Handle(ctx, &tg.Updates{Seq: 3, Date: 102})) // seq2 gap -> difference
	state, e := store.State(ctx, "acct")
	must(e)
	if state.Pts != 13 || state.Seq != 3 {
		t.Fatal("difference cursor lost", state)
	}
	must(coordinator.ChannelDifference(ctx, &tg.InputChannel{ChannelID: 77, AccessHash: 123}, 0))
	_, e = coordinator.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 77, AccessHash: 123}, 0, 100)
	must(e)
	for _, folder := range []int{0, 1} {
		_, e = coordinator.DialogsPage(ctx, folder, 0, 0, &tg.InputPeerEmpty{})
		must(e)
	}
	e = coordinator.ResolveSource(ctx, source, "synthetic_channel")
	must(e)
	if fixture.historyCalls.Load() != 1 || fixture.dialogCalls.Load() != 2 || fixture.resolveCalls.Load() != 1 {
		t.Fatal("RPC fixture not used")
	}
	complete, e := coordinator.BackfillPage(ctx, source, 100)
	must(e)
	if !complete {
		t.Fatal("bounded synthetic history not complete")
	}
	var historyEpoch string
	must(c.QueryRow(ctx, `SELECT epoch::text FROM noctis_v2.telegram_history_cursors WHERE source_id=$1`, source).Scan(&historyEpoch))
	if historyEpoch == epoch {
		t.Fatal("bootstrap reused live epoch")
	}
	must(coordinator.Handle(ctx, &tg.Updates{Seq: 4, Date: 104, Updates: []tg.UpdateClass{&tg.UpdateEditChannelMessage{Message: &tg.Message{ID: 50, PeerID: &tg.PeerChannel{ChannelID: 77}, Date: 100, EditDate: 104, Message: "synthetic edited text"}, Pts: 22, PtsCount: 1}}}))
	var superseded bool
	must(c.QueryRow(ctx, `SELECT superseded_by IS NOT NULL FROM noctis_v2.observations WHERE source_id=$1 AND native_id='50' AND revision='1'`, source).Scan(&superseded))
	if !superseded {
		t.Fatal("edit did not preserve supersession")
	}
	must(coordinator.Handle(ctx, &tg.Updates{Seq: 5, Date: 105, Updates: []tg.UpdateClass{&tg.UpdateDeleteChannelMessages{ChannelID: 77, Messages: []int{50}, Pts: 23, PtsCount: 1}}}))
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1 AND native_id='50' AND source_deleted`, source).Scan(&n))
	if n != 2 {
		t.Fatal("delete did not mark all revisions", n)
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id='acct'`)
	must(e)
	if _, e = store.Acquire(ctx, "acct", "expired-takeover", time.Minute); !errors.Is(e, telegramv2.ErrOwnership) {
		t.Fatal("lease expiry falsely proved transport closure")
	}
	b2.BatchID = uuid.NewString()
	if _, e = store.CommitUpdates(ctx, owner, b2); !errors.Is(e, telegramv2.ErrOwnership) {
		t.Fatal("stale owner published", e)
	}
}
