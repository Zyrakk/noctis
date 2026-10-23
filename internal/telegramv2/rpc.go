package telegramv2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/jackc/pgx/v5"
)

// RPC is implemented by the actual pinned *tg.Client and protocol fixtures.
type RPC interface {
	UpdatesGetState(context.Context) (*tg.UpdatesState, error)
	UpdatesGetDifference(context.Context, *tg.UpdatesGetDifferenceRequest) (tg.UpdatesDifferenceClass, error)
	UpdatesGetChannelDifference(context.Context, *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error)
	MessagesGetHistory(context.Context, *tg.MessagesGetHistoryRequest) (tg.MessagesMessagesClass, error)
	MessagesGetDialogs(context.Context, *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error)
	ContactsResolveUsername(context.Context, *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error)
}

var _ RPC = (*tg.Client)(nil)

type Coordinator struct {
	Store              Store
	Owner              Owner
	RPC                RPC
	mu                 sync.Mutex
	authenticationOnly bool
}

var ErrCaptureDisabled = errors.New("native capture disabled during explicit authentication")

func state(s tg.UpdatesState) State { return State{Pts: s.Pts, Qts: s.Qts, Date: s.Date, Seq: s.Seq} }
func peer(p tg.PeerClass) Peer {
	switch p := p.(type) {
	case *tg.PeerUser:
		return Peer{Type: "user", ID: p.UserID}
	case *tg.PeerChat:
		return Peer{Type: "chat", ID: p.ChatID}
	case *tg.PeerChannel:
		return Peer{Type: "channel", ID: p.ChannelID}
	default:
		return Peer{Type: "unknown"}
	}
}
func messageEvent(m tg.MessageClass, kind string, pts, count int) (Event, bool) {
	switch m := m.(type) {
	case *tg.Message:
		published := time.Unix(int64(m.Date), 0).UTC()
		// Edits with identical text remain distinct if Telegram edit_date changes.
		revision := fmt.Sprintf("%d:%d:%x", m.Date, m.EditDate, sha256.Sum256([]byte(m.Message)))
		return Event{Peer: peer(m.PeerID), MessageID: m.ID, Revision: revision, Kind: kind, Pts: pts, PtsCount: count, PublishedAt: &published, Text: func() ([]byte, error) { return []byte(m.Message), nil }, Metadata: func() (json.RawMessage, error) {
			return json.Marshal(map[string]any{"forward": m.FwdFrom, "author": m.FromID, "edit_date": m.EditDate})
		}}, true
	case *tg.MessageService:
		published := time.Unix(int64(m.Date), 0).UTC()
		return Event{Peer: peer(m.PeerID), MessageID: m.ID, Revision: fmt.Sprintf("service:%d:%d", m.Date, pts), Kind: "service", Pts: pts, PtsCount: count, PublishedAt: &published, Text: func() ([]byte, error) { return []byte("[Telegram service message; no text]"), nil }}, true
	default:
		return Event{}, false
	}
}
func events(updates []tg.UpdateClass) ([]Event, error) {
	out := []Event{}
	for _, u := range updates {
		var m tg.MessageClass
		var pts, count int
		kind := "message"
		switch u := u.(type) {
		case *tg.UpdateNewMessage:
			m = u.Message
			pts = u.Pts
			count = u.PtsCount
		case *tg.UpdateNewChannelMessage:
			m = u.Message
			pts = u.Pts
			count = u.PtsCount
		case *tg.UpdateEditMessage:
			m = u.Message
			pts = u.Pts
			count = u.PtsCount
			kind = "edit"
		case *tg.UpdateEditChannelMessage:
			m = u.Message
			pts = u.Pts
			count = u.PtsCount
			kind = "edit"
		case *tg.UpdateDeleteChannelMessages:
			for i, id := range u.Messages {
				n := 0
				if i == 0 {
					n = u.PtsCount
				}
				out = append(out, Event{Peer: Peer{Type: "channel", ID: u.ChannelID}, MessageID: id, Revision: fmt.Sprintf("delete:%d", u.Pts), Kind: "delete", Pts: u.Pts, PtsCount: n})
			}
			continue
		case *tg.UpdateDeleteMessages:
			// Account-wide delete IDs have no peer. Resolve only existing allowed inbox entries.
			for i, id := range u.Messages {
				n := 0
				if i == 0 {
					n = u.PtsCount
				}
				out = append(out, Event{Peer: Peer{Type: "unknown"}, MessageID: id, Revision: fmt.Sprintf("delete:%d", u.Pts), Kind: "delete", Pts: u.Pts, PtsCount: n})
			}
			continue
		case *tg.UpdateChannelTooLong:
			out = append(out, Event{Peer: Peer{Type: "channel", ID: u.ChannelID}, MessageID: 1, Revision: fmt.Sprintf("channel_gap:%d", u.Pts), Kind: "protocol_disposition"})
			continue
		default:
			p := 0
			n := 0
			q := 0
			if v, ok := u.(interface{ GetPts() int }); ok {
				p = v.GetPts()
			}
			if v, ok := u.(interface{ GetPtsCount() int }); ok {
				n = v.GetPtsCount()
			}
			if v, ok := u.(interface{ GetQts() int }); ok {
				q = v.GetQts()
			}
			if p > 0 || q > 0 {
				out = append(out, Event{Peer: Peer{Type: "unknown"}, MessageID: 1, Revision: fmt.Sprintf("%T:%d:%d", u, p, q), Kind: "protocol_disposition", Pts: p, PtsCount: n, Qts: q})
			}
			continue
		}
		if e, ok := messageEvent(m, kind, pts, count); ok {
			out = append(out, e)
		} else {
			return nil, errors.New("unsupported message constructor requires difference")
		}
	}
	return out, nil
}
func (c *Coordinator) failure(ctx context.Context, e error) error {
	if d, ok := tgerr.AsFloodWait(e); ok {
		at := time.Now().UTC().Add(d)
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer done()
		return errors.Join(e, c.Store.Pause(cleanup, c.Owner, "flood_wait", &at))
	}
	if tgerr.Is(e, "AUTH_KEY_UNREGISTERED", "AUTH_KEY_DUPLICATED", "SESSION_REVOKED", "USER_DEACTIVATED") {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer done()
		return errors.Join(e, c.Store.Pause(cleanup, c.Owner, "revoked", nil))
	}
	return e
}

func (c *Coordinator) Handle(ctx context.Context, u tg.UpdatesClass) error {
	if c.authenticationOnly {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expected, e := c.Store.State(ctx, c.Owner.Account)
	if e != nil {
		return e
	}
	next := expected
	var list []tg.UpdateClass
	seqStart, seq := 0, 0
	date := 0
	switch u := u.(type) {
	case *tg.Updates:
		list = u.Updates
		seq = u.Seq
		seqStart = seq
		date = u.Date
	case *tg.UpdatesCombined:
		list = u.Updates
		seqStart = u.SeqStart
		seq = u.Seq
		date = u.Date
	case *tg.UpdateShort:
		list = []tg.UpdateClass{u.Update}
		date = u.Date
	case *tg.UpdateShortMessage:
		m := &tg.Message{ID: u.ID, PeerID: &tg.PeerUser{UserID: u.UserID}, Date: u.Date, Message: u.Message, FwdFrom: u.FwdFrom}
		list = []tg.UpdateClass{&tg.UpdateNewMessage{Message: m, Pts: u.Pts, PtsCount: u.PtsCount}}
		date = u.Date
	case *tg.UpdateShortChatMessage:
		m := &tg.Message{ID: u.ID, PeerID: &tg.PeerChat{ChatID: u.ChatID}, FromID: &tg.PeerUser{UserID: u.FromID}, Date: u.Date, Message: u.Message, FwdFrom: u.FwdFrom}
		list = []tg.UpdateClass{&tg.UpdateNewMessage{Message: m, Pts: u.Pts, PtsCount: u.PtsCount}}
		date = u.Date
	case *tg.UpdatesTooLong:
		return c.difference(ctx)
	default:
		return c.difference(ctx)
	}
	if seq > 0 {
		if seq <= expected.Seq {
			return nil
		}
		if seqStart != expected.Seq+1 {
			return c.difference(ctx)
		}
		next.Seq = seq
	}
	next.Date = max(next.Date, date)
	ev, e := events(list)
	if errors.Is(e, ErrGap) {
		return c.difference(ctx)
	}
	if e != nil {
		return e
	}
	for _, v := range ev {
		if v.Peer.Type == "channel" && v.Kind == "protocol_disposition" {
			if e = c.channelDifferenceByID(ctx, v.Peer.ID); e != nil {
				return e
			}
		}
	}
	for _, v := range ev {
		if v.Peer.Type != "channel" {
			next.Pts = max(next.Pts, v.Pts)
		}
		next.Qts = max(next.Qts, v.Qts)
	}
	_, e = c.Store.CommitUpdates(ctx, c.Owner, Envelope{BatchID: uuid.NewString(), Expected: expected, Next: next, Events: ev, Mode: capture.Live})
	if errors.Is(e, ErrGap) {
		for _, event := range ev {
			if event.Peer.Type == "channel" {
				if ce := c.channelDifferenceByID(ctx, event.Peer.ID); ce != nil {
					return ce
				}
			}
		}
		_, e = c.Store.CommitUpdates(ctx, c.Owner, Envelope{BatchID: uuid.NewString(), Expected: expected, Next: next, Events: ev, Mode: capture.Live})
		if e == nil {
			return nil
		}
		return c.difference(ctx)
	}
	return e
}

func (c *Coordinator) Difference(ctx context.Context) error {
	if c.authenticationOnly {
		return ErrCaptureDisabled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.difference(ctx)
}
func (c *Coordinator) difference(ctx context.Context) error {
	for pages := 0; pages < 100; pages++ {
		expected, e := c.Store.State(ctx, c.Owner.Account)
		if e != nil {
			return e
		}
		request := &tg.UpdatesGetDifferenceRequest{Pts: expected.Pts, Qts: expected.Qts, Date: expected.Date}
		request.SetPtsLimit(100)
		request.SetPtsTotalLimit(10000)
		phase := "live"
		if expected.Pts == 0 {
			phase = "bootstrap"
		}
		var diff tg.UpdatesDifferenceClass
		var admission SourceAuthorizations
		e = c.Store.guardAPI(ctx, c.Owner, phase, "", nil, nil, func(ioCtx context.Context) error {
			admission = authorizationFrom(ioCtx)
			var callErr error
			diff, callErr = c.RPC.UpdatesGetDifference(ioCtx, request)
			return callErr
		})
		if e != nil {
			return c.failure(ctx, e)
		}
		next := expected
		var messages []tg.MessageClass
		var updates []tg.UpdateClass
		final := true
		gap := false
		switch d := diff.(type) {
		case *tg.UpdatesDifference:
			messages = d.NewMessages
			updates = d.OtherUpdates
			next = state(d.State)
		case *tg.UpdatesDifferenceSlice:
			messages = d.NewMessages
			updates = d.OtherUpdates
			next = state(d.IntermediateState)
			final = false
		case *tg.UpdatesDifferenceEmpty:
			next.Date = max(next.Date, d.Date)
			next.Seq = max(next.Seq, d.Seq)
		case *tg.UpdatesDifferenceTooLong:
			next.Pts = d.Pts
			gap = true
		default:
			return errors.New("unsupported Telegram difference")
		}
		ev, e := events(updates)
		if errors.Is(e, ErrGap) {
			ev = nil
			gap = true
		} else if e != nil {
			return e
		}
		for _, m := range messages {
			if v, ok := messageEvent(m, "difference", 0, 0); ok {
				ev = append(ev, v)
			}
		}
		mode := capture.Live
		if expected.Pts == 0 || gap {
			mode = capture.Bootstrap
		}
		if _, e = c.Store.CommitUpdates(ctx, c.Owner, Envelope{BatchID: uuid.NewString(), Expected: expected, Next: next, Events: ev, Difference: true, Gap: gap, Mode: mode, Authorization: admission}); e != nil {
			return e
		}
		if final {
			return nil
		}
	}
	return errors.New("Telegram difference page limit; durable cursor retained")
}

// ChannelDifference requires an authorized input channel resolved for this auth generation.
func (c *Coordinator) ChannelDifference(ctx context.Context, channel *tg.InputChannel, pts int) error {
	if c.authenticationOnly {
		return ErrCaptureDisabled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.channelDifference(ctx, channel, pts)
}
func (c *Coordinator) channelDifferenceByID(ctx context.Context, id int64) error {
	db, e := pgx.Connect(ctx, c.Store.DSN)
	if e != nil {
		return e
	}
	defer db.Close(context.Background())
	var hash *int64
	var pts int
	e = db.QueryRow(ctx, `SELECT p.access_hash,COALESCE(cs.pts,0) FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id LEFT JOIN noctis_v2.telegram_channel_states cs ON cs.account_id=p.account_id AND cs.channel_id=p.peer_id WHERE p.account_id=$1 AND p.peer_type='channel' AND p.peer_id=$2 AND p.auth_generation=$3 AND p.allowed AND `+intelligence.SourceAuthorizedSQL+``, c.Owner.Account, id, c.Owner.Generation).Scan(&hash, &pts)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if hash == nil {
		return errors.New("authorized channel access hash unavailable for auth generation")
	}
	return c.channelDifference(ctx, &tg.InputChannel{ChannelID: id, AccessHash: *hash}, pts)
}
func (c *Coordinator) channelDifference(ctx context.Context, channel *tg.InputChannel, pts int) error {
	for pages := 0; pages < 100; pages++ {
		phase := "live"
		if pts == 0 {
			phase = "bootstrap"
		}
		var response tg.UpdatesChannelDifferenceClass
		var admission SourceAuthorizations
		e := c.Store.guardAPI(ctx, c.Owner, phase, "", &Peer{Type: "channel", ID: channel.ChannelID}, &channel.AccessHash, func(ioCtx context.Context) error {
			admission = authorizationFrom(ioCtx)
			var callErr error
			response, callErr = c.RPC.UpdatesGetChannelDifference(ioCtx, &tg.UpdatesGetChannelDifferenceRequest{Channel: channel, Filter: &tg.ChannelMessagesFilterEmpty{}, Pts: pts, Limit: 100})
			return callErr
		})
		if e != nil {
			return c.failure(ctx, e)
		}
		var messages []tg.MessageClass
		var updates []tg.UpdateClass
		nextPts := pts
		final := true
		gap := false
		switch d := response.(type) {
		case *tg.UpdatesChannelDifference:
			messages = d.NewMessages
			updates = d.OtherUpdates
			nextPts = d.Pts
			final = d.Final
		case *tg.UpdatesChannelDifferenceEmpty:
			nextPts = d.Pts
			final = d.Final
		case *tg.UpdatesChannelDifferenceTooLong:
			production, err := c.Store.productionCapture(ctx, c.Owner)
			if err != nil {
				return err
			}
			if production {
				return errors.New("production channel gap requires explicit intervention; historical snapshot excluded")
			}
			messages = d.Messages
			final = d.Final
			gap = true
			if v, ok := d.Dialog.(*tg.Dialog); ok {
				nextPts = v.Pts
			} else {
				return errors.New("channel difference dialog missing")
			}
		default:
			return errors.New("unsupported channel difference")
		}
		ev, e := events(updates)
		if e != nil {
			return e
		}
		for _, m := range messages {
			if v, ok := messageEvent(m, "channel_difference", 0, 0); ok {
				ev = append(ev, v)
			}
		}
		// A minimal protocol marker advances channel state even for an empty page.
		ev = append(ev, Event{Peer: Peer{Type: "channel", ID: channel.ChannelID}, MessageID: 1, Revision: fmt.Sprintf("channel_state:%d", nextPts), Kind: "protocol_disposition", Pts: nextPts, PtsCount: max(nextPts-pts, 0)})
		expected, e := c.Store.State(ctx, c.Owner.Account)
		if e != nil {
			return e
		}
		mode := capture.Live
		if gap || pts == 0 {
			mode = capture.Bootstrap
		}
		if _, e = c.Store.CommitUpdates(ctx, c.Owner, Envelope{BatchID: uuid.NewString(), Expected: expected, Next: expected, Events: ev, Difference: true, Gap: gap, Mode: mode, Authorization: admission}); e != nil {
			return e
		}
		pts = nextPts
		if final {
			return nil
		}
	}
	return errors.New("channel difference page limit")
}

// HistoryPage is deliberately bootstrap-only; its checkpoint never becomes pts.
func (c *Coordinator) HistoryPage(ctx context.Context, p tg.InputPeerClass, offset, limit int) (tg.MessagesMessagesClass, error) {
	if c.authenticationOnly {
		return nil, ErrCaptureDisabled
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("history limit 1..100")
	}
	target, hash, e := inputIdentity(p)
	if e != nil {
		return nil, e
	}
	var v tg.MessagesMessagesClass
	e = c.Store.guardAPI(ctx, c.Owner, "bootstrap", "", &target, hash, func(ioCtx context.Context) error {
		var callErr error
		v, callErr = c.RPC.MessagesGetHistory(ioCtx, &tg.MessagesGetHistoryRequest{Peer: p, OffsetID: offset, Limit: limit})
		return callErr
	})
	return v, c.failure(ctx, e)
}
func (c *Coordinator) DialogsPage(ctx context.Context, folder, offsetID, offsetDate int, offsetPeer tg.InputPeerClass) (tg.MessagesDialogsClass, error) {
	if c.authenticationOnly {
		return nil, ErrCaptureDisabled
	}
	if folder != 0 && folder != 1 {
		return nil, errors.New("folder must be active or archived")
	}
	req := &tg.MessagesGetDialogsRequest{OffsetID: offsetID, OffsetDate: offsetDate, OffsetPeer: offsetPeer, Limit: 100}
	req.SetFolderID(folder)
	var v tg.MessagesDialogsClass
	e := c.Store.guardAPI(ctx, c.Owner, "control", "", nil, nil, func(ioCtx context.Context) error {
		var callErr error
		v, callErr = c.RPC.MessagesGetDialogs(ioCtx, req)
		return callErr
	})
	return v, c.failure(ctx, e)
}
func (c *Coordinator) Resolve(ctx context.Context, username string) (*tg.ContactsResolvedPeer, error) {
	if len(username) < 1 || len(username) > 64 {
		return nil, errors.New("invalid Telegram alias")
	}
	return nil, errors.New("native resolve requires an explicit approved source; use read-only inventory for discovery")
}

// ResolveSource grants no membership: it resolves an already approved immutable
// source identity and binds the returned access hash to this authorization key.
func (c *Coordinator) ResolveSource(ctx context.Context, sourceID, username string) error {
	if c.authenticationOnly {
		return ErrCaptureDisabled
	}
	if len(username) < 1 || len(username) > 64 {
		return errors.New("invalid Telegram alias")
	}
	var resolved *tg.ContactsResolvedPeer
	var admission SourceAuthorizations
	e := c.Store.guardAPI(ctx, c.Owner, "control", sourceID, nil, nil, func(ioCtx context.Context) error {
		admission = authorizationFrom(ioCtx)
		var callErr error
		resolved, callErr = c.RPC.ContactsResolveUsername(ioCtx, &tg.ContactsResolveUsernameRequest{Username: username})
		return callErr
	})
	if e != nil {
		return c.failure(ctx, e)
	}
	p := peer(resolved.Peer)
	if p.Type == "unknown" {
		return errors.New("resolved peer type unsupported")
	}
	var access *int64
	for _, chat := range resolved.Chats {
		if v, ok := chat.(*tg.Channel); ok && v.ID == p.ID {
			hash := v.AccessHash
			access = &hash
		}
	}
	for _, user := range resolved.Users {
		if v, ok := user.(*tg.User); ok && v.ID == p.ID {
			hash := v.AccessHash
			access = &hash
		}
	}
	db, e := pgx.Connect(ctx, c.Store.DSN)
	if e != nil {
		return e
	}
	defer db.Close(context.Background())
	tx, e := db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	if e = validateAuthorization(ctx, tx, admission); e != nil {
		return e
	}
	var active bool
	if e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND auth_generation=$4 AND NOT closed AND status='running' AND lease_expires_at>clock_timestamp() FOR UPDATE`, c.Owner.Account, c.Owner.ID, c.Owner.Fence, c.Owner.Generation).Scan(&active); e != nil {
		return e
	}
	b, e := budgetTx(ctx, tx, c.Owner)
	if e != nil {
		return e
	}
	if e = b.active(ctx, tx); e != nil {
		return e
	}
	matched := false
	for _, v := range b.Policy.Peers {
		if v.SourceID == sourceID && v.Type == p.Type && v.ID == p.ID {
			if e = b.allowSource(ctx, tx, v, "control"); e != nil {
				return e
			}
			matched = true
		}
	}
	if !matched {
		return errors.New("resolved identity outside capture policy")
	}
	tag, e := tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,access_hash,allowed) SELECT $1,$2,$3::bigint,s.id,$5,$6,true FROM noctis_v2.sources s JOIN noctis_v2.telegram_accounts a ON a.id=$1 WHERE s.id=$4 AND s.kind='telegram' AND s.native_id=$1||':'||$2||':'||$3::bigint::text AND `+intelligence.SourceAuthorizedSQL+` AND a.owner=$7 AND a.owner_fence=$8 AND a.lease_expires_at>clock_timestamp() ON CONFLICT(account_id,peer_type,peer_id) DO UPDATE SET auth_generation=EXCLUDED.auth_generation,access_hash=EXCLUDED.access_hash,allowed=true WHERE noctis_v2.telegram_peers.source_id=EXCLUDED.source_id`, c.Owner.Account, p.Type, p.ID, sourceID, c.Owner.Generation, access, c.Owner.ID, c.Owner.Fence)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("resolved peer conflicts with enabled source identity or owner")
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (c *Coordinator) BackfillPage(ctx context.Context, sourceID string, limit int) (bool, error) {
	if c.authenticationOnly {
		return false, ErrCaptureDisabled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit < 1 || limit > 100 {
		return false, errors.New("history limit 1..100")
	}
	db, e := pgx.Connect(ctx, c.Store.DSN)
	if e != nil {
		return false, e
	}
	defer db.Close(context.Background())
	var kind, epoch string
	var id int64
	var access *int64
	var offset int
	var complete bool
	e = db.QueryRow(ctx, `SELECT p.peer_type,p.peer_id,p.access_hash,p.bootstrap_epoch::text,COALESCE(h.offset_id,0),COALESCE(h.complete,false) FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id LEFT JOIN noctis_v2.telegram_history_cursors h ON h.source_id=p.source_id AND h.epoch=p.bootstrap_epoch WHERE p.account_id=$1 AND p.source_id=$2 AND p.allowed AND `+intelligence.SourceAuthorizedSQL+` AND p.auth_generation=$3`, c.Owner.Account, sourceID, c.Owner.Generation).Scan(&kind, &id, &access, &epoch, &offset, &complete)
	if e != nil {
		return false, e
	}
	if complete {
		return true, nil
	}
	var input tg.InputPeerClass
	switch kind {
	case "chat":
		input = &tg.InputPeerChat{ChatID: id}
	case "user":
		if access == nil {
			return false, errors.New("history access hash missing")
		}
		input = &tg.InputPeerUser{UserID: id, AccessHash: *access}
	case "channel":
		if access == nil {
			return false, errors.New("history access hash missing")
		}
		input = &tg.InputPeerChannel{ChannelID: id, AccessHash: *access}
	default:
		return false, errors.New("history peer type unsupported")
	}
	var raw tg.MessagesMessagesClass
	var admission SourceAuthorizations
	e = c.Store.guardAPI(ctx, c.Owner, "bootstrap", sourceID, &Peer{Type: kind, ID: id}, access, func(ioCtx context.Context) error {
		admission = authorizationFrom(ioCtx)
		var authorized bool
		if e := db.QueryRow(ioCtx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1 AND p.source_id=$2 AND p.bootstrap_epoch=$3 AND p.allowed AND p.auth_generation=$4 AND `+intelligence.SourceAuthorizedSQL+`)`, c.Owner.Account, sourceID, epoch, c.Owner.Generation).Scan(&authorized); e != nil {
			return e
		}
		if !authorized {
			return errors.New("history source authorization changed")
		}
		var callErr error
		raw, callErr = c.RPC.MessagesGetHistory(ioCtx, &tg.MessagesGetHistoryRequest{Peer: input, OffsetID: offset, Limit: limit})
		return callErr
	})
	if e != nil {
		return false, c.failure(ctx, e)
	}
	page, ok := raw.AsModified()
	if !ok {
		return false, errors.New("history not-modified response unsupported without cache")
	}
	ev := []Event{}
	next := offset
	for _, m := range page.GetMessages() {
		v, ok := messageEvent(m, "history", 0, 0)
		if !ok {
			continue
		}
		if v.Peer.Type != kind || v.Peer.ID != id {
			return false, errors.New("history RPC peer mismatch")
		}
		if offset > 0 && v.MessageID >= offset {
			return false, errors.New("history cursor did not progress")
		}
		if next == 0 || v.MessageID < next {
			next = v.MessageID
		}
		ev = append(ev, v)
	}
	complete = len(page.GetMessages()) < limit
	if len(page.GetMessages()) > 0 && len(ev) == 0 {
		return false, errors.New("history page contains no supported message constructors")
	}
	current, e := c.Store.State(ctx, c.Owner.Account)
	if e != nil {
		return false, e
	}
	_, e = c.Store.CommitUpdates(ctx, c.Owner, Envelope{BatchID: uuid.NewString(), Expected: current, Next: current, Difference: true, Mode: capture.Bootstrap, Events: ev, Authorization: admission, History: &HistoryCursor{SourceID: sourceID, Epoch: epoch, Expected: offset, Next: next, Complete: complete}})
	return complete, e
}

func inputIdentity(p tg.InputPeerClass) (Peer, *int64, error) {
	switch v := p.(type) {
	case *tg.InputPeerChannel:
		return Peer{Type: "channel", ID: v.ChannelID}, &v.AccessHash, nil
	case *tg.InputPeerUser:
		return Peer{Type: "user", ID: v.UserID}, &v.AccessHash, nil
	case *tg.InputPeerChat:
		return Peer{Type: "chat", ID: v.ChatID}, nil, nil
	default:
		return Peer{}, nil, errors.New("native history requires explicit peer identity")
	}
}

type DialogCandidate struct {
	Account    string `json:"account_id"`
	Type       string `json:"peer_type"`
	ID         string `json:"native_id"`
	Folder     int    `json:"folder"`
	Name       string `json:"name"`
	AccessHash int64  `json:"-"`
	Pts        int    `json:"-"`
}

func inputForPeer(p tg.PeerClass, chats []tg.ChatClass, users []tg.UserClass) (tg.InputPeerClass, error) {
	switch p := p.(type) {
	case *tg.PeerChat:
		return &tg.InputPeerChat{ChatID: p.ChatID}, nil
	case *tg.PeerChannel:
		for _, chat := range chats {
			if v, ok := chat.(*tg.Channel); ok && v.ID == p.ChannelID {
				return &tg.InputPeerChannel{ChannelID: v.ID, AccessHash: v.AccessHash}, nil
			}
		}
	case *tg.PeerUser:
		for _, u := range users {
			if v, ok := u.(*tg.User); ok && v.ID == p.UserID {
				return &tg.InputPeerUser{UserID: v.ID, AccessHash: v.AccessHash}, nil
			}
		}
	}
	return nil, errors.New("dialog page lacks offset peer access hash")
}
func (c *Coordinator) WalkDialogs(ctx context.Context, maxPages int, emit func(DialogCandidate) error) error {
	return c.failure(ctx, walkDialogs(ctx, c.RPC, c.Owner.Account, maxPages, emit))
}

func walkDialogs(ctx context.Context, rpc InventoryRPC, account string, maxPages int, emit func(DialogCandidate) error) error {
	if maxPages < 1 || maxPages > 10000 {
		return errors.New("dialog page budget invalid")
	}
	seen := map[Peer]bool{}
	for _, folder := range []int{0, 1} {
		offsetID, offsetDate := 0, 0
		var previousPeer Peer
		var offsetPeer tg.InputPeerClass = &tg.InputPeerEmpty{}
		finished := false
		for pageIndex := 0; pageIndex < maxPages; pageIndex++ {
			req := &tg.MessagesGetDialogsRequest{OffsetID: offsetID, OffsetDate: offsetDate, OffsetPeer: offsetPeer, Limit: 100}
			req.SetFolderID(folder)
			req.SetExcludePinned(pageIndex > 0)
			raw, e := rpc.MessagesGetDialogs(ctx, req)
			if e != nil {
				return e
			}
			page, ok := raw.AsModified()
			if !ok {
				return errors.New("dialogs not-modified unsupported without cache")
			}
			dialogs := page.GetDialogs()
			if len(dialogs) == 0 {
				finished = true
				break
			}
			var last *tg.Dialog
			for _, d := range dialogs {
				v, ok := d.(*tg.Dialog)
				if !ok {
					continue
				}
				last = v
				p := peer(v.Peer)
				if p.Type == "unknown" || seen[p] {
					continue
				}
				seen[p] = true
				candidate := DialogCandidate{Account: account, Type: p.Type, ID: fmt.Sprint(p.ID), Folder: folder, Pts: v.Pts}
				for _, chat := range page.GetChats() {
					if v, ok := chat.(*tg.Channel); ok && p.Type == "channel" && v.ID == p.ID {
						candidate.Name = v.Title
						candidate.AccessHash = v.AccessHash
					}
				}
				if e = emit(candidate); e != nil {
					return e
				}
			}
			if len(dialogs) < 100 {
				finished = true
				break
			}
			if last == nil || (last.TopMessage == offsetID && peer(last.Peer) == previousPeer) {
				return errors.New("dialog cursor failed to progress")
			}
			offsetID = last.TopMessage
			previousPeer = peer(last.Peer)
			offsetPeer, e = inputForPeer(last.Peer, page.GetChats(), page.GetUsers())
			if e != nil {
				return e
			}
			foundDate := false
			for _, m := range page.GetMessages() {
				switch m := m.(type) {
				case *tg.Message:
					if m.ID == offsetID && peer(m.PeerID) == peer(last.Peer) {
						offsetDate = m.Date
						foundDate = true
					}
				case *tg.MessageService:
					if m.ID == offsetID && peer(m.PeerID) == peer(last.Peer) {
						offsetDate = m.Date
						foundDate = true
					}
				}
			}
			if !foundDate {
				return errors.New("dialog cursor lacks top message date")
			}
		}
		if !finished {
			return errors.New("dialog budget reached; inventory explicitly incomplete")
		}
	}
	return nil
}
