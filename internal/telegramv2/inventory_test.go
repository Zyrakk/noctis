package telegramv2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

func TestInventoryRPCAllowlistAndBudget(t *testing.T) {
	called := 0
	next := telegram.InvokeFunc(func(context.Context, bin.Encoder, bin.Decoder) error { called++; return nil })
	invoke := inventoryMiddleware(4).Handle(next)
	for _, request := range []bin.Encoder{&tg.UpdatesGetStateRequest{}, &tg.UpdatesGetDifferenceRequest{}, &tg.UpdatesGetChannelDifferenceRequest{}, &tg.MessagesGetHistoryRequest{}, &tg.ChannelsJoinChannelRequest{}, &tg.MessagesSendMessageRequest{}, &tg.AuthSendCodeRequest{}, &tg.AuthLogOutRequest{}} {
		if err := invoke(context.Background(), request, nil); err == nil {
			t.Fatalf("forbidden %T allowed", request)
		}
	}
	if called != 0 {
		t.Fatal("forbidden request reached transport")
	}
	for _, request := range []bin.Encoder{&tg.HelpGetConfigRequest{}, &tg.UsersGetUsersRequest{}, &tg.ContactsResolveUsernameRequest{}, &tg.MessagesGetDialogsRequest{}} {
		if err := invoke(context.Background(), request, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := invoke(context.Background(), &tg.MessagesGetDialogsRequest{}, nil); err == nil || called != 4 {
		t.Fatal("RPC quota not enforced")
	}
}

type inventoryFixture struct {
	calls int
	err   error
	pages []tg.MessagesDialogsClass
}

func (f *inventoryFixture) ContactsResolveUsername(context.Context, *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error) {
	return nil, f.err
}
func (f *inventoryFixture) MessagesGetDialogs(context.Context, *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
	f.calls++
	if len(f.pages) > 0 {
		page := f.pages[0]
		f.pages = f.pages[1:]
		return page, f.err
	}
	return &tg.MessagesDialogs{}, f.err
}

func TestInventoryDialogCursorUsesPeerAndMessageID(t *testing.T) {
	f := &inventoryFixture{}
	for page := 0; page < 2; page++ {
		var dialogs []tg.DialogClass
		for n := 1; n <= 100; n++ {
			dialogs = append(dialogs, &tg.Dialog{Peer: &tg.PeerChat{ChatID: int64(page*100 + n)}, TopMessage: 1})
		}
		f.pages = append(f.pages, &tg.MessagesDialogsSlice{Dialogs: dialogs, Messages: []tg.MessageClass{&tg.Message{ID: 1, PeerID: &tg.PeerChat{ChatID: int64(page*100 + 100)}, Date: 100 - page}}})
	}
	seen := 0
	if err := (&Inventory{Account: "fixture", RPC: f}).WalkDialogs(context.Background(), 3, func(DialogCandidate) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 200 || f.calls != 4 {
		t.Fatal("dialogs sharing message IDs must remain distinct", seen, f.calls)
	}
}

func TestInventoryHasNoPersistenceAndErrorsDoNotPauseAccount(t *testing.T) {
	// The fixture implements only two read RPCs; Inventory has no database Store,
	// owner lease, state, observations or policy dependency, including on failure.
	f := &inventoryFixture{}
	i := &Inventory{Account: "test", RPC: f}
	if err := i.WalkDialogs(context.Background(), 2, func(DialogCandidate) error { t.Fatal("unexpected dialog"); return nil }); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Fatal("active/archive folders not traversed")
	}
	f.err = errors.New("FLOOD_WAIT_10")
	if _, err := i.Resolve(context.Background(), "alias"); !errors.Is(err, f.err) {
		t.Fatal("RPC error masked")
	}
	if err := i.WalkDialogs(context.Background(), 2, func(DialogCandidate) error { return nil }); !errors.Is(err, f.err) {
		t.Fatal("RPC error masked")
	}
}

func TestInventoryCanceledSessionRemainsByteIdenticalAndNoLogin(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.json")
	loader := session.Loader{Storage: &ProtectedSession{Path: path}}
	if err := loader.Save(context.Background(), &session.Data{DC: 2, Addr: "127.0.0.1:1", AuthKey: make([]byte, 256)}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunInventory(ctx, ClientConfig{APIID: 1, APIHash: "synthetic", SessionFile: path}, func(context.Context, *Inventory) error { t.Fatal("canceled inventory started action"); return nil }); err == nil {
		t.Fatal("canceled inventory succeeded")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("inventory changed session")
	}
	if err := RunInventory(ctx, ClientConfig{Authenticate: true}, nil); err == nil {
		t.Fatal("inventory accepted authentication")
	}
}
