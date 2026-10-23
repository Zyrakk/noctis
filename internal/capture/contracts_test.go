package capture

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"testing"
	"time"
)

func TestContractRoundTrip(t *testing.T) {
	b := Batch{Version: "1", SourceID: uuid.NewString(), Epoch: uuid.NewString(), Mode: Live, Expected: Checkpoint{0, json.RawMessage(`null`)}, Next: Checkpoint{1, json.RawMessage(`{"id":"9223372036854775807"}`)}, Items: []Item{{NativeID: "9223372036854775807", Revision: "1", Payload: []byte("España"), Representation: "utf8-v1", Hash: "hash", CollectedAt: time.Now().UTC()}}}
	b.BatchID = uuid.NewString()
	b.Items[0].Hash = fmt.Sprintf("sha256:%x", sha256.Sum256(b.Items[0].Payload))
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	var got Batch
	if e = json.Unmarshal(raw, &got); e != nil {
		t.Fatal(e)
	}
	if e = got.Validate(); e != nil {
		t.Fatal(e)
	}
	if got.Items[0].NativeID != b.Items[0].NativeID {
		t.Fatal("native id lost")
	}
	got.Items[0].Payload = []byte("changed")
	if got.Validate() == nil {
		t.Fatal("changed payload accepted")
	}
	got.Items[0].Payload = b.Items[0].Payload
	got.Next.Version = 9
	if got.Validate() == nil {
		t.Fatal("CAS accepted")
	}
}

func TestFixture(t *testing.T) {
	raw, e := os.ReadFile("../../testdata/contracts/v1/capture.json")
	if e != nil {
		t.Fatal(e)
	}
	var b Batch
	if e = json.Unmarshal(raw, &b); e != nil {
		t.Fatal(e)
	}
	if e = b.Validate(); e != nil {
		t.Fatal(e)
	}
}
