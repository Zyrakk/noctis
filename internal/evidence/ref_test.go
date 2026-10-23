package evidence

import "testing"

func TestUTF8ByteOffsets(t *testing.T) {
	r := Ref{ObservationID: "id", Revision: "1", Hash: "hash", Representation: "utf8-v1", Start: 1, End: 3}
	b := []byte("aéz")
	if e := r.Validate(b); e != nil {
		t.Fatal(e)
	}
	r.End = 2
	if r.Validate(b) == nil {
		t.Fatal("split UTF8 accepted")
	}
}
