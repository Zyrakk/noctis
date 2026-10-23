package intelligence

import (
	"github.com/Zyrakk/noctis/internal/evidence"
	"testing"
)

func TestWalletChecksumsAndUnsupportedChains(t *testing.T) {
	for _, v := range []string{"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"} {
		if !bitcoinBase58(v) {
			t.Fatal("valid BTC rejected", v)
		}
	}
	for _, v := range []string{"1BoatSLRHtKNngkdXEeobR76b53LETtpyU", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz"} {
		if bitcoinBase58(v) {
			t.Fatal("bad checksum accepted", v)
		}
	}
	// BIP173/BIP350 witness examples, including a checksum-invalid mutation.
	if !bitcoinSegwit("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh") {
		t.Fatal("valid bech32 address rejected")
	}
	if bitcoinSegwit("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlj") {
		t.Fatal("bad bech32 checksum accepted")
	}
	text := []byte("BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT ETH 0x52908400098527886E0F7030069857D2E4169EE7")
	refs := evidence.Ref{ObservationID: "obs", Revision: "r", Hash: "h", Representation: "text"}
	out, e := Extract(text, refs)
	if e != nil {
		t.Fatal(e)
	}
	supported, unsupported := false, false
	for _, o := range out {
		if o.Type == "wallet" {
			supported = o.Validation == "checksum_valid"
		}
		if o.Type == "wallet_unsupported" {
			unsupported = o.Validation == "unsupported_checksum"
		}
		if e = o.Evidence.Validate(text); e != nil {
			t.Fatal(e)
		}
	}
	if !supported || !unsupported {
		t.Fatal("wallet capability distinction missing", out)
	}
}
