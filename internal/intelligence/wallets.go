package intelligence

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"regexp"
	"strings"

	"github.com/Zyrakk/noctis/internal/evidence"
)

var walletPatterns = []struct {
	chain string
	re    *regexp.Regexp
}{
	{"bitcoin", regexp.MustCompile(`\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b`)},
	{"bitcoin_segwit", regexp.MustCompile(`(?i)\b(?:bc|tb)1[ac-hj-np-z02-9]{6,87}\b`)},
	{"ethereum", regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)},
}

func WalletCapabilities() map[string]string {
	return map[string]string{"bitcoin": "base58check_supported", "bitcoin_segwit": "bech32_bech32m_supported", "ethereum": "unsupported_checksum", "monero": "unsupported", "solana": "unsupported"}
}
func bitcoinBase58(value string) bool {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range value {
		i := strings.IndexRune(alphabet, c)
		if i < 0 {
			return false
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	decoded := n.Bytes()
	zeros := 0
	for _, c := range value {
		if c != '1' {
			break
		}
		zeros++
	}
	decoded = append(make([]byte, zeros), decoded...)
	if len(decoded) != 25 || (decoded[0] != 0 && decoded[0] != 5) {
		return false
	}
	first := sha256.Sum256(decoded[:21])
	second := sha256.Sum256(first[:])
	return bytes.Equal(decoded[21:], second[:4])
}
func bitcoinSegwit(value string) bool {
	if len(value) > 90 || value != strings.ToLower(value) && value != strings.ToUpper(value) {
		return false
	}
	value = strings.ToLower(value)
	sep := strings.LastIndexByte(value, '1')
	if sep < 1 || sep+7 > len(value) {
		return false
	}
	hrp := value[:sep]
	if hrp != "bc" && hrp != "tb" {
		return false
	}
	chars := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	data := []byte{}
	for _, r := range value[sep+1:] {
		i := strings.IndexRune(chars, r)
		if i < 0 {
			return false
		}
		data = append(data, byte(i))
	}
	expanded := []byte{}
	for _, r := range hrp {
		expanded = append(expanded, byte(r)>>5)
	}
	expanded = append(expanded, 0)
	for _, r := range hrp {
		expanded = append(expanded, byte(r)&31)
	}
	expanded = append(expanded, data...)
	check := uint32(1)
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range expanded {
		top := check >> 25
		check = (check&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generators {
			if top>>i&1 != 0 {
				check ^= g
			}
		}
	}
	if len(data) < 7 || data[0] > 16 {
		return false
	}
	if data[0] == 0 && check != 1 || data[0] > 0 && check != 0x2bc830a3 {
		return false
	}
	bits, acc, n := 0, uint32(0), 0
	for _, v := range data[1 : len(data)-6] {
		acc = acc<<5 | uint32(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			n++
		}
	}
	if bits >= 5 || acc<<uint(8-bits)&255 != 0 || n < 2 || n > 40 {
		return false
	}
	return data[0] != 0 || n == 20 || n == 32
}
func extractWallets(text []byte, ref evidence.Ref) []Observable {
	out := []Observable{}
	for _, p := range walletPatterns {
		for _, span := range p.re.FindAllIndex(text, -1) {
			value := string(text[span[0]:span[1]])
			kind, validation := "wallet", "checksum_valid"
			switch p.chain {
			case "bitcoin":
				if !bitcoinBase58(value) {
					continue
				}
			case "bitcoin_segwit":
				if !bitcoinSegwit(value) {
					continue
				}
				value = strings.ToLower(value)
			default:
				kind = "wallet_unsupported"
				validation = "unsupported_checksum"
			}
			r := ref
			r.Start = span[0]
			r.End = span[1]
			out = append(out, Observable{Type: kind, Value: value, Original: string(text[span[0]:span[1]]), Evidence: r, Validation: validation, Chain: p.chain})
		}
	}
	return out
}
