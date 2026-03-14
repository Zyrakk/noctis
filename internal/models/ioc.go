package models

// IOC type constants identify the kind of indicator of compromise.
const (
	IOCTypeIP           = "ip"
	IOCTypeDomain       = "domain"
	IOCTypeHashMD5      = "hash_md5"
	IOCTypeHashSHA1     = "hash_sha1"
	IOCTypeHashSHA256   = "hash_sha256"
	IOCTypeEmail        = "email"
	IOCTypeCryptoWallet = "crypto_wallet"
	IOCTypeURL          = "url"
	IOCTypeCVE          = "cve"
)

// IOC is a single indicator of compromise extracted from a finding.
type IOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}
