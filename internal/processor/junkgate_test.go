package processor

import "testing"

func TestIsJunk(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		// Multilingual content must not be penalized (unicode.IsLetter).
		{"russian text", "Продаётся доступ к сети крупной компании, цена договорная", false},
		{"persian text", "دسترسی به شبکه یک شرکت بزرگ برای فروش موجود است", false},
		{"chinese text", "出售某大型企业内网访问权限，价格面议", false},
		{"english text", "initial access offered for energy sector company", false},

		// Junk: too short, symbol-only, bare handles.
		{"emoji only", "🔥🔥💯😂👍", true},
		{"bare handle", "@darkseller99", true},
		{"bare handle without at", "some_handle", true},
		{"single dot", ".", true},
		{"empty", "", true},
		{"whitespace only", "   \n\t ", true},
		{"zero width only", "\u200b\u200d\ufeff", true},
		{"symbols only", "??!!...---", true},
		{"short latin fragment", "ok thx", true},
		{"short cyrillic fragment", "ок", true},
		{"placeholder credential is junk", "user:pass", true},
		{"bare media filename is junk", "photo.jpg", true},

		// IOC rescue: terse intel must never be junked.
		{"naked leak url", "https://anonfiles.com/abc12/corp_dump", false},
		{"short url rescued", "http://t.co/x1", false},
		{"terse ip port c2", "185.220.101.47:4444", false},
		{"short ip port rescued", "1.2.3.4:8080", false},
		{"bare ip rescued", "91.92.93.94", false},
		{"user pass line rescued", "bob:12345", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJunk(tt.content); got != tt.want {
				t.Errorf("isJunk(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestHasIOCRescue(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"ipv4", "45.155.205.99", true},
		{"ipv4 with port", "45.155.205.99:8443", true},
		{"not an ip (octets too large)", "999.999.999.999", false},
		{"url", "https://mega.nz/file/x1", true},
		{"defanged url", "hxxps://evil-site.ru/payload", true},
		{"domain", "evil-c2.ru", true},
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", true},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", true},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"cve", "CVE-2026-12345", true},
		{"cve id too short", "CVE-2026-123", false},
		{"email", "leaked@corp.ru", true},
		{"credential", "admin:s3cret99", true},
		{"btc wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", true},
		{"eth wallet", "0x52908400098527886E0F7030069857D2E4169EE7", true},
		{"executable filename rescues (conservative)", "stealer.exe", true},
		{"plain text no ioc", "hello world nothing here", false},

		// Placeholder rejection.
		{"placeholder domain", "example.com", false},
		{"placeholder url", "http://example.com/login", false},
		{"placeholder email", "test@example.com", false},
		{"placeholder credential", "user:pass", false},
		{"media filename not a domain", "photo.jpg", false},

		// Masking: without it, the credential pattern would match
		// "https://example.com/a" (scheme colon + path) and falsely rescue
		// a placeholder URL.
		{"masked placeholder url with colon path", "see https://example.com/a:bcde ok", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasIOCRescue(tt.content); got != tt.want {
				t.Errorf("hasIOCRescue(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}
