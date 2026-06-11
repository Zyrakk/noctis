package processor

import (
	"regexp"
	"strings"
	"unicode"
)

// Junk gate: rule-based pre-filter that runs before the LLM classifier.
// It marks obvious garbage (ultra-short fragments, symbol/emoji-only
// messages, bare @handles) as irrelevant without spending tokens, but
// rescues anything carrying an IOC: a naked leak URL or a bare C2 ip:port
// is intelligence, not junk. When in doubt, rescue — a false rescue costs
// one LLM call, a false junk loses intel.

// minLetterDigitRunes is the minimum number of letter/digit runes content
// needs to escape the junk gate without an IOC rescue. unicode.IsLetter
// counts all scripts, so Cyrillic/Persian/CJK text is not penalized.
const minLetterDigitRunes = 10

var (
	// A single bare @handle (the @ is optional) and nothing else.
	bareHandleRe = regexp.MustCompile(`^@?[A-Za-z0-9_]{3,32}$`)

	// IOC rescue patterns. Go regexp is RE2 (no lookarounds/backrefs):
	// URLs and emails are masked procedurally before the credential and
	// domain patterns run, instead of using lookarounds.
	ipv4Re       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?::[0-9]{1,5})?\b`)
	urlRe        = regexp.MustCompile(`(?i)\b(?:https?|hxxps?|ftp)://\S{4,}`)
	hashRe       = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)
	cveRe        = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	emailRe      = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
	walletRe     = regexp.MustCompile(`\b(?:bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b`)
	domainRe     = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	credentialRe = regexp.MustCompile(`[A-Za-z0-9._@-]{3,}:[^\s:]{4,}`)
)

// placeholderDomains are documentation/example domains that never count as IOCs.
var placeholderDomains = []string{"example.com", "example.org", "example.net"}

// placeholderCredentials are literal placeholder user:pass strings.
var placeholderCredentials = map[string]bool{
	"user:pass":         true,
	"user:password":     true,
	"username:password": true,
}

// mediaExtensions make bare file names ("photo.jpg") look like domains to
// domainRe; they are not IOCs. Executables/archives stay rescuable on purpose.
var mediaExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico",
	".mp4", ".avi", ".mov", ".webm", ".mp3",
}

func containsPlaceholderDomain(s string) bool {
	lower := strings.ToLower(s)
	for _, d := range placeholderDomains {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func isMediaFileName(s string) bool {
	lower := strings.ToLower(s)
	for _, ext := range mediaExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// hasIOCRescue reports whether content carries at least one IOC and must
// therefore never be junked.
func hasIOCRescue(content string) bool {
	if cveRe.MatchString(content) || hashRe.MatchString(content) ||
		ipv4Re.MatchString(content) || walletRe.MatchString(content) {
		return true
	}
	for _, u := range urlRe.FindAllString(content, -1) {
		if !containsPlaceholderDomain(u) {
			return true
		}
	}
	for _, m := range emailRe.FindAllString(content, -1) {
		if !containsPlaceholderDomain(m) {
			return true
		}
	}
	// Mask URLs and emails so scheme colons don't read as credentials and
	// their host parts don't re-match as domains.
	masked := emailRe.ReplaceAllString(urlRe.ReplaceAllString(content, " "), " ")
	for _, m := range credentialRe.FindAllString(masked, -1) {
		if !placeholderCredentials[strings.ToLower(m)] {
			return true
		}
	}
	for _, m := range domainRe.FindAllString(masked, -1) {
		if !containsPlaceholderDomain(m) && !isMediaFileName(m) {
			return true
		}
	}
	return false
}

// isJunk reports whether content is junk that should be marked irrelevant
// without an LLM call.
func isJunk(content string) bool {
	trimmed := strings.TrimSpace(content)

	letterDigits := 0
	for _, r := range trimmed {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			letterDigits++
		}
	}

	// letterDigits == 0 (symbol/emoji-only content) is the degenerate case
	// of the minimum-rune rule.
	junk := letterDigits < minLetterDigitRunes || bareHandleRe.MatchString(trimmed)
	if !junk {
		return false
	}
	return !hasIOCRescue(trimmed)
}
