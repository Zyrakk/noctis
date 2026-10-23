package intelligence

import (
	"fmt"
	"github.com/Zyrakk/noctis/internal/evidence"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Observable struct {
	Type       string       `json:"type"`
	Value      string       `json:"value"`
	Original   string       `json:"original"`
	Evidence   evidence.Ref `json:"evidence"`
	Validation string       `json:"validation,omitempty"`
	Chain      string       `json:"chain,omitempty"`
}

var patterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"cve", regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)},
	{"hash", regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)},
	{"url", regexp.MustCompile(`(?i)\b(?:https?|hxxps?)://[^\s<>"']+`)},
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{"ip", regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|[0-9a-fA-F]*:[0-9a-fA-F:]+`)},
	{"domain", regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.|\[\.\]))+[a-z]{2,63}\b`)},
}

// Extract parses syntax only; no observable receives a maliciousness judgment.
func Extract(text []byte, ref evidence.Ref) ([]Observable, error) {
	if !utf8.Valid(text) {
		return nil, fmt.Errorf("invalid UTF-8 document")
	}
	out := []Observable{}
	for _, p := range patterns {
		for _, span := range p.re.FindAllIndex(text, -1) {
			original := string(text[span[0]:span[1]])
			value := strings.ReplaceAll(original, "[.]", ".")
			switch p.kind {
			case "ip":
				if net.ParseIP(value) == nil {
					continue
				}
				value = net.ParseIP(value).String()
			case "url":
				value = strings.Replace(value, "hxxp", "http", 1)
				u, e := url.Parse(value)
				if e != nil || u.Hostname() == "" {
					continue
				}
			case "cve":
				value = strings.ToUpper(value)
			case "domain", "email", "hash":
				value = strings.ToLower(value)
			}
			r := ref
			r.Start = span[0]
			r.End = span[1]
			if e := r.Validate(text); e != nil {
				return nil, e
			}
			out = append(out, Observable{Type: p.kind, Value: value, Original: original, Evidence: r})
		}
	}
	out = append(out, extractWallets(text, ref)...)
	return out, nil
}

type Term struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func Gate(text []byte, observables []Observable, terms []Term) string {
	for _, t := range terms {
		for _, o := range observables {
			if t.Type == o.Type && strings.EqualFold(t.Value, o.Value) {
				return "relevant"
			}
		}
		if t.Type == "keyword" && strings.Contains(strings.ToLower(string(text)), strings.ToLower(t.Value)) {
			return "relevant"
		}
	}
	return "unknown"
}
