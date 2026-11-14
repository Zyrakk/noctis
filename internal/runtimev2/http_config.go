package runtimev2

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/Zyrakk/noctis/internal/configv2"
	"golang.org/x/net/idna"
)

var originDNS = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true), idna.BidiRule())

// validateOrigin accepts the ASCII serialization sent by browsers, never a URL
// that needs normalization. Requests must still match this origin exactly.
func validateOrigin(origin string) error {
	invalid := func(reason string) error { return fmt.Errorf("canonical origin required: %s", reason) }
	for _, b := range []byte(origin) {
		if b <= ' ' || b >= 127 {
			return invalid("use ASCII/punycode without whitespace or control characters")
		}
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return invalid("expected http://host or https://host with an optional port")
	}
	if u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || strings.ContainsAny(origin, "?#") {
		return invalid("credentials, paths (including /), query and fragment are forbidden")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return invalid("IPv6 zones are forbidden")
		}
		host = addr.String()
		if addr.Is6() {
			// netip prints mapped addresses with dotted IPv4, whereas browsers
			// serialize all IPv6 components in hexadecimal.
			if addr.Is4In6() {
				b := addr.As16()
				host = fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
			}
			host = "[" + host + "]"
		}
	} else {
		ascii, err := originDNS.ToASCII(host)
		if err != nil || ascii == "" || strings.ContainsAny(host, ":[]") || endsInIPv4Number(host) {
			return invalid("host must be valid DNS/punycode, IPv4 or bracketed IPv6")
		}
		host = ascii
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return invalid("port must be an integer from 0 to 65535")
		}
		if (u.Scheme == "http" && n == 80) || (u.Scheme == "https" && n == 443) {
			return invalid("omit the default port (80 for HTTP, 443 for HTTPS)")
		}
		host += ":" + strconv.FormatUint(n, 10)
	}
	if origin != u.Scheme+"://"+host {
		return invalid("use lowercase scheme/host, canonical IP notation and a port without leading zeros")
	}
	return nil
}

// Browsers interpret DNS names ending in decimal/hex numbers as IPv4. Accept
// those hosts only through netip's strict canonical IPv4 parsing above.
func endsInIPv4Number(host string) bool {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	last, digits := labels[len(labels)-1], "0123456789"
	if strings.HasPrefix(last, "0x") {
		last, digits = last[2:], "0123456789abcdef"
	} else if last == "" {
		return false
	}
	return strings.Trim(last, digits) == ""
}

// loadAPITLS validates and loads once before DB access or binding a listener.
// A nil configuration deliberately serves internal HTTP behind a TLS proxy.
func loadAPITLS(cfg configv2.Config) (*tls.Config, error) {
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, fmt.Errorf("API TLS requires both certificate and private key files, or neither for internal HTTP")
	}
	if cfg.TLSCert == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("API TLS certificate/private key could not be loaded: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}}, nil
}
