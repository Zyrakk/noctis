package capture

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Fetcher has no ambient proxy. Local exceptions are exact server-administered authorities.
type Fetcher struct {
	AllowLocal                map[string]bool
	MaxCompressed, MaxDecoded int64
	Timeout                   time.Duration
	BeforeRequest             func(context.Context) error
	Tor                       *TorProfile
	lookupIP                  func(context.Context, string, string) ([]net.IP, error)
	dialContext               func(context.Context, string, string) (net.Conn, error)
}

// Tor is an explicit restricted egress profile, never an ambient proxy or a
// fallback. Only exact administrator-approved v3 onion authorities are routed.
type TorProfile struct {
	SOCKSAddress string
	Authorities  map[string]bool
}

func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "3ffe::/16", "3fff::/20", "64:ff9b::/96"} {
		if netip.MustParsePrefix(cidr).Contains(a) {
			return false
		}
	}
	return true
}
func (f Fetcher) Get(ctx context.Context, raw string) ([]byte, error) {
	return f.get(ctx, raw, nil)
}

// GetWithHeaders is for server-owned adapter credentials. Redirects are denied
// to keep those credentials on the configured authority.
func (f Fetcher) GetWithHeaders(ctx context.Context, raw string, headers http.Header) ([]byte, error) {
	for key := range headers {
		switch http.CanonicalHeaderKey(key) {
		case "Accept", "Key", "X-Apikey", "Apikey", "Authorization":
		default:
			return nil, errors.New("fetch credential header denied")
		}
	}
	return f.get(ctx, raw, headers)
}
func (f Fetcher) get(ctx context.Context, raw string, headers http.Header) ([]byte, error) {
	if f.MaxCompressed <= 0 {
		f.MaxCompressed = 2 << 20
	}
	if f.MaxDecoded <= 0 {
		f.MaxDecoded = 8 << 20
	}
	if f.Timeout <= 0 {
		f.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	current := raw
	for redirects := 0; redirects < 6; redirects++ {
		u, e := url.Parse(current)
		if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || strings.Contains(u.Hostname(), "%") {
			return nil, errors.New("fetch URL denied (Tor requires isolated transport)")
		}
		onion := strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion")
		if onion && (f.Tor == nil || f.Tor.SOCKSAddress == "" || !f.Tor.Authorities[u.Host] || len(u.Hostname()) != 62 || u.Port() != "" && u.Port() != "80" && u.Port() != "443") {
			return nil, errors.New("Tor authority denied")
		}
		if f.Tor != nil && !onion {
			return nil, errors.New("Tor profile forbids clearnet; direct fallback denied")
		}
		lookup := f.lookupIP
		if lookup == nil {
			lookup = net.DefaultResolver.LookupIP
		}
		var ips []net.IP
		if !onion {
			ips, e = lookup(ctx, "ip", u.Hostname())
		}
		if !onion && (e != nil || len(ips) == 0) {
			return nil, errors.New("fetch DNS failed")
		}
		for _, ip := range ips {
			if !publicIP(ip) && !f.AllowLocal[u.Host] {
				return nil, errors.New("fetch IP denied")
			}
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		target := net.JoinHostPort(u.Hostname(), port)
		if !onion {
			target = net.JoinHostPort(ips[0].String(), port)
		}
		tr := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if onion {
				d, e := proxy.SOCKS5("tcp", f.Tor.SOCKSAddress, nil, &net.Dialer{Timeout: 5 * time.Second})
				if e != nil {
					return nil, e
				}
				cd, ok := d.(proxy.ContextDialer)
				if !ok {
					return nil, errors.New("SOCKS context transport unavailable")
				}
				return cd.DialContext(ctx, "tcp", target)
			}
			if f.dialContext != nil {
				return f.dialContext(ctx, "tcp", target)
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
		}, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10}
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Accept-Encoding", "gzip")
		for key, values := range headers {
			req.Header[key] = append([]string(nil), values...)
		}
		if f.BeforeRequest != nil {
			if e = f.BeforeRequest(ctx); e != nil {
				tr.CloseIdleConnections()
				return nil, e
			}
		}
		res, e := client.Do(req)
		if e != nil {
			tr.CloseIdleConnections()
			return nil, e
		}
		if res.StatusCode >= 300 && res.StatusCode < 400 {
			location, e := res.Location()
			res.Body.Close()
			tr.CloseIdleConnections()
			if len(headers) > 0 {
				return nil, errors.New("credentialed fetch redirect denied")
			}
			if e != nil {
				return nil, e
			}
			current = location.String()
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			tr.CloseIdleConnections()
			return nil, fmt.Errorf("fetch HTTP %d", res.StatusCode)
		}
		compressed := &io.LimitedReader{R: res.Body, N: f.MaxCompressed + 1}
		var reader io.Reader = compressed
		var gz *gzip.Reader
		if res.Header.Get("Content-Encoding") == "gzip" {
			gz, e = gzip.NewReader(compressed)
			if e != nil {
				res.Body.Close()
				tr.CloseIdleConnections()
				return nil, e
			}
			reader = gz
		} else if res.Header.Get("Content-Encoding") != "" {
			res.Body.Close()
			tr.CloseIdleConnections()
			return nil, errors.New("unsupported encoding")
		}
		data, e := io.ReadAll(io.LimitReader(reader, f.MaxDecoded+1))
		if gz != nil {
			gz.Close()
		}
		res.Body.Close()
		tr.CloseIdleConnections()
		if e != nil {
			return nil, e
		}
		if compressed.N <= 0 || int64(len(data)) > f.MaxDecoded {
			return nil, errors.New("fetch size limit")
		}
		return data, nil
	}
	return nil, errors.New("fetch redirect limit")
}
