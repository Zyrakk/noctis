package collector

import (
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// NewTorTransport creates an http.Transport routing through a SOCKS5 proxy.
// Returns an error if proxyAddr is empty.
func NewTorTransport(proxyAddr string, timeout time.Duration) (*http.Transport, error) {
	if proxyAddr == "" {
		return nil, errors.New("tor: SOCKS5 proxy address must not be empty")
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("tor: SOCKS5 dialer does not support DialContext")
	}

	return &http.Transport{
		DialContext: contextDialer.DialContext,
	}, nil
}
