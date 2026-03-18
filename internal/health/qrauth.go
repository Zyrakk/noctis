package health

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// QRAuthState holds the current Telegram QR auth state, shared between the
// collector (writer) and the health server (reader).
type QRAuthState struct {
	mu        sync.RWMutex
	tokenURL  string
	expiresAt time.Time
	status    qrAuthStatus
}

type qrAuthStatus int

const (
	qrAuthIdle    qrAuthStatus = iota // no auth in progress
	qrAuthPending                     // QR token active, waiting for scan
	qrAuthSuccess                     // auth completed
)

// SetToken updates the current QR login token URL.
func (s *QRAuthState) SetToken(url string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenURL = url
	s.expiresAt = expiresAt
	s.status = qrAuthPending
}

// SetSuccess marks auth as completed.
func (s *QRAuthState) SetSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenURL = ""
	s.status = qrAuthSuccess
}

// Clear resets the state to idle.
func (s *QRAuthState) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenURL = ""
	s.status = qrAuthIdle
}

func (s *QRAuthState) snapshot() (string, time.Time, qrAuthStatus) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokenURL, s.expiresAt, s.status
}

// Handler returns an http.HandlerFunc that serves the QR auth page.
func (s *QRAuthState) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenURL, expiresAt, status := s.snapshot()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		switch status {
		case qrAuthIdle:
			fmt.Fprint(w, pageIdle)
			return
		case qrAuthSuccess:
			fmt.Fprint(w, pageSuccess)
			return
		}

		// Generate QR code PNG as base64 data URI.
		png, err := qrcode.Encode(tokenURL, qrcode.Medium, 300)
		if err != nil {
			http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
			return
		}
		b64 := base64.StdEncoding.EncodeToString(png)

		ttl := time.Until(expiresAt).Truncate(time.Second)
		if ttl < 0 {
			ttl = 0
		}

		fmt.Fprintf(w, pagePending, b64, tokenURL, tokenURL, ttl)
	}
}

const pageIdle = `<!DOCTYPE html>
<html><head><title>Noctis — Telegram Auth</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0}
.card{text-align:center;padding:2rem}</style></head>
<body><div class="card"><h2>No QR auth pending</h2><p>Telegram is either already authenticated or the collector is not running.</p><p style="color:#888">This page auto-refreshes every 5 seconds.</p></div></body></html>`

const pageSuccess = `<!DOCTYPE html>
<html><head><title>Noctis — Telegram Auth</title>
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0}
.card{text-align:center;padding:2rem} .ok{color:#4caf50;font-size:3rem}</style></head>
<body><div class="card"><div class="ok">&#10004;</div><h2>Authentication successful</h2><p>Telegram session is active. You can close this page.</p></div></body></html>`

const pagePending = `<!DOCTYPE html>
<html><head><title>Noctis — Telegram QR Login</title>
<meta http-equiv="refresh" content="10">
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0}
.card{text-align:center;padding:2rem;max-width:400px}
img{border-radius:12px;background:#fff;padding:12px}
a{color:#64b5f6;word-break:break-all}
.expires{color:#888;margin-top:1rem}</style></head>
<body><div class="card">
<h2>Scan with Telegram</h2>
<p>Open Telegram &rarr; Settings &rarr; Devices &rarr; Link Desktop Device</p>
<img src="data:image/png;base64,%s" alt="QR Code" width="300" height="300">
<p><a href="%s">%s</a></p>
<p class="expires">Expires in: %s</p>
<p style="color:#888">This page auto-refreshes every 10 seconds.</p>
</div></body></html>`
