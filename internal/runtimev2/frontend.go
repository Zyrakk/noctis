package runtimev2

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/Zyrakk/noctis/internal/webassets"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

func frontendHandler() http.Handler {
	assets := webassets.FS()
	files := http.FileServer(http.FS(assets))
	landing, _ := fs.ReadFile(assets, "index.html")
	appPolicy := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
	policy := "default-src 'self'; script-src 'self'"
	for _, match := range regexp.MustCompile(`(?s)<script\b[^>]*>(.*?)</script>`).FindAllSubmatch(landing, -1) {
		digest := sha256.Sum256(match[1])
		policy += " 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	}
	policy += "; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://d2ol7oe51mr4n9.cloudfront.net; font-src 'self' https://fonts.gstatic.com; media-src https://d8j0ntlcm91z4.cloudfront.net; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", appPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if info, e := fs.Stat(assets, name); e == nil && !info.IsDir() && name != "index.html" && name != "app.html" {
			files.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || (strings.Contains(path.Base(name), ".") && name != "" && name != "." && name != "index.html" && name != "app.html") {
			http.NotFound(w, r)
			return
		}
		document := "app.html"
		if name == "" || name == "." || name == "index.html" {
			document = "index.html"
			w.Header().Set("Content-Security-Policy", policy)
		}
		raw, e := fs.ReadFile(assets, document)
		if e != nil {
			http.Error(w, "frontend unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if r.Method != "HEAD" {
			w.Write(raw)
		}
	})
}
