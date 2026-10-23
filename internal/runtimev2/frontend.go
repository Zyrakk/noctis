package runtimev2

import (
	"github.com/Zyrakk/noctis/internal/webassets"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func frontendHandler() http.Handler {
	assets := webassets.FS()
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if _, e := fs.Stat(assets, name); e == nil && name != "" {
			files.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		raw, e := fs.ReadFile(assets, "index.html")
		if e != nil {
			http.Error(w, "frontend unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Write(raw)
	})
}
