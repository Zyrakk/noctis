package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// authMiddleware validates the X-API-Key header against the configured API key
// using constant-time comparison.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-API-Key")
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing X-API-Key header"})
			return
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(s.apiKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeJSON marshals v to JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
