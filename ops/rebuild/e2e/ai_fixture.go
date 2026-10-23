package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func setupAIFixture(ctx context.Context, dir, binary, secret, cert, key, origin string, restart func() error) ([]string, []string, func(), error) {
	master := filepath.Join(dir, "ai-master.json")
	if e := os.WriteFile(master, []byte(`{"key_id":"synthetic-e2e","key":"`+strings.Repeat("ad", 32)+`"}`), 0600); e != nil {
		return nil, nil, nil, e
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, nil, nil, e
	}
	var mu sync.Mutex
	calls := []map[string]string{}
	gateway := func(route string) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer synthetic-private-api-key" {
				w.WriteHeader(401)
				return
			}
			var body struct {
				Model    string `json:"model"`
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Messages) != 2 {
				w.WriteHeader(400)
				return
			}
			var snap inference.Snapshot
			if json.Unmarshal([]byte(body.Messages[1].Content), &snap) != nil {
				w.WriteHeader(400)
				return
			}
			kind := "case.summarize"
			if route == "A" {
				kind = "evidence.translate"
			}
			result := inference.Result{SchemaVersion: "1", Kind: kind, Text: "Resultado sintético de ruta " + route + " y modelo " + body.Model, Labels: []string{"unknown"}, Intent: "unknown", Claims: []inference.Claim{}, Entities: []inference.Entity{}, Roles: []inference.Role{}, Refs: []evidence.Ref{}, Limitations: []string{"SYNTHETIC; sin calidad humana evaluada"}}
			for _, d := range snap.Documents {
				result.Refs = append(result.Refs, d.Ref)
			}
			mu.Lock()
			calls = append(calls, map[string]string{"route": route, "model": body.Model})
			mu.Unlock()
			raw, _ := json.Marshal(result)
			json.NewEncoder(w).Encode(map[string]any{"model": body.Model, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20}, "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(raw)}}}})
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		srv.StartTLS()
		return srv
	}
	a, b := gateway("A"), gateway("B")
	ua, _ := url.Parse(a.URL)
	ub, _ := url.Parse(b.URL)
	extra := []string{"--ai-master-key-file", master, "--ai-ca-file", cert, "--ai-local-authority", ua.Host + "," + ub.Host}
	workerLog, e := os.Create(filepath.Join(dir, "ai-worker.log"))
	if e != nil {
		a.Close()
		b.Close()
		return nil, nil, nil, e
	}
	args := append([]string{"v2", "--database-secret-file", secret, "serve", "--mode", "worker", "--automatic-inference=true"}, extra...)
	worker := exec.Command(binary, args...)
	worker.Stdout = workerLog
	worker.Stderr = workerLog
	if e = worker.Start(); e != nil {
		workerLog.Close()
		a.Close()
		b.Close()
		return nil, nil, nil, e
	}
	done := make(chan error, 1)
	go func() { done <- worker.Wait() }()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/calls" && r.Method == "GET":
			mu.Lock()
			defer mu.Unlock()
			json.NewEncoder(w).Encode(calls)
		case r.URL.Path == "/restart" && r.Method == "POST":
			if e := restart(); e != nil {
				http.Error(w, "restart failed", 500)
				return
			}
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			defer client.CloseIdleConnections()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				res, e := client.Get(origin + "/healthz")
				if e == nil {
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
					if res.StatusCode == 200 {
						w.WriteHeader(204)
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			http.Error(w, "restart readiness failed", 500)
		default:
			w.WriteHeader(404)
		}
	}))
	cleanup := func() {
		control.Close()
		worker.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			worker.Process.Kill()
			<-done
		}
		workerLog.Close()
		a.Close()
		b.Close()
	}
	if ctx.Err() != nil {
		cleanup()
		return nil, nil, nil, errors.New("fixture context expired")
	}
	return extra, []string{"NOCTIS_V2_AI_GATEWAY_A=" + a.URL, "NOCTIS_V2_AI_GATEWAY_B=" + b.URL, "NOCTIS_V2_AI_CONTROL=" + control.URL}, cleanup, nil
}
