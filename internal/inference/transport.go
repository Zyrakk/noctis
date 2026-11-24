package inference

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type GatewayError struct {
	Code       string
	Permanent  bool
	Uncertain  bool
	RetryAfter time.Duration
}

func (e *GatewayError) Error() string { return e.Code }

// TransportDiagnostic contains only a closed category; upstream error strings
// may contain endpoints, credentials or request material and are never retained.
type TransportDiagnostic struct {
	Gateway  *GatewayError
	Category string
}

func (e *TransportDiagnostic) Error() string { return e.Gateway.Code + ":" + e.Category }
func (e *TransportDiagnostic) Unwrap() error { return e.Gateway }
func transportDiagnostic(err error) error {
	category := "other"
	var timeout net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		category = "deadline"
	case errors.Is(err, context.Canceled):
		category = "cancel"
	case errors.As(err, &timeout) && timeout.Timeout():
		category = "transport_timeout"
	}
	return &TransportDiagnostic{&GatewayError{"upstream_uncertain", false, true, 0}, category}
}

type Usage struct {
	Input  int64 `json:"input_tokens"`
	Output int64 `json:"output_tokens"`
}
type GatewayResult struct {
	Result Result
	Model  string
	Usage  *Usage
}

func safeIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2002::/16", "3ffe::/16", "3fff::/20"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return !a.Is6() || netip.MustParsePrefix("2000::/3").Contains(a)
}
func (s Store) client(ctx context.Context, raw string) (*http.Client, func(), error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || strings.Contains(u.Hostname(), "%") || (u.Scheme != "https" && !(u.Scheme == "http" && s.AllowLocal[u.Host])) {
		return nil, nil, errors.New("endpoint denied")
	}
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if e != nil || len(ips) == 0 {
		return nil, nil, errors.New("endpoint DNS unavailable")
	}
	for _, ip := range ips {
		local := s.AllowLocal[u.Host] && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).Equal(ip)
		if !safeIP(ip) && !local {
			return nil, nil, errors.New("endpoint IP denied")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(ips[0].String(), port)
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if s.CAFile != "" {
		raw, e := os.ReadFile(s.CAFile)
		if e != nil {
			return nil, nil, errors.New("endpoint trust unavailable")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, nil, errors.New("endpoint trust invalid")
		}
		tc.RootCAs = roots
	}
	tr := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: tc, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	}, MaxResponseHeaderBytes: 64 << 10}
	// The request context bounds DNS, connection, headers and body together.
	// Mirror its remaining budget for headers; an earlier parent always wins.
	if deadline, ok := ctx.Deadline(); ok {
		tr.ResponseHeaderTimeout = max(time.Until(deadline), time.Nanosecond)
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr.CloseIdleConnections, nil
}

// resultSchema is also checked locally. Provider schema compliance conveys no truth.
func resultSchema() map[string]any {
	str := func() any { return map[string]any{"type": "string"} }
	arr := func(v any) any { return map[string]any{"type": "array", "items": v} }
	obj := func(p map[string]any) any {
		required := []string{}
		for k := range p {
			required = append(required, k)
		}
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	ref := obj(map[string]any{"observation_id": str(), "revision": str(), "hash": str(), "representation": str(), "start": map[string]any{"type": "integer"}, "end": map[string]any{"type": "integer"}})
	claim := obj(map[string]any{"subject": str(), "predicate": str(), "object": str(), "refs": arr(ref)})
	entity := obj(map[string]any{"kind": str(), "alias": str(), "scope": str(), "language": str(), "refs": arr(ref)})
	role := obj(map[string]any{"type": str(), "value": str(), "role": str(), "refs": arr(ref)})
	plan := obj(map[string]any{"version": str(), "entity": str(), "operation": str(), "mode": str(), "text": str(), "filters": obj(map[string]any{"source_id": str(), "case_id": str(), "kind": str()}), "cursor": str(), "limit": map[string]any{"type": "integer"}})
	nullable := func(v any) any { return map[string]any{"anyOf": []any{v, map[string]any{"type": "null"}}} }
	return obj(map[string]any{"schema_version": str(), "kind": str(), "text": str(), "labels": arr(str()), "intent": str(), "claims": arr(claim), "entities": arr(entity), "roles": arr(role), "identity": nullable(obj(map[string]any{"relation": str(), "refs": arr(ref)})), "plan": nullable(plan), "refs": arr(ref), "limitations": arr(str())}).(map[string]any)
}
func (s Store) wire(ctx context.Context, b Binding, c Connection, key, attempt string, snap Snapshot, functions []Function, authorize func(context.Context) error) (GatewayResult, error) {
	var out GatewayResult
	ctx, cancel := context.WithTimeout(ctx, time.Duration(b.Limits.DeadlineMS)*time.Millisecond)
	defer cancel()
	payload, _ := json.Marshal(snap)
	system, _, promptErr := promptsv2.Resolve(b.PromptVersion)
	if promptErr != nil {
		return out, &GatewayError{"prompt_version_invalid", true, false, 0}
	}
	ids, _ := json.Marshal(functions)
	system += string(ids)
	body, _ := json.Marshal(map[string]any{"model": b.Model, "max_tokens": b.Limits.MaxOutputTokens, "stream": false, "messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": string(payload)}}, "response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "noctis_v1", "strict": true, "schema": resultSchema()}}})
	if c.Adapter == "openai-responses" {
		body, _ = json.Marshal(map[string]any{"model": b.Model, "instructions": system, "input": string(payload), "max_output_tokens": b.Limits.MaxOutputTokens, "stream": false, "store": false, "text": map[string]any{"format": map[string]any{"type": "json_schema", "name": "noctis_v1", "strict": true, "schema": responsesSchemaForPrompt(functions, snap, b.PromptVersion)}}})
	} else if c.Adapter != "openai-chat" {
		return out, &GatewayError{"adapter_invalid", true, false, 0}
	}
	// This bounds the local request only. Provider-added context and billing
	// require a separately reviewed contract and upstream monetary cap.
	if len(body) > b.Limits.MaxInputTokens {
		return out, &GatewayError{"input_limit", true, false, 0}
	}
	client, close, e := s.client(ctx, c.URL)
	if e != nil {
		return out, &GatewayError{"endpoint_denied", true, false, 0}
	}
	defer close()
	req, e := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(body))
	if e != nil {
		return out, &GatewayError{"invalid_request", true, false, 0}
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("X-Noctis-Attempt", attempt)
	if e = authorize(ctx); e != nil {
		return out, &GatewayError{"authorization_changed", true, false, 0}
	}
	res, e := client.Do(req)
	if e != nil {
		return out, transportDiagnostic(e)
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if e != nil {
		return out, transportDiagnostic(e)
	}
	if len(raw) > 2<<20 {
		return out, &GatewayError{"response_limit", true, true, 0}
	}
	// Only 200 carries a supported synchronous response. Other successful
	// statuses may already have executed the request, so never retry or release
	// its exposure based on their body, Location or Retry-After headers.
	if res.StatusCode > http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return out, &GatewayError{"response_status_invalid", true, true, 0}
	}
	if res.StatusCode != 200 {
		g := &GatewayError{Code: "upstream_error", Permanent: res.StatusCode >= 400 && res.StatusCode < 500, Uncertain: res.StatusCode >= 500}
		switch res.StatusCode {
		case 400:
			g.Code = "invalid_request"
		case 401, 403:
			g.Code = "authentication_denied"
		case 429:
			g.Code = "rate_limited"
			g.Permanent = false
			n, _ := strconv.Atoi(res.Header.Get("Retry-After"))
			g.RetryAfter = time.Duration(min(max(n, 1), 86400)) * time.Second
		default:
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				g.Code = "redirect_denied"
				g.Permanent = true
			}
		}
		return out, g
	}
	if c.Adapter == "openai-responses" {
		return decodeResponses(raw, b.Model)
	}
	var envelope struct {
		Model   string `json:"model"`
		Choices []struct {
			Finish  string `json:"finish_reason"`
			Message struct {
				Content string  `json:"content"`
				Refusal *string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			Input  *int64 `json:"prompt_tokens"`
			Output *int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Choices) != 1 {
		return out, &GatewayError{"response_invalid", true, true, 0}
	}
	out.Model = envelope.Model
	if out.Model == "" {
		out.Model = "unknown"
	}
	if envelope.Usage != nil && envelope.Usage.Input != nil && envelope.Usage.Output != nil && *envelope.Usage.Input >= 0 && *envelope.Usage.Output >= 0 && *envelope.Usage.Input <= 1<<30 && *envelope.Usage.Output <= 1<<30 {
		out.Usage = &Usage{*envelope.Usage.Input, *envelope.Usage.Output}
	}
	ch := envelope.Choices[0]
	if ch.Finish != "stop" || ch.Message.Refusal != nil {
		return out, &GatewayError{"response_incomplete", true, out.Usage == nil, 0}
	}
	if Strict([]byte(ch.Message.Content), &out.Result) != nil {
		return out, &GatewayError{"response_schema_invalid", true, out.Usage == nil, 0}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(ch.Message.Content), &fields) != nil {
		return out, &GatewayError{"response_schema_invalid", true, out.Usage == nil, 0}
	}
	for _, name := range []string{"schema_version", "kind", "text", "labels", "intent", "claims", "entities", "roles", "identity", "plan", "refs", "limitations"} {
		if _, ok := fields[name]; !ok {
			return out, &GatewayError{"response_schema_invalid", true, out.Usage == nil, 0}
		}
	}
	if out.Model != "unknown" && out.Model != b.Model {
		return out, &GatewayError{"model_changed", true, out.Usage == nil, 0}
	}
	return out, nil
}
