package runtimev2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/jackc/pgx/v5"
)

func TestWorkerValidatesDeliveryEndpointBeforeDatabase(t *testing.T) {
	for _, endpoint := range []string{"/relative", "https://", "ftp://localhost", "http://localhost:", "http://[::1]:65536"} {
		t.Run(endpoint, func(t *testing.T) {
			err := Run(context.Background(), configv2.Config{Mode: "worker", DatabaseURL: "://invalid-dsn", DeliveryEndpoint: endpoint})
			if !errors.Is(err, intelligence.ErrInvalidDeliveryEndpoint) {
				t.Fatalf("endpoint not rejected before database check: %v", err)
			}
		})
	}
	// An empty worker destination still disables delivery and proceeds to Check.
	if err := Run(context.Background(), configv2.Config{Mode: "worker", DatabaseURL: "://invalid-dsn"}); err == nil || errors.Is(err, intelligence.ErrInvalidDeliveryEndpoint) {
		t.Fatalf("empty destination should proceed to database check: %v", err)
	}
}

func outboxSnapshot(t *testing.T, c *pgx.Conn) string {
	t.Helper()
	var snapshot string
	if err := c.QueryRow(context.Background(), `SELECT jsonb_agg(to_jsonb(o) ORDER BY id)::text FROM noctis_v2.outbox o`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestInvalidDeliveryEndpointsPreserveOutboxPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	first, _, _ := qualifiedOutbox(t, dsn)
	qualifiedOutbox(t, dsn)
	qualifiedOutbox(t, dsn)
	uncertain, _, _ := qualifiedOutbox(t, dsn)
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.outbox SET state='uncertain' WHERE id=$1`, uncertain); err != nil {
		t.Fatal(err)
	}
	var key, body string
	if err = c.QueryRow(ctx, `SELECT delivery_key,body::text FROM noctis_v2.outbox WHERE id=$1`, first).Scan(&key, &body); err != nil {
		t.Fatal(err)
	}
	type receipt struct{ key, body, contentType, state string }
	received := make(chan receipt, 1)
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, readErr := io.ReadAll(r.Body)
		var state string
		queryErr := c.QueryRow(ctx, `SELECT state FROM noctis_v2.outbox WHERE id=$1`, first).Scan(&state)
		if readErr != nil || queryErr != nil {
			w.WriteHeader(500)
			return
		}
		received <- receipt{r.Header.Get("Idempotency-Key"), string(b), r.Header.Get("Content-Type"), state}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	worker := intelligence.Worker{DSN: dsn}
	before := outboxSnapshot(t, c)
	for range 2 {
		for _, endpoint := range []string{"", "/events", "https://", "ftp://localhost", receiver.URL + "/%zz", receiver.URL + "/?q=%zz", "http://localhost:", "http://localhost:65536", "http://[::1", "http://[bad-ipv6]"} {
			if err = worker.DispatchOnce(ctx, endpoint, nil); !errors.Is(err, intelligence.ErrInvalidDeliveryEndpoint) {
				t.Fatalf("invalid endpoint: %v", err)
			}
		}
	}
	if after := outboxSnapshot(t, c); after != before || calls.Load() != 0 {
		t.Fatal("invalid destinations changed outbox or sent requests")
	}
	if err = worker.DispatchOnce(ctx, receiver.URL+"/events?kind=brief", nil); err != nil {
		t.Fatal(err)
	}
	got := <-received
	if calls.Load() != 1 || got.key != key || got.body != body || got.contentType != "application/json" || got.state != "uncertain" {
		t.Fatalf("delivery identity, body or durable admission changed: %+v calls=%d", got, calls.Load())
	}
	var queued, delivered, uncertainCount int
	if err = c.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='queued'),count(*) FILTER(WHERE state='delivered'),count(*) FILTER(WHERE state='uncertain') FROM noctis_v2.outbox`).Scan(&queued, &delivered, &uncertainCount); err != nil || queued != 2 || delivered != 1 || uncertainCount != 1 {
		t.Fatalf("delivery consumed more than one row: queued=%d delivered=%d uncertain=%d err=%v", queued, delivered, uncertainCount, err)
	}
}

func TestDeliveryPreparationFailurePreservesQueuePostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	id, _, _ := qualifiedOutbox(t, dsn)
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.outbox SET delivery_key=$2 WHERE id=$1`, id, "bad\r\nkey"); err != nil {
		t.Fatal(err)
	}
	before := outboxSnapshot(t, c)
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer receiver.Close()
	if err = (intelligence.Worker{DSN: dsn}).DispatchOnce(ctx, receiver.URL, nil); err == nil || err.Error() != "invalid delivery idempotency key" {
		t.Fatalf("invalid header not rejected during preparation: %v", err)
	}
	if after := outboxSnapshot(t, c); after != before || calls.Load() != 0 {
		t.Fatal("request preparation failure consumed delivery or sent a request")
	}
}

type deliveryFailingTransport struct{ attempts int }

func (tr *deliveryFailingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.attempts++
	return nil, errors.New("synthetic transport failure")
}

func TestDeliverySendFailureRemainsUncertainPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	id, _, _ := qualifiedOutbox(t, dsn)
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	worker := intelligence.Worker{DSN: dsn}
	transport := &deliveryFailingTransport{}
	client := &http.Client{Transport: transport}
	if err = worker.DispatchOnce(ctx, "https://receiver.invalid/events", client); err == nil {
		t.Fatal("failed send acknowledged")
	}
	var state string
	if err = c.QueryRow(ctx, `SELECT state FROM noctis_v2.outbox WHERE id=$1`, id).Scan(&state); err != nil || state != "uncertain" {
		t.Fatal("send failure lost uncertainty", state, err)
	}
	if err = worker.DispatchOnce(ctx, "https://receiver.invalid/events", client); !errors.Is(err, pgx.ErrNoRows) || transport.attempts != 1 {
		t.Fatal("uncertain send replayed", err, transport.attempts)
	}
}
