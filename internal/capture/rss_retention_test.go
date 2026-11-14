package capture

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const rssExpiredEntry = `<item><guid>A</guid><title>old evidence</title></item>`
const rssNewEntry = `<item><guid>B</guid><title>new evidence</title></item>`

func rssExpiredBatch(t *testing.T, dsn, address, entry string, change func(*Item)) Batch {
	t.Helper()
	ctx := context.Background()
	b := batch(t, dsn)
	items, err := ParseFeed([]byte(`<rss><channel>`+entry+`</channel></rss>`), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	b.Items = items
	if change != nil {
		change(&b.Items[0])
	}
	if _, err = (Store{DSN: dsn}).CommitBatch(ctx, b); err != nil {
		t.Fatal(err)
	}
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.sources SET native_id=$2 WHERE id=$1`, b.SourceID, address); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.observations SET retention_expired_at=clock_timestamp() WHERE source_id=$1`, b.SourceID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.content_blobs SET payload=''::bytea`); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertRSSPollRollback(t *testing.T, dsn string, b Batch, wantVersion int64) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var intact bool
	err = c.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM noctis_v2.observations)=1 AND
 (SELECT count(*) FROM noctis_v2.observations WHERE retention_expired_at IS NOT NULL)=1 AND
 (SELECT count(*) FROM noctis_v2.content_blobs)=1 AND
 (SELECT octet_length(payload)=0 FROM noctis_v2.content_blobs) AND
 (SELECT count(*) FROM noctis_v2.jobs)=1 AND
 (SELECT count(*) FROM noctis_v2.batch_receipts)=1 AND
 (SELECT version=$2 AND value=$3::jsonb FROM noctis_v2.checkpoints WHERE source_id=$1)`, b.SourceID, wantVersion, string(b.Next.Value)).Scan(&intact)
	if err != nil || !intact {
		t.Fatal("failed poll changed capture state", intact, err)
	}
}

func TestRSSExpiredIdentityConflictRollsBackPostgres(t *testing.T) {
	for _, field := range []string{"hash", "representation"} {
		t.Run(field, func(t *testing.T) {
			dsn := isolated(t)
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Include the new entry first to detect partial commits as well.
				fmt.Fprint(w, `<rss><channel>`+rssNewEntry+rssExpiredEntry+`</channel></rss>`)
			}))
			defer feed.Close()
			b := rssExpiredBatch(t, dsn, feed.URL, rssExpiredEntry, func(item *Item) {
				if field == "hash" {
					item.Payload = []byte("different content for the same revision")
					item.Hash = fmt.Sprintf("sha256:%x", sha256.Sum256(item.Payload))
				} else {
					item.Representation = "other-text-v1"
				}
			})
			err := (Store{DSN: dsn}).Poll(context.Background(), b.SourceID, Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}})
			if !errors.Is(err, ErrConflict) {
				t.Fatal("expired identity mismatch accepted", err)
			}
			assertRSSPollRollback(t, dsn, b, 1)
		})
	}
}

func TestRSSExpiredFilterPreservesOriginalLimitsPostgres(t *testing.T) {
	for _, tc := range []struct {
		name, entry, want string
		count             int
	}{
		{name: "items", entry: rssExpiredEntry, count: 10001, want: "capture item limit exceeded"},
		{name: "bytes", entry: `<item><guid>A</guid><title>` + strings.Repeat("x", 4<<20) + `</title></item>`, count: 9, want: "capture payload limit exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := isolated(t)
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<rss><channel>`)
				for i := 0; i < tc.count; i++ {
					fmt.Fprint(w, tc.entry)
				}
				fmt.Fprint(w, `</channel></rss>`)
			}))
			defer feed.Close()
			b := rssExpiredBatch(t, dsn, feed.URL, tc.entry, nil)
			err := (Store{DSN: dsn}).Poll(context.Background(), b.SourceID, Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}, MaxCompressed: 40 << 20, MaxDecoded: 40 << 20})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("original batch limit bypassed: %v, want %s", err, tc.want)
			}
			assertRSSPollRollback(t, dsn, b, 1)
		})
	}
}

func TestRSSExpiredFilterRevalidatesAuthorizationAndCASPostgres(t *testing.T) {
	for _, change := range []string{"authorization", "policy", "epoch", "checkpoint"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dsn := isolated(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var released sync.Once
			unblock := func() { released.Do(func() { close(release) }) }
			feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-release:
					fmt.Fprint(w, `<rss><channel>`+rssExpiredEntry+rssNewEntry+`</channel></rss>`)
				case <-r.Context().Done():
				}
			}))
			defer feed.Close()
			defer unblock()
			b := rssExpiredBatch(t, dsn, feed.URL, rssExpiredEntry, nil)
			done := make(chan error, 1)
			go func() {
				done <- (Store{DSN: dsn}).Poll(ctx, b.SourceID, Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}})
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			c, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close(context.Background())
			version := int64(1)
			switch change {
			case "authorization":
				_, err = c.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, b.SourceID)
			case "policy":
				_, err = c.Exec(ctx, `UPDATE noctis_v2.sources SET policy_version='p2' WHERE id=$1`, b.SourceID)
			case "epoch":
				_, err = c.Exec(ctx, `UPDATE noctis_v2.sources SET epoch=$2 WHERE id=$1`, b.SourceID, uuid.NewString())
			case "checkpoint":
				version = 2
				_, err = c.Exec(ctx, `UPDATE noctis_v2.checkpoints SET version=2 WHERE source_id=$1`, b.SourceID)
			}
			if err != nil {
				t.Fatal(err)
			}
			unblock()
			err = <-done
			if change == "checkpoint" {
				if !errors.Is(err, ErrConflict) {
					t.Fatal("stale checkpoint accepted", err)
				}
			} else if err == nil || err.Error() != "source authorization changed" {
				t.Fatal("changed source authorization accepted", err)
			}
			assertRSSPollRollback(t, dsn, b, version)
		})
	}
}
