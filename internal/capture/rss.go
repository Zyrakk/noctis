package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

type feedEntry struct {
	ID          string `xml:"id"`
	GUID        string `xml:"guid"`
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Content     string `xml:"content"`
	Summary     string `xml:"summary"`
	Link        struct {
		Text string `xml:",chardata"`
		Href string `xml:"href,attr"`
	} `xml:"link"`
	Published string `xml:"published"`
	PubDate   string `xml:"pubDate"`
	Updated   string `xml:"updated"`
}
type feed struct {
	XMLName xml.Name
	Channel struct {
		Items []feedEntry `xml:"item"`
	} `xml:"channel"`
	Entries []feedEntry `xml:"entry"`
}

func ParseFeed(raw []byte, now time.Time) ([]Item, error) {
	var f feed
	if e := xml.Unmarshal(raw, &f); e != nil {
		return nil, e
	}
	if f.XMLName.Local != "rss" && f.XMLName.Local != "feed" {
		return nil, fmt.Errorf("unsupported feed root")
	}
	entries := append(f.Channel.Items, f.Entries...)
	out := make([]Item, 0, len(entries))
	for _, entry := range entries {
		text := strings.TrimSpace(entry.Title + "\n" + entry.Description + "\n" + entry.Summary + "\n" + entry.Content)
		if text == "" {
			continue
		}
		id := entry.GUID
		if id == "" {
			id = entry.ID
		}
		if id == "" {
			id = entry.Link.Text
			if id == "" {
				id = entry.Link.Href
			}
		}
		if id == "" {
			return nil, fmt.Errorf("feed entry lacks stable identity")
		}
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text)))
		var published *time.Time
		for _, value := range []string{entry.Published, entry.PubDate} {
			for _, layout := range []string{time.RFC3339, time.RFC1123Z, time.RFC1123, time.RFC822Z} {
				if t, e := time.Parse(layout, value); e == nil {
					t = t.UTC()
					published = &t
					break
				}
			}
			if published != nil {
				break
			}
		}
		out = append(out, Item{NativeID: id, Revision: hash, Payload: []byte(text), Representation: "feed-text-v1", Hash: hash, PublishedAt: published, CollectedAt: now.UTC()})
	}
	return out, nil
}
func (s Store) Poll(ctx context.Context, id string, f Fetcher) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	var address, epoch, policy string
	e = c.QueryRow(ctx, `SELECT native_id,epoch::text,policy_version FROM noctis_v2.sources s WHERE id=$1 AND kind IN ('rss','atom') AND `+intelligence.SourceAuthorizedSQL, id).Scan(&address, &epoch, &policy)
	if e != nil {
		return e
	}
	var expected Checkpoint
	expected.Value = json.RawMessage("null")
	var v string
	e = c.QueryRow(ctx, `SELECT version,value::text FROM noctis_v2.checkpoints WHERE source_id=$1 AND epoch=$2 AND mode='live'`, id, epoch).Scan(&expected.Version, &v)
	if e == nil {
		expected.Value = json.RawMessage(v)
	} else if e != pgx.ErrNoRows {
		return e
	}
	f.BeforeRequest = func(ctx context.Context) error {
		var valid bool
		if e := c.QueryRow(ctx, `SELECT `+intelligence.SourceAuthorizedSQL+` AND policy_version=$2 AND epoch::text=$3 FROM noctis_v2.sources s WHERE id=$1`, id, policy, epoch).Scan(&valid); e != nil {
			return e
		}
		if !valid {
			return errors.New("source authorization changed")
		}
		return nil
	}
	var raw []byte
	e = intelligence.GuardProjectionIO(ctx, c, func(ioCtx context.Context) error {
		var fetchErr error
		raw, fetchErr = f.Get(ioCtx, address)
		return fetchErr
	})
	if e != nil {
		_, _ = c.Exec(ctx, `UPDATE noctis_v2.sources SET last_error=$2,coverage='gap_unknown' WHERE id=$1`, id, e.Error())
		return e
	}
	items, e := ParseFeed(raw, time.Now().UTC())
	if e != nil {
		return e
	}
	checkpoint, _ := json.Marshal(map[string]string{"feed_hash": fmt.Sprintf("%x", sha256.Sum256(raw))})
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	var valid bool
	if e = tx.QueryRow(ctx, `SELECT `+intelligence.SourceAuthorizedSQL+` AND policy_version=$2 AND epoch::text=$3 FROM noctis_v2.sources s WHERE id=$1 FOR SHARE`, id, policy, epoch).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return errors.New("source authorization changed")
	}
	if _, e = CommitBatchTx(ctx, tx, Batch{BatchID: uuid.NewString(), Version: "1", SourceID: id, Epoch: epoch, Mode: Live, Expected: expected, Next: Checkpoint{Version: expected.Version + 1, Value: checkpoint}, Items: items}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
