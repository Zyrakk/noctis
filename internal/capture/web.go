package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type WebConfig struct {
	ParserVersion string      `json:"parser_version"`
	ItemTag       string      `json:"item_tag"`
	AuthFile      string      `json:"auth_file"`
	MaxItems      int         `json:"max_items"`
	Tor           *TorProfile `json:"tor,omitempty"`
}
type WebPage struct {
	Items []Item
	Next  string
}

func ParseWeb(raw []byte, address, kind string, cfg WebConfig, now time.Time) (WebPage, error) {
	out := WebPage{Items: []Item{}}
	base, e := url.Parse(address)
	if e != nil {
		return out, e
	}
	if cfg.ParserVersion == "" || len(cfg.ParserVersion) > 64 {
		return out, errors.New("parser version required")
	}
	if cfg.MaxItems < 1 || cfg.MaxItems > 1000 {
		return out, errors.New("web item bound required")
	}
	root, e := html.Parse(strings.NewReader(string(raw)))
	if e != nil {
		return out, e
	}
	attr := func(n *html.Node, key string) string {
		for _, a := range n.Attr {
			if a.Key == key {
				return a.Val
			}
		}
		return ""
	}
	var text func(*html.Node) string
	text = func(n *html.Node) string {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "noscript" || n.Data == "template") {
			return ""
		}
		if n.Type == html.TextNode {
			return n.Data
		}
		var b strings.Builder
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			b.WriteString(text(ch))
			b.WriteByte('\n')
		}
		return b.String()
	}
	tag := cfg.ItemTag
	if tag == "" {
		tag = "article"
		if kind == "paste" {
			tag = "pre"
		}
	}
	var walk func(*html.Node) error
	index := 0
	walk = func(n *html.Node) error {
		if n.Type == html.ElementNode && n.Data == "a" && strings.Contains(" "+attr(n, "rel")+" ", " next ") {
			u, e := base.Parse(attr(n, "href"))
			if e != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil {
				return errors.New("pagination crossed authorized origin")
			}
			out.Next = u.String()
		}
		if n.Type == html.ElementNode && n.Data == tag {
			index++
			if index > cfg.MaxItems {
				return errors.New("web page exceeds item limit")
			}
			content := strings.Join(strings.Fields(text(n)), " ")
			if content == "" {
				return nil
			}
			id := attr(n, "data-id")
			if id == "" {
				id = attr(n, "id")
			}
			if id == "" {
				id = fmt.Sprintf("web-path-v1:%s#%s:%d", address, tag, index)
			} else {
				id = base.Scheme + "://" + base.Host + base.Path + "#" + id
			}
			hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
			out.Items = append(out.Items, Item{NativeID: id, Revision: cfg.ParserVersion + ":" + hash, Payload: []byte(content), Hash: hash, Representation: "web-text-v1", CollectedAt: now.UTC()})
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			if e := walk(ch); e != nil {
				return e
			}
		}
		return nil
	}
	if e = walk(root); e != nil {
		return out, e
	}
	if len(out.Items) == 0 {
		return out, errors.New("web page has no configured items; parser review required")
	}
	return out, nil
}

func (s Store) PollWeb(ctx context.Context, id string, f Fetcher) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	var address, kind, epoch, policy string
	var cfgRaw []byte
	e = c.QueryRow(ctx, `SELECT native_id,kind,epoch::text,policy_version,adapter_config FROM noctis_v2.sources s WHERE id=$1 AND kind IN('html','paste','forum') AND `+intelligence.SourceAuthorizedSQL, id).Scan(&address, &kind, &epoch, &policy, &cfgRaw)
	if e != nil {
		return e
	}
	var cfg WebConfig
	if json.Unmarshal(cfgRaw, &cfg) != nil {
		return errors.New("invalid web adapter config")
	}
	f.Tor = cfg.Tor
	expected := Checkpoint{Value: json.RawMessage("null")}
	var cp []byte
	e = c.QueryRow(ctx, `SELECT version,value FROM noctis_v2.checkpoints WHERE source_id=$1 AND epoch=$2 AND mode='live'`, id, epoch).Scan(&expected.Version, &cp)
	if e == nil {
		expected.Value = cp
		var page struct {
			Next string `json:"next_url"`
		}
		if json.Unmarshal(cp, &page) != nil {
			return errors.New("invalid web checkpoint")
		}
		if page.Next != "" {
			address = page.Next
		}
	} else if e != pgx.ErrNoRows {
		return e
	}
	headers := http.Header{}
	if cfg.AuthFile != "" {
		st, e := os.Stat(cfg.AuthFile)
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return errors.New("protected web auth file required")
		}
		raw, e := os.ReadFile(cfg.AuthFile)
		if e != nil || len(raw) > 8192 {
			return errors.New("web auth unavailable")
		}
		headers.Set("Authorization", strings.TrimSpace(string(raw)))
	}
	f.BeforeRequest = func(ctx context.Context) error {
		var valid bool
		e := c.QueryRow(ctx, `SELECT `+intelligence.SourceAuthorizedSQL+` AND policy_version=$2 AND epoch::text=$3 FROM noctis_v2.sources s WHERE id=$1`, id, policy, epoch).Scan(&valid)
		if e != nil {
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
		raw, fetchErr = f.GetWithHeaders(ioCtx, address, headers)
		return fetchErr
	})
	if e != nil {
		return errors.New("web fetch failed")
	}
	page, e := ParseWeb(raw, address, kind, cfg, time.Now().UTC())
	if e != nil {
		return e
	}
	next, _ := json.Marshal(map[string]any{"page_url": address, "next_url": page.Next, "complete": page.Next == "", "parser_version": cfg.ParserVersion})
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
	_, e = CommitBatchTx(ctx, tx, Batch{BatchID: uuid.NewString(), Version: "1", SourceID: id, Epoch: epoch, Mode: Live, Expected: expected, Next: Checkpoint{Version: expected.Version + 1, Value: next}, Items: page.Items})
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET last_success_at=clock_timestamp(),last_error=NULL,coverage=$2,poll_after=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id, "bounded_web_page; publication_time_unknown; pagination_complete="+fmt.Sprint(page.Next == ""))
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
