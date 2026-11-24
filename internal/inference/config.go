package inference

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"github.com/jackc/pgx/v5"
	"io"
	"net/url"
	"os"
	"strings"
)

var ErrConflict = errors.New("configuration conflict")
var ErrInvalid = errors.New("configuration invalid")

type Store struct {
	DSN        string
	KeyFile    string
	CAFile     string
	AllowLocal map[string]bool
}

func DefaultConfig() Config {
	c := Config{Connections: []Connection{}, Bindings: []Binding{}, MaxConcurrent: 1}
	for _, f := range Functions {
		c.Bindings = append(c.Bindings, Binding{Function: f.ID, PromptVersion: "2", SchemaVersion: "1", PolicyVersion: "1", Limits: Limits{32768, 2048, 30000}, Price: Price{Version: "unconfigured"}, MaxConcurrent: 1})
	}
	return c
}
func Strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return ErrInvalid
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return ErrInvalid
	}
	return nil
}
func (s Store) key() (string, cipher.AEAD, error) {
	info, e := os.Stat(s.KeyFile)
	if e != nil || info.Mode().Perm()&0077 != 0 {
		return "", nil, errors.New("credential key unavailable")
	}
	raw, e := os.ReadFile(s.KeyFile)
	if e != nil {
		return "", nil, errors.New("credential key unavailable")
	}
	var k struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if Strict(raw, &k) != nil || k.KeyID == "" || len(k.KeyID) > 128 {
		return "", nil, errors.New("credential key invalid")
	}
	secret, e := hex.DecodeString(k.Key)
	if e != nil || len(secret) != 32 {
		return "", nil, errors.New("credential key invalid")
	}
	block, e := aes.NewCipher(secret)
	if e != nil {
		return "", nil, e
	}
	a, e := cipher.NewGCM(block)
	return k.KeyID, a, e
}
func aad(id string, rev int64, keyID string) []byte {
	return []byte(fmt.Sprintf("noctis-ai-v1\x00%s\x00%d\x00%s", id, rev, keyID))
}
func (s Store) decrypt(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, rev int64, id string) (string, error) {
	var keyID string
	var nonce, body []byte
	e := tx.QueryRow(ctx, `SELECT key_id,nonce,ciphertext FROM noctis_v2.ai_secrets WHERE config_revision=$1 AND connection_id=$2`, rev, id).Scan(&keyID, &nonce, &body)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	kid, a, e := s.key()
	if e != nil || kid != keyID {
		return "", errors.New("credential unavailable")
	}
	plain, e := a.Open(nil, nonce, body, aad(id, rev, kid))
	if e != nil {
		return "", errors.New("credential unavailable")
	}
	return string(plain), nil
}
func (s Store) Read(ctx context.Context) (ConfigView, error) {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return ConfigView{}, e
	}
	defer c.Close(context.Background())
	cfg, e := readConfig(ctx, c)
	_, _, ke := s.key()
	return ConfigView{cfg, Functions, ke == nil}, e
}
func readConfig(ctx context.Context, c interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (Config, error) {
	var raw []byte
	e := c.QueryRow(ctx, `SELECT body FROM noctis_v2.ai_configs ORDER BY revision DESC LIMIT 1`).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return DefaultConfig(), nil
	}
	if e != nil {
		return Config{}, e
	}
	var cfg Config
	e = json.Unmarshal(raw, &cfg)
	return cfg, e
}
func (s Store) Validate(c Config) error {
	if len(c.Connections) > 64 || len(c.Bindings) != len(Functions) || c.DailyCap < 0 || c.MonthlyCap < 0 || c.MaxConcurrent < 1 || c.MaxConcurrent > 64 {
		return ErrInvalid
	}
	ids := map[string]bool{}
	for _, v := range c.Connections {
		u, e := url.Parse(v.URL)
		if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Hostname(), "%") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion") || (u.Scheme != "https" && !(u.Scheme == "http" && s.AllowLocal[u.Host])) || !supportedAdapter(v.Adapter) || len(v.URL) > 2048 || v.ID == "" || len(v.ID) > 128 || ids[v.ID] || v.Provider == "" || len(v.Provider) > 128 || len(v.DataClasses) == 0 {
			return ErrInvalid
		}
		ids[v.ID] = true
		switch v.SecretAction {
		case "", "unchanged", "clear":
			if v.APIKey != "" {
				return ErrInvalid
			}
		case "set":
			if strings.TrimSpace(v.APIKey) == "" || len(v.APIKey) > 8192 || strings.ContainsAny(v.APIKey, "\r\n") {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		for _, d := range v.DataClasses {
			if d != "public-approved" && d != "private-approved" {
				return ErrInvalid
			}
		}
	}
	funcs := map[Function]bool{}
	for _, b := range c.Bindings {
		if _, _, err := promptsv2.Resolve(b.PromptVersion); err != nil {
			return ErrInvalid
		}
		if _, ok := Spec(b.Function); !ok || funcs[b.Function] {
			return ErrInvalid
		}
		funcs[b.Function] = true
		if b.DailyCap < 0 || b.MonthlyCap < 0 || b.MaxConcurrent < 1 || b.MaxConcurrent > 64 || b.Limits.MaxInputTokens < 1 || b.Limits.MaxInputTokens > 1<<20 || b.Limits.MaxOutputTokens < 1 || b.Limits.MaxOutputTokens > 65536 || b.Limits.DeadlineMS < 100 || b.Limits.DeadlineMS > 120000 || b.Price.Input < 0 || b.Price.Output < 0 || b.Price.Input > 1e9 || b.Price.Output > 1e9 || b.Price.Version == "" || len(b.Price.Version) > 128 || b.SchemaVersion != "1" || b.PolicyVersion == "" || len(b.PolicyVersion) > 128 {
			return ErrInvalid
		}
		if b.Enabled && (!ids[b.ConnectionID] || !b.StructuredJSON || strings.TrimSpace(b.Model) == "" || len(b.Model) > 256 || b.DailyCap == 0 || b.MonthlyCap == 0 || c.DailyCap == 0 || c.MonthlyCap == 0) {
			return ErrInvalid
		}
		// Compare the marker without changing the persisted tariff identity.
		priceVersion := strings.TrimSpace(b.Price.Version)
		if b.Enabled && (priceVersion == "" || strings.EqualFold(priceVersion, "unconfigured")) {
			return ErrInvalid
		}
	}
	return nil
}
func (s Store) Save(ctx context.Context, cfg Config, expected int64, actor string) (ConfigView, error) {
	if e := s.Validate(cfg); e != nil {
		return ConfigView{}, e
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return ConfigView{}, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return ConfigView{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451004)`); e != nil {
		return ConfigView{}, e
	}
	old, e := readConfig(ctx, tx)
	if e != nil {
		return ConfigView{}, e
	}
	if old.Revision != expected || cfg.Revision != expected {
		return ConfigView{}, ErrConflict
	}
	cfg.Revision = old.Revision + 1
	secrets := map[string]string{}
	for i, v := range cfg.Connections {
		var key string
		switch v.SecretAction {
		case "set":
			key = v.APIKey
		case "clear":
		default:
			key, e = s.decrypt(ctx, tx, old.Revision, v.ID)
			if e != nil {
				return ConfigView{}, e
			}
		}
		secrets[v.ID] = key
		cfg.Connections[i].APIKey = ""
		cfg.Connections[i].SecretAction = ""
		cfg.Connections[i].SecretPresent = key != ""
	}
	raw, _ := json.Marshal(cfg)
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_configs(revision,body,actor) VALUES($1,$2,$3)`, cfg.Revision, string(raw), actor); e != nil {
		return ConfigView{}, e
	}
	for id, plain := range secrets {
		if plain == "" {
			continue
		}
		kid, a, ke := s.key()
		if ke != nil {
			return ConfigView{}, ke
		}
		nonce := make([]byte, a.NonceSize())
		if _, e = rand.Read(nonce); e != nil {
			return ConfigView{}, e
		}
		encrypted := a.Seal(nil, nonce, []byte(plain), aad(id, cfg.Revision, kid))
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_secrets(config_revision,connection_id,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, cfg.Revision, id, kid, nonce, encrypted); e != nil {
			return ConfigView{}, e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.ai_promotions SET status='invalidated' WHERE status='validated'`); e != nil {
		return ConfigView{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return ConfigView{}, e
	}
	_, _, ke := s.key()
	return ConfigView{cfg, Functions, ke == nil}, nil
}
func findBinding(c Config, id Function) (Binding, Connection, error) {
	for _, b := range c.Bindings {
		if b.Function == id && b.Enabled && b.StructuredJSON {
			for _, v := range c.Connections {
				if v.ID == b.ConnectionID {
					return b, v, nil
				}
			}
		}
	}
	return Binding{}, Connection{}, errors.New("function disabled or capability unavailable")
}
