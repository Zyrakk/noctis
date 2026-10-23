package legacyimport

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SourceManifest preserves unknown identities as null; aliases are never IDs.
// Import never changes an existing source or grants access from legacy status.
type SourceManifest struct {
	Version    string           `json:"version"`
	ManifestID string           `json:"manifest_id"`
	Sources    []ManifestSource `json:"sources"`
}
type ManifestSource struct {
	Identity         string   `json:"identity"`
	SourceID         *string  `json:"source_id"`
	LegacySourceID   *string  `json:"legacy_source_id"`
	Kind             string   `json:"kind"`
	AccountID        *string  `json:"account_id"`
	PeerType         *string  `json:"peer_type"`
	NativeID         *string  `json:"native_id"`
	Aliases          []string `json:"aliases"`
	Provenance       []string `json:"provenance"`
	LegacyStatus     string   `json:"legacy_status"`
	Authorization    string   `json:"authorization"`
	ResolutionStatus string   `json:"resolution_status"`
	Disposition      string   `json:"disposition"`
	PolicyVersion    string   `json:"policy_version"`
	Conflicts        []string `json:"conflicts"`
}
type ImportReceipt struct {
	ManifestID string `json:"manifest_id"`
	Digest     string `json:"digest"`
	DryRun     bool   `json:"dry_run"`
	Entries    int    `json:"entries"`
	Created    int    `json:"created"`
	Preserved  int    `json:"preserved"`
	Unresolved int    `json:"unresolved"`
}
type Store struct{ DSN string }

func (s Store) ImportManifest(ctx context.Context, m SourceManifest, dryRun bool) (ImportReceipt, error) {
	r := ImportReceipt{ManifestID: m.ManifestID, DryRun: dryRun, Entries: len(m.Sources)}
	if m.Version != "sources-manifest-v1" || m.ManifestID == "" || len(m.Sources) > 100000 {
		return r, errors.New("invalid manifest")
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return r, e
	}
	if len(raw) > 32<<20 {
		return r, errors.New("manifest exceeds limit")
	}
	r.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return r, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return r, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,9))`, m.ManifestID); e != nil {
		return r, e
	}
	var digest string
	var prior []byte
	e = tx.QueryRow(ctx, `SELECT digest,receipt FROM noctis_v2.source_imports WHERE manifest_id=$1`, m.ManifestID).Scan(&digest, &prior)
	if e == nil {
		if digest != r.Digest {
			return r, errors.New("manifest identity conflict")
		}
		e = json.Unmarshal(prior, &r)
		r.DryRun = dryRun
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return r, e
	}
	seen := map[string]bool{}
	for _, v := range m.Sources {
		if v.Identity == "" || len(v.Identity) > 1024 || seen[v.Identity] || len(v.Provenance) == 0 {
			return r, errors.New("invalid/duplicate manifest identity or provenance")
		}
		seen[v.Identity] = true
		switch v.Disposition {
		case "enabled", "paused", "inaccessible", "excluded", "pending", "rejected":
		default:
			return r, errors.New("explicit disposition required")
		}
		if v.Authorization == "" || v.ResolutionStatus == "" || v.Kind == "" {
			return r, errors.New("authorization, resolution and kind required")
		}
		if v.Disposition == "enabled" && (v.Authorization != "approved" || v.ResolutionStatus != "resolved" || len(v.Conflicts) > 0) {
			return r, errors.New("source activation requires resolved approved policy")
		}
		if v.SourceID != nil {
			if _, e = uuid.Parse(*v.SourceID); e != nil {
				return r, errors.New("invalid source UUID")
			}
		}
		var id *string
		if v.NativeID == nil || *v.NativeID == "" || v.PolicyVersion == "" || v.ResolutionStatus != "resolved" {
			r.Unresolved++
		} else {
			native := *v.NativeID
			if v.Kind == "telegram" {
				if v.AccountID == nil || v.PeerType == nil || *v.AccountID == "" || (*v.PeerType != "channel" && *v.PeerType != "chat" && *v.PeerType != "user") {
					return r, errors.New("resolved Telegram account and peer type required")
				}
				if peer, e := strconv.ParseInt(native, 10, 64); e != nil || peer <= 0 {
					return r, errors.New("Telegram native peer ID requires positive MTProto integer string")
				}
				if account, e := strconv.ParseInt(*v.AccountID, 10, 64); e != nil || account <= 0 {
					return r, errors.New("Telegram account ID requires positive integer string")
				}
				native = *v.AccountID + ":" + *v.PeerType + ":" + native
			}
			chosen := uuid.NewSHA1(uuid.NameSpaceOID, []byte(v.Kind+":"+native)).String()
			if v.SourceID != nil {
				chosen = *v.SourceID
			}
			if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,10))`, v.Kind+":"+native); e != nil {
				return r, e
			}
			var existing string
			e = tx.QueryRow(ctx, `SELECT id::text FROM noctis_v2.sources WHERE kind=$1 AND native_id=$2`, v.Kind, native).Scan(&existing)
			if e == nil {
				chosen = existing
				r.Preserved++
			} else if errors.Is(e, pgx.ErrNoRows) {
				var hasPolicy bool
				if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.policies WHERE version=$1)`, v.PolicyVersion).Scan(&hasPolicy); e != nil {
					return r, e
				}
				if !hasPolicy {
					return r, errors.New("manifest policy unavailable")
				}
				enabled := v.Disposition == "enabled"
				var activation *time.Time
				if enabled {
					now := time.Now().UTC()
					activation = &now
				}
				_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch,activated_at,coverage) VALUES($1,$2,$3,$4,$5,$6,$7,'unknown')`, chosen, v.Kind, native, v.PolicyVersion, enabled, uuid.NewString(), activation)
				if e != nil {
					return r, e
				}
				r.Created++
			} else {
				return r, e
			}
			id = &chosen
		}
		body, _ := json.Marshal(v)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.source_dispositions(identity,source_id,body) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, v.Identity, id, string(body)); e != nil {
			return r, e
		}
	}
	receipt, _ := json.Marshal(r)
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.source_imports(manifest_id,digest,manifest,receipt) VALUES($1,$2,$3,$4)`, m.ManifestID, r.Digest, string(raw), string(receipt)); e != nil {
		return r, e
	}
	if dryRun {
		return r, nil
	}
	return r, tx.Commit(ctx)
}

type HistoryRecord struct {
	ArchiveDigest  string          `json:"archive_digest"`
	Table          string          `json:"table"`
	LegacyID       string          `json:"legacy_id"`
	SourceID       string          `json:"source_id"`
	Text           string          `json:"text"`
	PublishedAt    *time.Time      `json:"published_at"`
	LegacyJudgment json.RawMessage `json:"legacy_judgment"`
}
type HistoryBatch struct {
	ImportedAt    time.Time          `json:"imported_at"`
	SourceID      string             `json:"source_id"`
	ArchiveDigest string             `json:"archive_digest"`
	Table         string             `json:"table"`
	Expected      capture.Checkpoint `json:"expected"`
	Next          capture.Checkpoint `json:"next"`
	Records       []HistoryRecord    `json:"records"`
}

func (s Store) ImportHistory(ctx context.Context, b HistoryBatch, dryRun bool) (capture.Receipt, error) {
	if b.ArchiveDigest == "" || b.Table == "" || strings.ContainsAny(b.Table, "\x00\n") || b.ImportedAt.IsZero() || b.ImportedAt.Location() != time.UTC {
		return capture.Receipt{}, errors.New("archive and table identity required")
	}
	epoch := uuid.NewSHA1(uuid.NameSpaceOID, []byte(b.ArchiveDigest+":"+b.Table+":"+b.SourceID)).String()
	raw, e := json.Marshal(b)
	if e != nil {
		return capture.Receipt{}, e
	}
	batchID := uuid.NewSHA1(uuid.NameSpaceOID, raw).String()
	batch := capture.Batch{BatchID: batchID, Version: "1", SourceID: b.SourceID, Epoch: epoch, Mode: capture.LegacyImport, Expected: b.Expected, Next: b.Next}
	now := b.ImportedAt
	for _, v := range b.Records {
		if v.ArchiveDigest != b.ArchiveDigest || v.Table != b.Table || v.SourceID != b.SourceID || v.LegacyID == "" || !json.Valid(v.LegacyJudgment) {
			return capture.Receipt{}, errors.New("history identity mismatch")
		}
		payload := []byte(v.Text)
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
		batch.Items = append(batch.Items, capture.Item{NativeID: "legacy:" + b.ArchiveDigest + ":" + b.Table + ":" + v.LegacyID, Revision: hash, Payload: payload, Hash: hash, Representation: "text/plain;utf8;v1", PublishedAt: v.PublishedAt, CollectedAt: now})
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return capture.Receipt{}, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return capture.Receipt{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,14))`, b.ArchiveDigest+":"+b.Table); e != nil {
		return capture.Receipt{}, e
	}
	for _, v := range b.Records {
		body, _ := json.Marshal(v)
		var prior []byte
		e = tx.QueryRow(ctx, `SELECT body FROM noctis_v2.legacy_records WHERE archive_digest=$1 AND table_name=$2 AND legacy_id=$3`, v.ArchiveDigest, v.Table, v.LegacyID).Scan(&prior)
		if e == nil {
			var same bool
			if e = tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, string(prior), string(body)).Scan(&same); e != nil {
				return capture.Receipt{}, e
			}
			if !same {
				return capture.Receipt{}, errors.New("legacy record identity conflict")
			}
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return capture.Receipt{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.legacy_records VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, v.ArchiveDigest, v.Table, v.LegacyID, v.SourceID, string(body)); e != nil {
			return capture.Receipt{}, e
		}
	}
	r, e := capture.CommitBatchTx(ctx, tx, batch)
	if e != nil {
		return capture.Receipt{}, e
	}
	if dryRun {
		return r, nil
	}
	return r, tx.Commit(ctx)
}
