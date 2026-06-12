#!/usr/bin/env python3
"""Training-set assembly (roadmap F1.8). Read-only against the DB.

Builds the stage-1 (relevant vs irrelevant) and stage-2 (6-class) datasets
from relabel_results.csv + raw_content, with the exclusions, dedup, temporal
split and IOC masking the roadmap mandates. Emits exactly the contract
train_baseline.py consumes.

Detected schema of relabel_results.csv (verified against the real file,
24,038 data rows): id, groq_category, model_category, model_severity,
model_confidence, protected ('0'/'1'), final_label, source, needs_review
('0'/'1'), content_snippet (200-char truncation). source values: agree
(4,311) | rules_protected (926) | downgrade (17,712) | reclassified (1,086)
| no_verdict_keep_groq (3 — the roadmap's "3 sin veredicto"). One
reclassified row carries final_label='third_party_reporting' (a provenance
value, not a class) — excluded with a warning.

Assembly rules (F1.8):
  - actionable: source in (agree, rules_protected); reclassified rows only
    with --include-reclassified (D9: excluded unless F1.2 adjudicates them);
    final_label must be one of the 6 classes.
  - irrelevant: original raw_content rows with category='irrelevant',
    classified=true and is_noise=false, PLUS the source='downgrade' rows.
  - excluded everywhere: ids in --gold-ids-file (gold is never trained on),
    the no_verdict_keep_groq rows, non-adjudicated needs_review rows,
    is_noise=true rows (junk belongs to the gate, not the model), and ids
    whose full content is missing from raw_content (the snippet is truncated
    — unusable for training).
  - exact dedup by content_hash BEFORE splitting (a duplicate shared between
    train and test invalidates the evaluation); earliest collected_at wins.
  - temporal split by collected_at: oldest 80% train / 10% val / newest 10%
    test, computed once on the stage-1 corpus; stage-2 rows inherit their
    stage-1 split so the two stages can never leak across each other.
  - text = mask_iocs(content)  (F1.9 — the ONE shared masker; the same
    function must run at inference). language = textlang.detect_script on
    the RAW content (mask tokens are Latin and would skew the heuristic).

Outputs in --out-dir: stage1.parquet, stage2.parquet (columns: id, text,
label, language, split, content_hash, collected_at) and stats.json (class
counts per split, language distribution, exclusion accounting).

The DSN comes from --dsn or NOCTIS_DB_DSN. --dry-run reports the CSV-side
plan (populations and exclusions known without the DB) and writes nothing.

Examples:
    export NOCTIS_DB_DSN="postgres://noctis:PASS@localhost:5432/noctis?sslmode=disable"

    # standard build (gold ids file is REQUIRED — gold never enters training)
    python3 tools/build_dataset.py --gold-ids-file tools/data/gold_set.csv \\
        --out-dir tools/out/dataset

    # after F1.2 adjudication validated the reclassified rows
    python3 tools/build_dataset.py --gold-ids-file tools/data/gold_set.csv \\
        --out-dir tools/out/dataset --include-reclassified

    # CSV-side plan only, no DB, no files
    python3 tools/build_dataset.py --gold-ids-file tools/data/gold_set.csv \\
        --out-dir /tmp/x --dry-run
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

from mask_iocs import mask_iocs
from textlang import detect_script

DEFAULT_CSV = Path("tools/data/relabel_results.csv")

SIX_CLASSES = ("threat_actor_comms", "vulnerability", "data_dump",
               "malware_sample", "access_broker", "credential_leak")
TRUSTED_SOURCES = ("agree", "rules_protected")
SPLIT_FRACTIONS = (0.8, 0.1)  # train, val; test = remainder
CONTRACT_COLUMNS = ["id", "text", "label", "language", "split",
                    "content_hash", "collected_at"]

EXPECTED_COLUMNS = {
    "id", "groq_category", "model_category", "model_severity",
    "model_confidence", "protected", "final_label", "source",
    "needs_review", "content_snippet",
}


def load_relabel_csv(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"relabel CSV not found: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = EXPECTED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(
                f"{path}: header mismatch, missing columns {sorted(missing)} "
                f"(got: {reader.fieldnames})")
        return list(reader)


def load_gold_ids(path: Path) -> set[str]:
    """Gold-set ids: a CSV with an 'id' column, or one bare id per line."""
    if not path.exists():
        raise SystemExit(
            f"gold ids file not found: {path} — the gold set must exist "
            "before any training data is assembled (F1.7); refusing to run")
    with path.open(newline="", encoding="utf-8") as f:
        first = f.readline()
        f.seek(0)
        if "id" in [c.strip().lower() for c in first.split(",")]:
            return {r["id"].strip() for r in csv.DictReader(f) if r.get("id")}
        return {line.strip() for line in f if line.strip()}


def plan_from_csv(rows: list[dict], include_reclassified: bool) -> dict:
    """CSV-side selection + exclusion accounting (no DB needed)."""
    plan = {"actionable": [], "downgrades": [], "excluded": Counter()}
    for r in rows:
        src = r["source"]
        if src == "no_verdict_keep_groq":
            plan["excluded"]["no_verdict"] += 1
            continue
        if src == "downgrade":
            plan["downgrades"].append(r)
            continue
        if src == "reclassified" or r["needs_review"].strip() == "1":
            if not include_reclassified:
                plan["excluded"]["needs_review_not_adjudicated"] += 1
                continue
        elif src not in TRUSTED_SOURCES:
            plan["excluded"][f"unknown_source:{src}"] += 1
            continue
        if r["final_label"] not in SIX_CLASSES:
            print(f"warning: excluding id {r['id']}: final_label "
                  f"{r['final_label']!r} is not one of the 6 classes",
                  file=sys.stderr)
            plan["excluded"]["final_label_not_a_class"] += 1
            continue
        plan["actionable"].append(r)
    return plan


def fetch_csv_row_meta(dsn: str, ids: list[str]) -> dict[str, dict]:
    """content/content_hash/collected_at/is_noise for the CSV ids (SELECT only)."""
    return _query(dsn, """
        SELECT id, COALESCE(content, ''), content_hash, collected_at,
               COALESCE(is_noise, false)
        FROM raw_content WHERE id = ANY(%s::uuid[])""", (ids,))


def fetch_original_irrelevant(dsn: str) -> dict[str, dict]:
    """Original irrelevant rows, junk already excluded (SELECT only)."""
    return _query(dsn, """
        SELECT id, COALESCE(content, ''), content_hash, collected_at, false
        FROM raw_content
        WHERE classified = true AND category = 'irrelevant'
          AND COALESCE(is_noise, false) = false""", ())


def _query(dsn: str, sql: str, params) -> dict[str, dict]:
    try:
        import psycopg
    except ImportError:
        raise SystemExit('psycopg missing — pip install "psycopg[binary]" '
                         "(see tools/requirements.txt)")
    if not dsn:
        raise SystemExit("no DSN: pass --dsn or set NOCTIS_DB_DSN")
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        try:
            cur.execute(sql, params)
        except psycopg.errors.UndefinedColumn as e:
            raise SystemExit(
                f"{e} — is_noise missing? Run the noise flagging first: "
                "python tools/noctis_rules.py --flag --apply")
        return {str(r[0]): {"content": r[1], "content_hash": r[2],
                            "collected_at": r[3], "is_noise": r[4]}
                for r in cur.fetchall()}


def assemble(plan: dict, gold_ids: set[str], csv_meta: dict[str, dict],
             originals: dict[str, dict]) -> tuple[pd.DataFrame, dict]:
    """Stage-1 dataframe (with stage-2 labels carried along) + stats."""
    excluded = plan["excluded"]
    rows = []

    def add(rid: str, meta: dict, label: str, stage2_label: str | None):
        if rid in gold_ids:
            excluded["gold_set"] += 1
            return
        if meta is None:
            excluded["content_missing_in_db"] += 1
            return
        if meta["is_noise"]:
            excluded["is_noise"] += 1
            return
        if not meta["content"].strip():
            excluded["empty_content"] += 1
            return
        rows.append({
            "id": rid,
            "content": meta["content"],
            "label": label,
            "stage2_label": stage2_label,
            "content_hash": meta["content_hash"],
            "collected_at": meta["collected_at"],
        })

    for r in plan["actionable"]:
        add(r["id"], csv_meta.get(r["id"]), "relevant", r["final_label"])
    for r in plan["downgrades"]:
        add(r["id"], csv_meta.get(r["id"]), "irrelevant", None)
    for rid, meta in originals.items():
        add(rid, meta, "irrelevant", None)

    df = pd.DataFrame(rows)
    if df.empty:
        raise SystemExit("nothing left to train on after exclusions")

    # Exact dedup by content_hash BEFORE splitting; earliest occurrence wins.
    df = df.sort_values(["collected_at", "id"]).reset_index(drop=True)
    dupe_mask = df.duplicated(subset="content_hash", keep="first")
    label_conflicts = int(
        df[df.duplicated(subset="content_hash", keep=False)]
        .groupby("content_hash")["label"].nunique().gt(1).sum())
    excluded["dedup_content_hash"] += int(dupe_mask.sum())
    df = df[~dupe_mask].reset_index(drop=True)

    # Temporal split on the already collected_at-sorted frame.
    n = len(df)
    n_train = int(n * SPLIT_FRACTIONS[0])
    n_val = int(n * SPLIT_FRACTIONS[1])
    df["split"] = (["train"] * n_train + ["val"] * n_val
                   + ["test"] * (n - n_train - n_val))

    df["text"] = df["content"].map(mask_iocs)
    df["language"] = df["content"].map(detect_script)

    stats = {
        "rows_after_dedup": n,
        "label_conflicting_duplicate_hashes": label_conflicts,
        "excluded": dict(excluded),
    }
    return df.drop(columns=["content"]), stats


def split_stats(df: pd.DataFrame) -> dict:
    out = {}
    for split in ("train", "val", "test"):
        part = df[df["split"] == split]
        out[split] = {
            "rows": len(part),
            "classes": part["label"].value_counts().to_dict(),
            "languages": part["language"].value_counts().to_dict(),
        }
    return out


def write_outputs(df: pd.DataFrame, stats: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    stage1 = df[CONTRACT_COLUMNS].copy()
    stage2 = df[df["label"] == "relevant"].copy()
    stage2["label"] = stage2["stage2_label"]
    stage2 = stage2[CONTRACT_COLUMNS]

    stage1.to_parquet(out_dir / "stage1.parquet", index=False)
    stage2.to_parquet(out_dir / "stage2.parquet", index=False)

    stats["stage1"] = split_stats(stage1)
    stats["stage2"] = split_stats(stage2)
    (out_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Assemble stage-1/stage-2 training datasets (F1.8). "
                    "Read-only: never writes to the DB.",
        epilog=__doc__.split("Examples:")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV,
                    help=f"relabel results CSV (default {DEFAULT_CSV})")
    ap.add_argument("--gold-ids-file", type=Path, required=True,
                    help="file with gold-set ids (CSV with an 'id' column, "
                         "or one id per line); REQUIRED — gold never trains")
    ap.add_argument("--out-dir", type=Path, required=True,
                    help="output directory for parquet files + stats.json")
    ap.add_argument("--include-reclassified", action="store_true",
                    help="include source=reclassified rows (only after F1.2 "
                         "adjudication validates them; default: excluded)")
    ap.add_argument("--dsn", default=os.environ.get("NOCTIS_DB_DSN"),
                    help="Postgres DSN (default: NOCTIS_DB_DSN env var)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the CSV-side plan; no DB, no files")
    args = ap.parse_args(argv)

    rows = load_relabel_csv(args.csv)
    gold_ids = load_gold_ids(args.gold_ids_file)
    plan = plan_from_csv(rows, args.include_reclassified)

    print(f"CSV plan: {len(plan['actionable'])} actionable, "
          f"{len(plan['downgrades'])} downgrades, "
          f"excluded so far: {dict(plan['excluded'])}, "
          f"gold ids to exclude: {len(gold_ids)}")
    if args.dry_run:
        print("dry-run: would fetch full content for "
              f"{len(plan['actionable']) + len(plan['downgrades'])} CSV ids "
              "plus all original irrelevant rows (is_noise=false) from "
              f"raw_content, then write stage1.parquet / stage2.parquet / "
              f"stats.json to {args.out_dir} — no DB touched, nothing written")
        return 0

    csv_ids = [r["id"] for r in plan["actionable"] + plan["downgrades"]]
    csv_meta = fetch_csv_row_meta(args.dsn, csv_ids)
    originals = fetch_original_irrelevant(args.dsn)
    print(f"DB: {len(csv_meta)} CSV ids resolved, "
          f"{len(originals)} original irrelevant rows")

    df, stats = assemble(plan, gold_ids, csv_meta, originals)
    stats["config"] = {"include_reclassified": args.include_reclassified,
                       "split_fractions": [0.8, 0.1, 0.1],
                       "gold_ids": len(gold_ids)}
    write_outputs(df, stats, args.out_dir)

    s1, s2 = stats["stage1"], stats["stage2"]
    print("stage1 rows:", {k: v["rows"] for k, v in s1.items()})
    print("stage2 rows:", {k: v["rows"] for k, v in s2.items()})
    print(f"exclusions: {stats['excluded']}")
    print(f"datasets written to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
