#!/usr/bin/env python3
"""Relabel validation worksheets + error-rate summary (roadmap F1.1–F1.4).

Reads tools/data/relabel_results.csv, joins it against raw_content by id to
pull the FULL content (the CSV's content_snippet is a 200-char truncation —
unusable for adjudication), and writes manual-review worksheets. Strictly
read-only: the database is only ever SELECTed, never written.

Detected schema of relabel_results.csv (verified against the real file,
24,038 data rows):

    id                UUID into raw_content
    groq_category     original Groq label            -> worksheet old_label
    model_category    Flash-Lite judge label
    model_severity    judge severity
    model_confidence  judge confidence (0..1)
    protected         rules-layer veto flag ('0'/'1')
    final_label       decided label                  -> worksheet new_label
    source            decision source                -> worksheet decision_source
                      one of: agree (4,311) | rules_protected (926) |
                      downgrade (17,712) | reclassified (1,086) |
                      no_verdict_keep_groq (3)
    needs_review      '0'/'1' (1,089 ones = reclassified + the 3 no-verdict)
    content_snippet   200-char truncation of content (fallback only)

Known data quirks (real file): one reclassified row carries
final_label='third_party_reporting' (a provenance value, not a class);
credential exits number 133 (82 downgraded to irrelevant — the roadmap's
"~83" — plus 51 cross-reclassified).

Worksheet columns: id, content, old_label, new_label, decision_source,
verdict (empty — you fill: ok / wrong / unsure), notes (empty).

DSN comes from --dsn or the NOCTIS_DB_DSN environment variable. --dry-run
prints what would be exported without touching the DB or writing files.
summarize needs no DB at all.

Examples:
    export NOCTIS_DB_DSN="postgres://noctis:PASS@localhost:5432/noctis?sslmode=disable"

    # F1.1 — every row that left credential_leak (all of them, no sampling)
    python3 tools/validate_relabel.py credential-exits

    # F1.2 — 30 random needs_review/reclassified rows, fixed seed
    python3 tools/validate_relabel.py needs-review-sample --n 30 --seed 42

    # F1.3 — 50 random downgrades
    python3 tools/validate_relabel.py downgrade-sample --n 50

    # preview without DB or files
    python3 tools/validate_relabel.py downgrade-sample --dry-run

    # F1.4 — error rates for validation_report.md (no DB needed)
    python3 tools/validate_relabel.py summarize tools/data/review_*.csv
"""

import argparse
import csv
import os
import random
import sys
from collections import Counter
from pathlib import Path

DEFAULT_CSV = Path("tools/data/relabel_results.csv")
DEFAULT_OUT_DIR = Path("tools/data")

EXPECTED_COLUMNS = {
    "id", "groq_category", "model_category", "model_severity",
    "model_confidence", "protected", "final_label", "source",
    "needs_review", "content_snippet",
}
WORKSHEET_COLUMNS = ("id", "content", "old_label", "new_label",
                     "decision_source", "verdict", "notes")

# Verdict normalisation for summarize. Anything else counts as "other" and
# is listed so typos don't silently vanish from the error rate.
VERDICT_CORRECT = {"ok", "correct", "good", "right", "agree", "valid"}
VERDICT_ERROR = {"wrong", "error", "bad", "incorrect", "miss", "fail"}
VERDICT_UNSURE = {"unsure", "unclear", "?", "dunno", "maybe"}


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


def select_credential_exits(rows: list[dict]) -> list[dict]:
    """F1.1: every row whose label LEFT credential_leak."""
    return [r for r in rows
            if r["groq_category"] == "credential_leak"
            and r["final_label"] != "credential_leak"]


def select_needs_review(rows: list[dict]) -> list[dict]:
    """F1.2 population: flagged needs_review or cross-reclassified."""
    return [r for r in rows
            if r["needs_review"].strip() == "1" or r["source"] == "reclassified"]


def select_downgrades(rows: list[dict]) -> list[dict]:
    """F1.3 population: downgraded to irrelevant."""
    return [r for r in rows if r["source"] == "downgrade"]


def sample_rows(rows: list[dict], n: int, seed: int) -> list[dict]:
    """Deterministic sample of n rows (all of them when n >= population)."""
    if n >= len(rows):
        return list(rows)
    return random.Random(seed).sample(rows, n)


def fetch_contents(dsn: str, ids: list[str]) -> dict[str, str]:
    """Full content for the given raw_content ids. Read-only SELECT."""
    try:
        import psycopg
    except ImportError:
        raise SystemExit('psycopg missing — pip install "psycopg[binary]" '
                         "(see tools/requirements.txt)")
    if not dsn:
        raise SystemExit("no DSN: pass --dsn or set NOCTIS_DB_DSN")
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, COALESCE(content, '') FROM raw_content "
            "WHERE id = ANY(%s::uuid[])", (ids,))
        return {str(fid): content for fid, content in cur.fetchall()}


def build_worksheet(selected: list[dict], contents: dict[str, str]) -> list[dict]:
    """Map CSV rows + full contents into review-worksheet rows."""
    missing = 0
    out = []
    for r in selected:
        content = contents.get(r["id"])
        if content is None or not content.strip():
            # Fall back to the 200-char snippet rather than dropping the row:
            # a truncated review beats a silent hole in the sample.
            content = r["content_snippet"]
            missing += 1
        out.append({
            "id": r["id"],
            "content": content,
            "old_label": r["groq_category"],
            "new_label": r["final_label"],
            "decision_source": r["source"],
            "verdict": "",
            "notes": "",
        })
    if missing:
        print(f"warning: {missing} id(s) had no content in raw_content; "
              "wrote the 200-char snippet instead", file=sys.stderr)
    return out


def write_worksheet(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=WORKSHEET_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def export(selected: list[dict], out_path: Path, args, label: str) -> None:
    """Shared dry-run / fetch / write tail of the three export subcommands."""
    print(f"{label}: {len(selected)} row(s) selected")
    if args.dry_run:
        print(f"dry-run: would join {len(selected)} id(s) against raw_content "
              f"and write {out_path} — no DB touched, nothing written")
        return
    contents = fetch_contents(args.dsn, [r["id"] for r in selected])
    write_worksheet(out_path, build_worksheet(selected, contents))
    print(f"worksheet written: {out_path} "
          f"(fill the 'verdict' column: ok / wrong / unsure)")


def classify_verdict(raw: str) -> str:
    v = raw.strip().lower()
    if not v:
        return "pending"
    if v in VERDICT_CORRECT:
        return "correct"
    if v in VERDICT_ERROR:
        return "error"
    if v in VERDICT_UNSURE:
        return "unsure"
    return "other"


def summarize_sheet(path: Path) -> dict:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    counts = Counter(classify_verdict(r.get("verdict", "")) for r in rows)
    others = sorted({r["verdict"].strip() for r in rows
                     if classify_verdict(r.get("verdict", "")) == "other"})
    adjudicated = counts["correct"] + counts["error"] + counts["unsure"]
    return {
        "sheet": path.name,
        "rows": len(rows),
        "adjudicated": adjudicated,
        "correct": counts["correct"],
        "error": counts["error"],
        "unsure": counts["unsure"],
        "pending": counts["pending"],
        "other_verdicts": others,
        "error_rate": (counts["error"] / adjudicated) if adjudicated else None,
    }


def cmd_summarize(paths: list[Path]) -> None:
    """Markdown table ready to paste into validation_report.md (F1.4)."""
    print("| sheet | rows | adjudicated | errors | unsure | pending | error rate |")
    print("|---|---|---|---|---|---|---|")
    for path in paths:
        s = summarize_sheet(path)
        rate = f"{s['error_rate']:.1%}" if s["error_rate"] is not None else "—"
        print(f"| {s['sheet']} | {s['rows']} | {s['adjudicated']} | "
              f"{s['error']} | {s['unsure']} | {s['pending']} | {rate} |")
        if s["other_verdicts"]:
            print(f"|   ^ unrecognised verdict values: "
                  f"{', '.join(s['other_verdicts'])} | | | | | | |")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Manual-review worksheets for the relabel validation "
                    "(F1.1–F1.4). Read-only: never writes to the DB.",
        epilog=__doc__.split("Examples:")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Shared flags live on the subcommands (not the top level) so they can be
    # written after the subcommand name, as in the examples above.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--csv", type=Path, default=DEFAULT_CSV,
                        help=f"relabel results CSV (default {DEFAULT_CSV})")
    common.add_argument("--dsn", default=os.environ.get("NOCTIS_DB_DSN"),
                        help="Postgres DSN (default: NOCTIS_DB_DSN env var)")
    common.add_argument("--dry-run", action="store_true",
                        help="report what would be done; no DB, no files")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("credential-exits", parents=[common],
                       help="F1.1: all rows that left credential_leak")
    p.add_argument("--out", type=Path,
                   default=DEFAULT_OUT_DIR / "review_credential_exits.csv")

    p = sub.add_parser("needs-review-sample", parents=[common],
                       help="F1.2: sample of needs_review/reclassified rows")
    p.add_argument("--n", type=int, default=30, help="sample size (default 30)")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default 42)")
    p.add_argument("--out", type=Path,
                   default=DEFAULT_OUT_DIR / "review_needs_review_sample.csv")

    p = sub.add_parser("downgrade-sample", parents=[common],
                       help="F1.3: sample of rows downgraded to irrelevant")
    p.add_argument("--n", type=int, default=50, help="sample size (default 50)")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default 42)")
    p.add_argument("--out", type=Path,
                   default=DEFAULT_OUT_DIR / "review_downgrade_sample.csv")

    p = sub.add_parser("summarize",
                       help="F1.4: error rates from filled-in worksheets")
    p.add_argument("sheets", nargs="+", type=Path,
                   help="filled review CSVs")

    args = ap.parse_args(argv)

    if args.command == "summarize":
        cmd_summarize(args.sheets)
        return 0

    rows = load_relabel_csv(args.csv)
    if args.command == "credential-exits":
        export(select_credential_exits(rows), args.out, args,
               "credential exits (groq=credential_leak -> anything else)")
    elif args.command == "needs-review-sample":
        population = select_needs_review(rows)
        print(f"needs_review/reclassified population: {len(population)}")
        export(sample_rows(population, args.n, args.seed), args.out, args,
               f"needs-review sample (n={args.n}, seed={args.seed})")
    elif args.command == "downgrade-sample":
        population = select_downgrades(rows)
        print(f"downgrade population: {len(population)}")
        export(sample_rows(population, args.n, args.seed), args.out, args,
               f"downgrade sample (n={args.n}, seed={args.seed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
