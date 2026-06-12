"""Unit tests for build_dataset.py on synthetic fixtures.

No DB: csv_meta and originals are injected as plain dicts, exactly the shape
the psycopg fetchers return. Exercises the F1.8 rules end to end: exclusions,
dedup, temporal split, masking, and the parquet contract.
"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from build_dataset import (
    assemble,
    load_gold_ids,
    main,
    plan_from_csv,
    write_outputs,
    CONTRACT_COLUMNS,
    SIX_CLASSES,
)

T0 = datetime(2025, 6, 1, tzinfo=timezone.utc)


def mk_csv_row(rid, groq, final, source, needs="0"):
    return {"id": rid, "groq_category": groq, "model_category": final,
            "model_severity": "info", "model_confidence": "0.9",
            "protected": "0", "final_label": final, "source": source,
            "needs_review": needs, "content_snippet": "snip"}


def build_fixture():
    """Synthetic CSV rows + injected DB metadata mirroring the real quirks."""
    csv_rows, csv_meta = [], {}
    clock = iter(range(10_000))

    def meta(rid, content, content_hash=None, is_noise=False, at=None):
        csv_meta[rid] = {
            "content": content,
            "content_hash": content_hash or f"hash-{rid}",
            "collected_at": at or (T0 + timedelta(days=next(clock))),
            "is_noise": is_noise,
        }

    for i in range(12):
        rid = f"agree-{i}"
        csv_rows.append(mk_csv_row(rid, "vulnerability", "vulnerability", "agree"))
        meta(rid, f"эксплойт {i} сканируй 91.92.93.94 срочно эксплуатация")
    for i in range(6):
        rid = f"prot-{i}"
        csv_rows.append(mk_csv_row(rid, "credential_leak", "credential_leak",
                                   "rules_protected"))
        meta(rid, f"слив учеток номер {i} mark{i}:opensesame{i} продажа")
    for i in range(4):
        rid = f"recl-{i}"
        csv_rows.append(mk_csv_row(rid, "malware_sample", "data_dump",
                                   "reclassified", needs="1"))
        meta(rid, f"дамп базы данных архив номер {i} для скачивания")
    # the real file's three quirks:
    csv_rows.append(mk_csv_row("noverdict-0", "access_broker", "access_broker",
                               "no_verdict_keep_groq", needs="1"))
    meta("noverdict-0", "без вердикта")
    csv_rows.append(mk_csv_row("tpr-0", "threat_actor_comms",
                               "third_party_reporting", "reclassified",
                               needs="1"))
    meta("tpr-0", "репост новости про группировку")
    for i in range(20):
        rid = f"down-{i}"
        csv_rows.append(mk_csv_row(rid, "threat_actor_comms", "irrelevant",
                                   "downgrade"))
        meta(rid, f"болтовня в канале номер {i} ни о чем вообще")
    # exclusion cases:
    csv_rows.append(mk_csv_row("gold-1", "vulnerability", "vulnerability", "agree"))
    meta("gold-1", "этот ряд в голд сете")
    csv_rows.append(mk_csv_row("noise-1", "data_dump", "data_dump", "agree"))
    meta("noise-1", "мусорная строка", is_noise=True)
    csv_rows.append(mk_csv_row("missing-1", "data_dump", "data_dump", "agree"))
    # missing-1 deliberately gets NO meta (absent from raw_content)
    # duplicate content_hash pair — later one must be dropped:
    csv_rows.append(mk_csv_row("dupA", "threat_actor_comms", "irrelevant",
                               "downgrade"))
    meta("dupA", "дубликат текст", content_hash="hash-dup")
    csv_rows.append(mk_csv_row("dupB", "threat_actor_comms", "irrelevant",
                               "downgrade"))
    meta("dupB", "дубликат текст", content_hash="hash-dup")

    originals = {}
    for i in range(20):
        rid = f"orig-{i}"
        originals[rid] = {
            "content": f"обычный чат про погоду и мемы номер {i}",
            "content_hash": f"hash-{rid}",
            "collected_at": T0 + timedelta(days=next(clock)),
            "is_noise": False,
        }
    return csv_rows, csv_meta, originals


class TestPlanFromCsv(unittest.TestCase):
    def test_default_excludes_reclassified_and_no_verdict(self):
        csv_rows, _, _ = build_fixture()
        plan = plan_from_csv(csv_rows, include_reclassified=False)
        ids = {r["id"] for r in plan["actionable"]}
        self.assertNotIn("recl-0", ids)
        self.assertNotIn("noverdict-0", ids)
        self.assertEqual(plan["excluded"]["no_verdict"], 1)
        # 4 reclassified + the third_party_reporting row (also reclassified)
        self.assertEqual(plan["excluded"]["needs_review_not_adjudicated"], 5)
        self.assertEqual(len(plan["downgrades"]), 22)  # 20 + dupA + dupB

    def test_include_reclassified_keeps_them_but_not_bad_labels(self):
        csv_rows, _, _ = build_fixture()
        plan = plan_from_csv(csv_rows, include_reclassified=True)
        ids = {r["id"] for r in plan["actionable"]}
        self.assertIn("recl-0", ids)
        self.assertNotIn("tpr-0", ids)  # not one of the 6 classes
        self.assertEqual(plan["excluded"]["final_label_not_a_class"], 1)


class TestAssemble(unittest.TestCase):
    def run_assemble(self, include_reclassified=False):
        csv_rows, csv_meta, originals = build_fixture()
        plan = plan_from_csv(csv_rows, include_reclassified)
        return assemble(plan, {"gold-1"}, csv_meta, originals)

    def test_exclusion_accounting(self):
        _, stats = self.run_assemble()
        ex = stats["excluded"]
        self.assertEqual(ex["gold_set"], 1)
        self.assertEqual(ex["is_noise"], 1)
        self.assertEqual(ex["content_missing_in_db"], 1)
        self.assertEqual(ex["dedup_content_hash"], 1)

    def test_dedup_keeps_earliest(self):
        df, _ = self.run_assemble()
        dup = df[df["content_hash"] == "hash-dup"]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup.iloc[0]["id"], "dupA")  # earlier collected_at

    def test_temporal_split_is_ordered(self):
        df, _ = self.run_assemble()
        self.assertEqual(set(df["split"]), {"train", "val", "test"})
        t = df[df["split"] == "train"]["collected_at"].max()
        v0 = df[df["split"] == "val"]["collected_at"].min()
        v1 = df[df["split"] == "val"]["collected_at"].max()
        e = df[df["split"] == "test"]["collected_at"].min()
        self.assertLessEqual(t, v0)
        self.assertLessEqual(v1, e)

    def test_masking_and_language(self):
        df, _ = self.run_assemble()
        row = df[df["id"] == "agree-0"].iloc[0]
        self.assertIn("<IP>", row["text"])
        self.assertNotIn("91.92.93.94", row["text"])
        self.assertEqual(row["language"], "cyrillic")
        cred = df[df["id"] == "prot-0"].iloc[0]
        self.assertIn("<CRED>", cred["text"])

    def test_labels(self):
        df, _ = self.run_assemble()
        self.assertEqual(set(df["label"]), {"relevant", "irrelevant"})
        relevant = df[df["label"] == "relevant"]
        self.assertTrue(set(relevant["stage2_label"]) <= set(SIX_CLASSES))


class TestOutputs(unittest.TestCase):
    def test_parquet_contract_and_stats(self):
        csv_rows, csv_meta, originals = build_fixture()
        plan = plan_from_csv(csv_rows, include_reclassified=False)
        df, stats = assemble(plan, {"gold-1"}, csv_meta, originals)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_outputs(df, stats, out)

            s1 = pd.read_parquet(out / "stage1.parquet")
            s2 = pd.read_parquet(out / "stage2.parquet")
            self.assertEqual(list(s1.columns), CONTRACT_COLUMNS)
            self.assertEqual(list(s2.columns), CONTRACT_COLUMNS)
            self.assertEqual(set(s1["label"]), {"relevant", "irrelevant"})
            self.assertTrue(set(s2["label"]) <= set(SIX_CLASSES))
            self.assertEqual(len(s2), len(s1[s1["label"] == "relevant"]))

            st = json.loads((out / "stats.json").read_text())
            for key in ("rows_after_dedup", "excluded", "stage1", "stage2"):
                self.assertIn(key, st)
            self.assertEqual(
                st["stage1"]["train"]["rows"]
                + st["stage1"]["val"]["rows"]
                + st["stage1"]["test"]["rows"],
                st["rows_after_dedup"])


class TestRefusals(unittest.TestCase):
    def test_missing_gold_file_refuses(self):
        with self.assertRaises(SystemExit) as ctx:
            load_gold_ids(Path("/nonexistent/gold.csv"))
        self.assertIn("refusing", str(ctx.exception))

    def test_gold_ids_both_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            as_csv = Path(tmp) / "gold.csv"
            as_csv.write_text("id,label\ng1,x\ng2,y\n", encoding="utf-8")
            self.assertEqual(load_gold_ids(as_csv), {"g1", "g2"})
            as_lines = Path(tmp) / "gold.txt"
            as_lines.write_text("g3\ng4\n\n", encoding="utf-8")
            self.assertEqual(load_gold_ids(as_lines), {"g3", "g4"})

    def test_dry_run_needs_no_db(self):
        csv_rows, _, _ = build_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "relabel.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                import csv as csvmod
                w = csvmod.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
                w.writeheader()
                w.writerows(csv_rows)
            gold = Path(tmp) / "gold.txt"
            gold.write_text("gold-1\n", encoding="utf-8")

            rc = main(["--csv", str(csv_path), "--gold-ids-file", str(gold),
                       "--out-dir", str(Path(tmp) / "out"), "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertFalse((Path(tmp) / "out").exists())


if __name__ == "__main__":
    unittest.main()
