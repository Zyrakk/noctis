"""Unit tests for validate_relabel.py on synthetic fixtures. No DB, pure stdlib."""

import csv
import tempfile
import unittest
from pathlib import Path

from validate_relabel import (
    build_worksheet,
    classify_verdict,
    load_relabel_csv,
    sample_rows,
    select_credential_exits,
    select_downgrades,
    select_needs_review,
    summarize_sheet,
    write_worksheet,
    EXPECTED_COLUMNS,
    WORKSHEET_COLUMNS,
)


def mk(rid, groq, final, source, needs="0", snippet="snippet text"):
    return {"id": rid, "groq_category": groq, "model_category": final,
            "model_severity": "info", "model_confidence": "0.9",
            "protected": "0", "final_label": final, "source": source,
            "needs_review": needs, "content_snippet": snippet}


FIXTURE = [
    mk("a1", "credential_leak", "irrelevant", "downgrade"),
    mk("a2", "credential_leak", "data_dump", "reclassified", needs="1"),
    mk("a3", "credential_leak", "credential_leak", "agree"),
    mk("b1", "threat_actor_comms", "irrelevant", "downgrade"),
    mk("b2", "threat_actor_comms", "irrelevant", "downgrade"),
    mk("c1", "vulnerability", "vulnerability", "agree"),
    mk("c2", "malware_sample", "data_dump", "reclassified", needs="1"),
    mk("d1", "access_broker", "access_broker", "no_verdict_keep_groq", needs="1"),
]


class TestSelections(unittest.TestCase):
    def test_credential_exits(self):
        ids = {r["id"] for r in select_credential_exits(FIXTURE)}
        self.assertEqual(ids, {"a1", "a2"})  # a3 stayed in the class

    def test_needs_review_union(self):
        # reclassified rows plus any needs_review=1 (covers the no-verdict
        # rows, which are flagged needs_review in the real file).
        ids = {r["id"] for r in select_needs_review(FIXTURE)}
        self.assertEqual(ids, {"a2", "c2", "d1"})

    def test_downgrades(self):
        ids = {r["id"] for r in select_downgrades(FIXTURE)}
        self.assertEqual(ids, {"a1", "b1", "b2"})


class TestSampling(unittest.TestCase):
    def test_deterministic_with_seed(self):
        pop = select_downgrades(FIXTURE)
        s1 = sample_rows(pop, 2, seed=42)
        s2 = sample_rows(pop, 2, seed=42)
        self.assertEqual([r["id"] for r in s1], [r["id"] for r in s2])
        self.assertEqual(len(s1), 2)

    def test_n_larger_than_population_takes_all(self):
        pop = select_downgrades(FIXTURE)
        self.assertEqual(len(sample_rows(pop, 500, seed=1)), len(pop))


class TestWorksheet(unittest.TestCase):
    def test_mapping_and_snippet_fallback(self):
        selected = select_credential_exits(FIXTURE)
        contents = {"a1": "полный текст слива с логином mark:opensesame"}
        ws = build_worksheet(selected, contents)  # a2 missing from "DB"

        self.assertEqual([tuple(r.keys()) for r in ws],
                         [WORKSHEET_COLUMNS] * 2)
        by_id = {r["id"]: r for r in ws}
        self.assertEqual(by_id["a1"]["content"],
                         "полный текст слива с логином mark:opensesame")
        self.assertEqual(by_id["a1"]["old_label"], "credential_leak")
        self.assertEqual(by_id["a1"]["new_label"], "irrelevant")
        self.assertEqual(by_id["a1"]["decision_source"], "downgrade")
        self.assertEqual(by_id["a1"]["verdict"], "")
        self.assertEqual(by_id["a1"]["notes"], "")
        # missing content falls back to the 200-char snippet
        self.assertEqual(by_id["a2"]["content"], "snippet text")

    def test_write_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ws.csv"
            write_worksheet(path, build_worksheet(FIXTURE[:1], {}))
            with path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(tuple(rows[0].keys()), WORKSHEET_COLUMNS)


class TestCsvLoading(unittest.TestCase):
    def test_header_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("id,oldlabel\nx,y\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                load_relabel_csv(path)
            self.assertIn("header mismatch", str(ctx.exception))

    def test_real_header_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ok.csv"
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=sorted(EXPECTED_COLUMNS))
                w.writeheader()
                w.writerow(mk("x1", "vulnerability", "vulnerability", "agree"))
            self.assertEqual(len(load_relabel_csv(path)), 1)


class TestSummarize(unittest.TestCase):
    def test_verdict_normalisation(self):
        self.assertEqual(classify_verdict("OK"), "correct")
        self.assertEqual(classify_verdict(" wrong "), "error")
        self.assertEqual(classify_verdict("unsure"), "unsure")
        self.assertEqual(classify_verdict(""), "pending")
        self.assertEqual(classify_verdict("weird"), "other")

    def test_error_rate_math(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "filled.csv"
            rows = build_worksheet(FIXTURE[:6], {})
            for row, verdict in zip(rows, ["ok", "ok", "wrong", "unsure",
                                           "", "weird"]):
                row["verdict"] = verdict
            write_worksheet(path, rows)

            s = summarize_sheet(path)
            self.assertEqual(s["rows"], 6)
            self.assertEqual(s["adjudicated"], 4)  # correct+error+unsure
            self.assertEqual(s["error"], 1)
            self.assertEqual(s["pending"], 1)
            self.assertEqual(s["other_verdicts"], ["weird"])
            self.assertAlmostEqual(s["error_rate"], 0.25)


if __name__ == "__main__":
    unittest.main()
