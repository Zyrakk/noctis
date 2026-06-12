"""End-to-end test for train_baseline.py on synthetic parquet fixtures.

No DB needed: builds a small separable bilingual corpus in a temp dir, runs
the full training entrypoint, and checks artifacts, the gate's recall
constraint, and that accuracy is never reported.
"""

import json
import random
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from train_baseline import main

ACTIONABLE = {
    "threat_actor_comms": ["группировка взяла ответственность за атаку",
                           "actor claims responsibility for the breach"],
    "vulnerability": ["эксплойт для уязвимости в продукте вендора",
                      "proof of concept exploit for enterprise firewall"],
    "data_dump": ["дамп базы данных клиентов магазина",
                  "full customer database dump for download"],
    "malware_sample": ["новый стилер билд с обходом антивируса",
                       "fresh stealer build with antivirus bypass"],
    "access_broker": ["продаю доступ к сети компании через RDP",
                      "selling corporate network access via vpn"],
    "credential_leak": ["слив учетных записей с паролями сотрудников",
                        "employee account passwords leaked combo list"],
}
IRRELEVANT = ["привет как дела у вас сегодня",
              "thanks for the invite great channel",
              "поздравляю с праздником всем добра",
              "lol that meme is hilarious indeed"]


def synth_rows(rng, texts_by_label, n_per_label):
    rows = []
    for label, seeds in texts_by_label.items():
        for i in range(n_per_label):
            seed = seeds[i % len(seeds)]
            words = seed.split()
            rng.shuffle(words)
            text = " ".join(words) + f" вариант v{i}"
            rows.append({"id": f"{label}-{i}", "text": text, "label": label,
                         "language": "cyrillic" if i % 2 == 0 else "latin"})
    rng.shuffle(rows)
    for j, row in enumerate(rows):
        row["split"] = ("train" if j % 10 < 8 else
                        "val" if j % 10 == 8 else "test")
    return rows


class TestTrainBaseline(unittest.TestCase):
    def test_full_run_on_synthetic_dataset(self):
        rng = random.Random(7)
        stage2 = synth_rows(rng, ACTIONABLE, 40)
        stage1 = ([dict(r, label="relevant") for r in stage2]
                  + synth_rows(rng, {"irrelevant": IRRELEVANT}, 120))

        with tempfile.TemporaryDirectory() as tmp:
            data_dir, out_dir = Path(tmp) / "data", Path(tmp) / "out"
            data_dir.mkdir()
            pd.DataFrame(stage1).to_parquet(data_dir / "stage1.parquet")
            pd.DataFrame(stage2).to_parquet(data_dir / "stage2.parquet")

            rc = main(["--data-dir", str(data_dir), "--out-dir", str(out_dir),
                       "--seed", "42"])
            self.assertEqual(rc, 0)

            for name in ("stage1_gate.joblib", "stage2_classifier.joblib",
                         "eval.json", "report.md"):
                self.assertTrue((out_dir / name).exists(), name)

            ev = json.loads((out_dir / "eval.json").read_text())
            op = ev["stage1"]["operating_point"]
            self.assertGreaterEqual(op["val_recall"], op["target_recall"])
            self.assertIn("threshold", op)

            # Metrics structure: per-class + per-language, both stages.
            for stage in ("stage1", "stage2"):
                for split in ("val", "test"):
                    block = ev[stage][split]
                    self.assertIn("macro_f1", block)
                    self.assertTrue(block["per_class"])
                    self.assertTrue(block["per_language"])

            # Roadmap principle 5: accuracy is never reported anywhere.
            self.assertNotIn("accuracy", (out_dir / "eval.json").read_text())
            self.assertNotIn("accuracy",
                             (out_dir / "report.md").read_text().lower())

            # Synthetic corpus is separable: a sane baseline must do well.
            self.assertGreater(ev["stage2"]["test"]["macro_f1"], 0.7)

    def test_missing_dataset_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                main(["--data-dir", tmp, "--out-dir", tmp])
            self.assertIn("build_dataset", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
