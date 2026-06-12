#!/usr/bin/env python3
"""Fase 1 baseline (roadmap F1.10/F1.11): two-stage TF-IDF classifier.

Stage 1 — binary gate (relevant vs irrelevant) with a decision-threshold
sweep: the reported operating point is the highest threshold whose recall on
actionable ("relevant") content is >= --gate-recall (default 0.97, roadmap
G3) on the validation split, then frozen and applied to test.

Stage 2 — 6-class classifier over relevant content only.

Both stages: TF-IDF char(2,5) + word(1,2) n-grams -> LinearSVC (default) or
LogisticRegression (--model logreg), class_weight='balanced'. Char n-grams
carry most of the signal on short/noisy Cyrillic text.

Metrics: macro-F1 and per-class precision/recall/F1 on val and test, plus the
same metrics split by the script heuristic (cyrillic/latin/other, textlang.py).
Plain accuracy is NEVER reported (roadmap principle 5: 89% of the data is two
classes; accuracy is noise).

Input contract (produced by build_dataset.py; no DB access here):
    <data-dir>/stage1.parquet  columns: id, text, label, language, split
                               label in {relevant, irrelevant}
    <data-dir>/stage2.parquet  same columns, label in the 6 actionable
                               classes (threat_actor_comms, vulnerability,
                               data_dump, malware_sample, access_broker,
                               credential_leak)
    split in {train, val, test}; text is already IOC-masked (mask_iocs).

Outputs in --out-dir:
    stage1_gate.joblib        {"pipeline", "threshold", "positive_label"}
    stage2_classifier.joblib  fitted sklearn Pipeline
    eval.json                 all metrics, machine-readable
    report.md                 human-readable summary

Examples:
    # default LinearSVC baseline
    python3 tools/train_baseline.py --data-dir tools/out/dataset \\
        --out-dir tools/out/baseline

    # logistic regression variant, stricter gate
    python3 tools/train_baseline.py --data-dir tools/out/dataset \\
        --out-dir tools/out/baseline_lr --model logreg --gate-recall 0.98
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

REQUIRED_COLUMNS = {"id", "text", "label", "language", "split"}
SPLITS = ("train", "val", "test")
POSITIVE_LABEL = "relevant"


def build_pipeline(model: str, seed: int, min_df: int) -> Pipeline:
    """TF-IDF char(2,5) + word(1,2) union feeding a balanced linear model."""
    features = FeatureUnion([
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(2, 5),
                                 min_df=min_df, max_features=300_000,
                                 sublinear_tf=True)),
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                 min_df=min_df, max_features=200_000,
                                 sublinear_tf=True)),
    ])
    if model == "logreg":
        clf = LogisticRegression(class_weight="balanced", max_iter=2000,
                                 random_state=seed)
    else:
        clf = LinearSVC(class_weight="balanced", random_state=seed)
    return Pipeline([("tfidf", features), ("clf", clf)])


def relevance_scores(pipeline: Pipeline, texts) -> np.ndarray:
    """Score for the positive ('relevant') class, model-agnostic."""
    clf = pipeline.named_steps["clf"]
    pos_idx = list(clf.classes_).index(POSITIVE_LABEL)
    if hasattr(clf, "predict_proba"):
        return pipeline.predict_proba(texts)[:, pos_idx]
    scores = pipeline.decision_function(texts)
    # Binary LinearSVC: positive scores favour classes_[1].
    return scores if pos_idx == 1 else -scores


def sweep_threshold(scores: np.ndarray, is_relevant: np.ndarray,
                    target_recall: float) -> dict:
    """Highest threshold with relevant-recall >= target on these scores.

    Predicting relevant iff score >= threshold, recall is monotonically
    non-increasing in the threshold, so the best valid operating point is
    the largest threshold still meeting the target. -inf (gate everything
    through) is always a candidate, so a result always exists.
    """
    total_pos = int(is_relevant.sum())
    if total_pos == 0:
        raise SystemExit("threshold sweep: no relevant rows in val split")
    best = None
    for t in np.concatenate(([-np.inf], np.unique(scores))):
        pred = scores >= t
        tp = int((pred & is_relevant).sum())
        recall = tp / total_pos
        if recall < target_recall:
            continue
        precision = tp / int(pred.sum()) if pred.any() else 0.0
        if best is None or t > best["threshold"]:
            best = {"threshold": float(t), "val_recall": float(recall),
                    "val_precision": float(precision)}
    return best


def metrics_block(y_true, y_pred, languages) -> dict:
    """macro-F1 + per-class P/R/F1, overall and per language bucket.

    classification_report's 'accuracy' entry is dropped on purpose
    (roadmap principle 5: never report accuracy).
    """
    def report(yt, yp):
        rep = classification_report(yt, yp, output_dict=True, zero_division=0)
        rep.pop("accuracy", None)
        macro = rep.pop("macro avg", {})
        rep.pop("weighted avg", None)
        return {"macro_f1": macro.get("f1-score", 0.0), "per_class": rep}

    out = report(y_true, y_pred)
    out["per_language"] = {}
    languages = np.asarray(languages)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    for lang in sorted(set(languages)):
        m = languages == lang
        block = report(y_true[m], y_pred[m])
        block["support"] = int(m.sum())
        out["per_language"][lang] = block
    return out


def load_split(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise SystemExit(f"missing dataset file: {path} "
                         "(run build_dataset.py first)")
    df = pd.read_parquet(path)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise SystemExit(f"{path}: missing required columns {sorted(missing)}")
    bad_splits = set(df["split"]) - set(SPLITS)
    if bad_splits:
        raise SystemExit(f"{path}: unknown split values {sorted(bad_splits)}")
    return df


def train_stage1(df: pd.DataFrame, args) -> tuple[dict, dict]:
    parts = {s: df[df["split"] == s] for s in SPLITS}
    pipe = build_pipeline(args.model, args.seed, args.min_df)
    pipe.fit(parts["train"]["text"], parts["train"]["label"])

    op = sweep_threshold(
        relevance_scores(pipe, parts["val"]["text"]),
        (parts["val"]["label"] == POSITIVE_LABEL).to_numpy(),
        args.gate_recall,
    )
    op["target_recall"] = args.gate_recall

    result = {"operating_point": op}
    for split in ("val", "test"):
        part = parts[split]
        pred = np.where(
            relevance_scores(pipe, part["text"]) >= op["threshold"],
            POSITIVE_LABEL, "irrelevant",
        )
        result[split] = metrics_block(part["label"], pred, part["language"])
    artifact = {"pipeline": pipe, "threshold": op["threshold"],
                "positive_label": POSITIVE_LABEL}
    return result, artifact


def train_stage2(df: pd.DataFrame, args) -> tuple[dict, Pipeline]:
    parts = {s: df[df["split"] == s] for s in SPLITS}
    pipe = build_pipeline(args.model, args.seed, args.min_df)
    pipe.fit(parts["train"]["text"], parts["train"]["label"])

    result = {}
    for split in ("val", "test"):
        part = parts[split]
        pred = pipe.predict(part["text"])
        result[split] = metrics_block(part["label"], pred, part["language"])
    return result, pipe


def write_report(path: Path, evaluation: dict) -> None:
    """Human-readable summary. Macro-F1 headline; accuracy nowhere."""
    lines = ["# Baseline evaluation (TF-IDF, two stages)", ""]
    cfg = evaluation["config"]
    lines += [f"- model: `{cfg['model']}`  seed: {cfg['seed']}  "
              f"min_df: {cfg['min_df']}",
              f"- gate target: relevant-recall >= {cfg['gate_recall']}", ""]
    for stage in ("stage1", "stage2"):
        ev = evaluation[stage]
        title = ("Stage 1 — relevance gate" if stage == "stage1"
                 else "Stage 2 — 6-class")
        lines += [f"## {title}", ""]
        if stage == "stage1":
            op = ev["operating_point"]
            lines += [f"Operating point: threshold `{op['threshold']:.4f}` — "
                      f"val recall {op['val_recall']:.3f}, "
                      f"val precision {op['val_precision']:.3f} "
                      f"(target recall {op['target_recall']})", ""]
        for split in ("val", "test"):
            block = ev[split]
            lines += [f"### {split} — macro-F1 {block['macro_f1']:.3f}", "",
                      "| class | precision | recall | f1 | support |",
                      "|---|---|---|---|---|"]
            for cls, m in sorted(block["per_class"].items()):
                lines.append(f"| {cls} | {m['precision']:.3f} | "
                             f"{m['recall']:.3f} | {m['f1-score']:.3f} | "
                             f"{int(m['support'])} |")
            lines += ["", "| language | macro-F1 | support |", "|---|---|---|"]
            for lang, lm in sorted(block["per_language"].items()):
                lines.append(f"| {lang} | {lm['macro_f1']:.3f} | "
                             f"{lm['support']} |")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Two-stage TF-IDF baseline (roadmap F1.10/F1.11). "
                    "Reads parquet datasets, no DB access.",
        epilog=__doc__.split("Examples:")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--data-dir", required=True, type=Path,
                    help="directory with stage1.parquet and stage2.parquet")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="directory for models, eval.json and report.md")
    ap.add_argument("--model", choices=("linearsvc", "logreg"),
                    default="linearsvc", help="classifier (default linearsvc)")
    ap.add_argument("--gate-recall", type=float, default=0.97,
                    help="minimum relevant-recall for the stage-1 gate "
                         "operating point (default 0.97, roadmap G3)")
    ap.add_argument("--min-df", type=int, default=2,
                    help="TF-IDF min document frequency (default 2)")
    ap.add_argument("--seed", type=int, default=42, help="random seed")
    args = ap.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    evaluation = {"config": {"model": args.model, "seed": args.seed,
                             "gate_recall": args.gate_recall,
                             "min_df": args.min_df}}

    stage1_df = load_split(args.data_dir / "stage1.parquet")
    evaluation["stage1"], gate = train_stage1(stage1_df, args)
    joblib.dump(gate, args.out_dir / "stage1_gate.joblib")

    stage2_df = load_split(args.data_dir / "stage2.parquet")
    evaluation["stage2"], clf = train_stage2(stage2_df, args)
    joblib.dump(clf, args.out_dir / "stage2_classifier.joblib")

    (args.out_dir / "eval.json").write_text(
        json.dumps(evaluation, indent=2, ensure_ascii=False), encoding="utf-8")
    write_report(args.out_dir / "report.md", evaluation)

    op = evaluation["stage1"]["operating_point"]
    print(f"stage1 gate: threshold {op['threshold']:.4f} "
          f"(val recall {op['val_recall']:.3f}, "
          f"precision {op['val_precision']:.3f})")
    print(f"stage1 test macro-F1: {evaluation['stage1']['test']['macro_f1']:.3f}")
    print(f"stage2 test macro-F1: {evaluation['stage2']['test']['macro_f1']:.3f}")
    print(f"artifacts written to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
