"""
Unified evaluation harness. Produces every number the Results section needs.

Modes (one file covers main results, ablation, and cross-dataset):
  --mode model    transformer only (argmax / prob threshold)
  --mode rules    deterministic rule engine only (no model)
  --mode hybrid   full deployed fusion policy (rules + model + thresholds)

Cross-dataset = train on set A, pass set B's test.parquet here with the model
trained on A. Ablation = run all three modes on the same test set.

Metrics: Accuracy, Precision, Recall, F1, FPR, ROC-AUC (+ per-attack-class
recall, confusion matrix). Saves <out>.json and prints a table.

Usage
-----
  # transformer-only
  python evaluate.py --mode model --model models/bert_csic \
      --test data/splits/csic2010/test.parquet --out results/bert_csic_model.json
  # rules-only ablation
  python evaluate.py --mode rules \
      --test data/splits/csic2010/test.parquet --out results/csic_rules.json
  # full hybrid
  python evaluate.py --mode hybrid --model models/bert_csic \
      --test data/splits/csic2010/test.parquet --out results/bert_csic_hybrid.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import (confusion_matrix, roc_auc_score,
                             precision_score, recall_score, f1_score,
                             accuracy_score)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from waf_rules import rules_verdict, fuse_decision  # noqa: E402

MAX_LEN = 256


def model_probs(model_dir: str, texts: list[str], batch: int = 64) -> np.ndarray:
    """Return P(malicious) for each text using a fine-tuned HF model."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device).eval()

    probs = []
    with torch.no_grad():
        for i in range(0, len(texts), batch):
            chunk = texts[i:i + batch]
            enc = tok(chunk, truncation=True, max_length=MAX_LEN,
                      padding=True, return_tensors="pt").to(device)
            logits = model(**enc).logits
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            probs.extend(p.tolist())
    return np.array(probs)


def metrics_block(y_true, y_pred, y_score=None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if y_score is not None and len(set(y_true)) > 1:
        out["roc_auc"] = round(roc_auc_score(y_true, y_score), 4)
    return out


def per_class_recall(df: pd.DataFrame, y_pred) -> dict:
    df = df.copy()
    df["pred"] = y_pred
    res = {}
    for atk in sorted(df.loc[df["label"] == 1, "attack_type"].unique()):
        sub = df[(df["label"] == 1) & (df["attack_type"] == atk)]
        if len(sub):
            res[atk] = round(sub["pred"].mean(), 4)  # recall within class
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["model", "rules", "hybrid"], required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", help="model dir (required for model/hybrid)")
    ap.add_argument("--prob-threshold", type=float, default=0.5,
                    help="for --mode model: P(malicious) cutoff")
    ap.add_argument("--tau-high", type=float, default=0.98)
    ap.add_argument("--tau-low", type=float, default=0.90)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dump-scores",
                    help="optional CSV path: writes y_true,y_score per sample "
                         "so make_figures.py can build ROC/PR curves")
    args = ap.parse_args()

    df = pd.read_parquet(args.test)
    y_true = df["label"].to_numpy()
    y_score = None

    if args.mode == "rules":
        y_pred = np.array([
            int(rules_verdict(m, u)[0])
            for m, u in zip(df["method"], df["raw_uri"])
        ])

    elif args.mode == "model":
        if not args.model:
            ap.error("--model required for --mode model")
        y_score = model_probs(args.model, df["text"].tolist())
        y_pred = (y_score >= args.prob_threshold).astype(int)

    else:  # hybrid
        if not args.model:
            ap.error("--model required for --mode hybrid")
        y_score = model_probs(args.model, df["text"].tolist())
        y_pred = np.array([
            int(fuse_decision(m, u, p, args.tau_high, args.tau_low)[0])
            for m, u, p in zip(df["method"], df["raw_uri"], y_score)
        ])

    report = {
        "mode": args.mode,
        "model": args.model,
        "test_set": args.test,
        "n": int(len(df)),
        "metrics": metrics_block(y_true, y_pred, y_score),
        "per_attack_recall": per_class_recall(df, y_pred),
        "params": {"prob_threshold": args.prob_threshold,
                   "tau_high": args.tau_high, "tau_low": args.tau_low},
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)

    if args.dump_scores and y_score is not None:
        os.makedirs(os.path.dirname(args.dump_scores) or ".", exist_ok=True)
        pd.DataFrame({"y_true": y_true, "y_score": y_score}).to_csv(
            args.dump_scores, index=False)
        print(f"  scores -> {args.dump_scores}")

    m = report["metrics"]
    print(f"\n=== {args.mode.upper()} on {os.path.basename(args.test)} (n={report['n']}) ===")
    print(f"  Acc {m['accuracy']}  P {m['precision']}  R {m['recall']}  "
          f"F1 {m['f1']}  FPR {m['fpr']}  AUC {m.get('roc_auc','-')}")
    print(f"  per-class recall: {report['per_attack_recall']}")
    print(f"  saved -> {args.out}")


if __name__ == "__main__":
    main()
