"""
Unified evaluation harness. Produces every number the Results section needs.

Modes:
  --mode model    transformer only (probability threshold)
  --mode rules    deterministic rule engine only (no model)
  --mode hybrid   full deployed fusion policy (rules + model + thresholds)

Cross-dataset = model trained on set A, --test from set B.
Ablation      = all three modes on the same test set.
Seeds         = run once per trained seed, then aggregate with stats_tests.py.

Outputs <out>.json with metrics, per-class recall, the count of decisions per
fusion branch (hybrid/rules), and the run parameters. Optional dumps:
  --dump-preds  CSV: y_true, y_pred, y_score, branch, attack_type
                (needed for McNemar tests, bootstrap CIs and ROC/PR curves)
  --dump-logits .npy of raw logits (needed by calibration.py)
  --logits-in   reuse saved logits instead of re-running the model

Attack-only test sets (e.g. the 2025 ModSecurity capture): precision, FPR,
F1 and AUC are reported as null, because they are not defined without
benign requests; recall is still computed.

Usage
-----
  python evaluate.py --mode hybrid --model models/bert_csic_s42 \
      --test data/splits/csic2010/test.parquet \
      --out results/csic/hybrid_s42.json --dump-preds results/csic/hybrid_s42.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from common import (load_table, model_logits, pick_text_column,  # noqa: E402
                    save_json, softmax_prob)
from waf_rules import (BRANCHES, fuse_decision, load_rules_config,  # noqa: E402
                       rules_verdict)

# Kept for older scripts that import it from here.
from common import model_probs  # noqa: E402,F401


def _confusion(y_true, y_pred):
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    return tn, fp, fn, tp


def _auc(y_true, y_score):
    """ROC-AUC via the rank-sum formula (ties get average ranks)."""
    y_true = np.asarray(y_true).astype(int)
    s = pd.Series(np.asarray(y_score, dtype=float))
    ranks = s.rank(method="average").to_numpy()
    n1 = int(y_true.sum()); n0 = len(y_true) - n1
    if n0 == 0 or n1 == 0:
        return None
    return float((ranks[y_true == 1].sum() - n1 * (n1 + 1) / 2) / (n0 * n1))


def metrics_block(y_true, y_pred, y_score=None) -> dict:
    tn, fp, fn, tp = _confusion(y_true, y_pred)
    has_benign = (tn + fp) > 0
    has_mal = (tp + fn) > 0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if has_mal else None
    out = {
        "n": int(len(y_true)),
        "accuracy": round((tp + tn) / max(len(y_true), 1), 4),
        "recall": round(rec, 4) if rec is not None else None,
        "precision": round(prec, 4) if has_benign else None,
        "f1": (round(2 * prec * rec / (prec + rec), 4) if (prec + rec) else 0.0)
              if (has_benign and has_mal) else None,
        "fpr": round(fp / (fp + tn), 4) if has_benign else None,
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
    if y_score is not None and has_benign and has_mal:
        out["roc_auc"] = round(_auc(y_true, y_score), 4)
    if not has_benign:
        out["note"] = "attack-only test set: only recall is defined"
    return out


def per_class_recall(df: pd.DataFrame, y_pred) -> dict:
    df = df.copy()
    df["pred"] = y_pred
    res = {}
    if "attack_type" not in df.columns:
        return res
    for atk in sorted(df.loc[df["label"] == 1, "attack_type"].unique()):
        sub = df[(df["label"] == 1) & (df["attack_type"] == atk)]
        if len(sub):
            res[atk] = {"recall": round(float(sub["pred"].mean()), 4),
                        "n": int(len(sub))}
    return res


def branch_counts(branches, y_true) -> dict:
    """How many decisions each fusion branch made, split by true label."""
    out = {}
    for b in BRANCHES:
        sel = [i for i, x in enumerate(branches) if x == b]
        if sel:
            yt = np.asarray(y_true)[sel]
            out[b] = {"total": len(sel), "malicious": int((yt == 1).sum()),
                      "benign": int((yt == 0).sum())}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["model", "rules", "hybrid"], required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", help="model dir (required for model/hybrid)")
    ap.add_argument("--text-col", default=None,
                    help="model input column (default 'text'); use the same "
                         "column the model was trained on")
    ap.add_argument("--prob-threshold", type=float, default=0.5)
    ap.add_argument("--tau-high", type=float, default=0.98)
    ap.add_argument("--tau-low", type=float, default=0.90)
    ap.add_argument("--temperature", type=float, default=1.0,
                    help="temperature from calibration.py (1.0 = none)")
    ap.add_argument("--rules-config", help="JSON file that extends the rule lists")
    ap.add_argument("--logits-in", help="reuse logits saved with --dump-logits")
    ap.add_argument("--dump-logits", help="save raw logits (.npy)")
    ap.add_argument("--dump-preds", help="save per-request predictions (.csv)")
    ap.add_argument("--dump-scores", help="(old name) y_true,y_score CSV")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rules_info = load_rules_config(args.rules_config)
    df = load_table(args.test)
    y_true = df["label"].to_numpy().astype(int)
    y_score = None
    logits = None
    branches = [""] * len(df)

    if args.mode in ("model", "hybrid"):
        if not args.model and not args.logits_in:
            ap.error("--model (or --logits-in) required for model/hybrid")
        if args.logits_in:
            logits = np.load(args.logits_in)
        else:
            col = pick_text_column(df, args.text_col)
            logits = model_logits(args.model, df[col].tolist())
        if args.dump_logits:
            os.makedirs(os.path.dirname(args.dump_logits) or ".", exist_ok=True)
            np.save(args.dump_logits, logits)
        y_score = softmax_prob(logits, args.temperature)

    if args.mode == "rules":
        res = [rules_verdict(m, u) for m, u in zip(df["method"], df["raw_uri"])]
        y_pred = np.array([int(r[0]) for r in res])
        branches = [r[1] for r in res]
    elif args.mode == "model":
        y_pred = (y_score >= args.prob_threshold).astype(int)
        branches = ["model_threshold" if p else "allow" for p in y_pred]
    else:
        res = [fuse_decision(m, u, p, args.tau_high, args.tau_low)
               for m, u, p in zip(df["method"], df["raw_uri"], y_score)]
        y_pred = np.array([int(r[0]) for r in res])
        branches = [r[1] for r in res]

    meta = {}
    if args.model and os.path.exists(os.path.join(args.model, "run_meta.json")):
        with open(os.path.join(args.model, "run_meta.json")) as fh:
            meta = json.load(fh)

    report = {
        "mode": args.mode,
        "model": args.model,
        "seed": meta.get("seed"),
        "train_text_col": meta.get("text_col"),
        "test_set": args.test,
        "n": int(len(df)),
        "metrics": metrics_block(y_true, y_pred, y_score),
        "per_attack_recall": per_class_recall(df, y_pred),
        "branch_counts": branch_counts(branches, y_true) if args.mode != "model" else {},
        "params": {"prob_threshold": args.prob_threshold,
                   "tau_high": args.tau_high, "tau_low": args.tau_low,
                   "temperature": args.temperature,
                   "text_col": args.text_col or "text",
                   "rules": rules_info, "rules_config": args.rules_config},
    }
    save_json(report, args.out)

    if args.dump_preds:
        os.makedirs(os.path.dirname(args.dump_preds) or ".", exist_ok=True)
        pd.DataFrame({
            "y_true": y_true, "y_pred": y_pred,
            "y_score": y_score if y_score is not None else np.nan,
            "branch": branches,
            "attack_type": df["attack_type"] if "attack_type" in df else "",
        }).to_csv(args.dump_preds, index=False)
    if args.dump_scores and y_score is not None:
        pd.DataFrame({"y_true": y_true, "y_score": y_score}).to_csv(
            args.dump_scores, index=False)

    m = report["metrics"]
    print(f"\n=== {args.mode.upper()} on {os.path.basename(args.test)} (n={report['n']}) ===")
    print(f"  Acc {m['accuracy']}  P {m['precision']}  R {m['recall']}  "
          f"F1 {m['f1']}  FPR {m['fpr']}  AUC {m.get('roc_auc', '-')}")
    if report["branch_counts"]:
        print(f"  branches: { {k: v['total'] for k, v in report['branch_counts'].items()} }")
    print(f"  saved -> {args.out}")


if __name__ == "__main__":
    main()
