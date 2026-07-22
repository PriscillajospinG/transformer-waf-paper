"""
Threshold sensitivity analysis (Results 6.4 / GAP 3: false-positive control).

Computes model P(malicious) once on the test set, then sweeps the decision
threshold and records FPR / recall / precision / F1 at each point so you can
plot the FPR-vs-recall trade-off and justify the chosen operating point.

Also sweeps the hybrid tau_high band if --hybrid is set.

Usage
-----
  python threshold_sweep.py --model models/bert_csic \
      --test data/splits/csic2010/test.parquet --out results/threshold_csic.csv
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             confusion_matrix)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from evaluate import model_probs  # noqa: E402
from waf_rules import fuse_decision  # noqa: E402


def fpr(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return fp / (fp + tn) if (fp + tn) else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--hybrid", action="store_true",
                    help="sweep hybrid tau_high instead of raw prob threshold")
    args = ap.parse_args()

    df = pd.read_parquet(args.test)
    y = df["label"].to_numpy()
    scores = model_probs(args.model, df["text"].tolist())

    rows = []
    for t in np.round(np.arange(0.50, 1.00, 0.02), 2):
        if args.hybrid:
            pred = np.array([
                int(fuse_decision(m, u, p, tau_high=float(t), tau_low=max(0.5, t - 0.08))[0])
                for m, u, p in zip(df["method"], df["raw_uri"], scores)
            ])
        else:
            pred = (scores >= t).astype(int)
        rows.append({
            "threshold": float(t),
            "precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred, zero_division=0), 4),
            "f1": round(f1_score(y, pred, zero_division=0), 4),
            "fpr": round(fpr(y, pred), 4),
        })

    out = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out.to_csv(args.out, index=False)
    best = out.loc[out["f1"].idxmax()]
    print(out.to_string(index=False))
    print(f"\nBest-F1 operating point: threshold={best['threshold']} "
          f"F1={best['f1']} FPR={best['fpr']} recall={best['recall']}")
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
