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
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             confusion_matrix)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from common import load_table, model_probs  # noqa: E402
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
    ap.add_argument("--text-col", default="text",
                    help="model input column (match training)")
    ap.add_argument("--fpr-budgets", default="0.01,0.03,0.05,0.10",
                    help="comma list: report the best-recall threshold under each FPR")
    args = ap.parse_args()

    df = load_table(args.test)
    y = df["label"].to_numpy()
    scores = model_probs(args.model, df[args.text_col].tolist())

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

    # Operating points: for each FPR budget, the threshold with the highest
    # recall whose FPR <= budget (Eq. tau* in the paper).
    ops = {}
    for b in [float(x) for x in args.fpr_budgets.split(",")]:
        ok = out[out["fpr"] <= b]
        if len(ok):
            r = ok.loc[ok["recall"].idxmax()]
            ops[f"fpr<={b}"] = {"threshold": float(r["threshold"]),
                                "recall": float(r["recall"]), "fpr": float(r["fpr"]),
                                "f1": float(r["f1"])}
    best = out.loc[out["f1"].idxmax()]
    summary = {"sweep_csv": args.out, "best_f1": best.to_dict(),
               "operating_points": ops}
    with open(os.path.splitext(args.out)[0] + "_points.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print(out.to_string(index=False))
    print(f"\nBest-F1: threshold={best['threshold']} F1={best['f1']} "
          f"FPR={best['fpr']} recall={best['recall']}")
    for k, v in ops.items():
        print(f"  {k}: tau={v['threshold']} recall={v['recall']} fpr={v['fpr']}")
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
