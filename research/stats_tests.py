"""
Statistics for the journal tables: seed aggregation, significance tests and
confidence intervals. Needs only NumPy and pandas.

Sub-commands
------------
aggregate   mean and sample standard deviation over several evaluate.py JSONs
            (one per training seed), e.g. results/csic/hybrid_s*.json
mcnemar     exact McNemar test between two configurations evaluated on the
            SAME test set (two --dump-preds CSVs from evaluate.py)
bootstrap   percentile bootstrap 95% confidence intervals for recall,
            precision, F1 and FPR from one --dump-preds CSV

Usage
-----
  python stats_tests.py aggregate --inputs "results/csic/hybrid_s*.json" \
      --out results/csic/hybrid_agg.json
  python stats_tests.py mcnemar --a results/csic/model_s42.csv \
      --b results/csic/hybrid_s42.csv --out results/csic/mcnemar_model_vs_hybrid.json
  python stats_tests.py bootstrap --preds results/csic/hybrid_s42.csv \
      --out results/csic/hybrid_s42_ci.json
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from common import save_json  # noqa: E402

METRICS = ["accuracy", "precision", "recall", "f1", "fpr", "roc_auc"]


# ------------------------------------------------------------------ aggregate
def aggregate(paths: list[str]) -> dict:
    if not paths:
        raise SystemExit("no input files matched")
    rows = []
    for p in sorted(paths):
        with open(p) as fh:
            d = json.load(fh)
        m = d.get("metrics", d)
        rows.append({k: m.get(k) for k in METRICS} | {"file": p, "seed": d.get("seed")})
    df = pd.DataFrame(rows)
    out = {"n_runs": len(df), "files": df["file"].tolist(),
           "seeds": df["seed"].tolist(), "metrics": {}}
    for k in METRICS:
        vals = pd.to_numeric(df[k], errors="coerce").dropna()
        if len(vals):
            out["metrics"][k] = {
                "mean": round(float(vals.mean()), 4),
                "std": round(float(vals.std(ddof=1)), 4) if len(vals) > 1 else 0.0,
                "min": round(float(vals.min()), 4),
                "max": round(float(vals.max()), 4),
                "latex": f"{vals.mean():.3f} $\\pm$ {vals.std(ddof=1) if len(vals) > 1 else 0:.3f}",
            }
    return out


# -------------------------------------------------------------------- mcnemar
def mcnemar_exact(y, a, b) -> dict:
    """
    Exact (binomial) McNemar test on paired predictions.
    n01: A correct, B wrong; n10: A wrong, B correct.
    """
    y, a, b = (np.asarray(v).astype(int) for v in (y, a, b))
    ca, cb = (a == y), (b == y)
    n01 = int((ca & ~cb).sum())
    n10 = int((~ca & cb).sum())
    n = n01 + n10
    if n == 0:
        p = 1.0
    else:
        k = min(n01, n10)
        tail = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
        p = min(1.0, 2 * tail)
    return {"n01_A_right_B_wrong": n01, "n10_A_wrong_B_right": n10,
            "discordant": n, "p_value_exact": p}


# ------------------------------------------------------------------ bootstrap
def _rates(y, p):
    tp = np.sum((y == 1) & (p == 1)); fp = np.sum((y == 0) & (p == 1))
    tn = np.sum((y == 0) & (p == 0)); fn = np.sum((y == 1) & (p == 0))
    rec = tp / (tp + fn) if (tp + fn) else np.nan
    prec = tp / (tp + fp) if (tp + fp) else np.nan
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else np.nan
    fpr = fp / (fp + tn) if (fp + tn) else np.nan
    return {"recall": rec, "precision": prec, "f1": f1, "fpr": fpr}


def bootstrap_ci(y, p, n_boot: int = 2000, seed: int = 42, alpha: float = 0.05) -> dict:
    y, p = np.asarray(y).astype(int), np.asarray(p).astype(int)
    rng = np.random.default_rng(seed)
    point = _rates(y, p)
    samples = {k: [] for k in point}
    n = len(y)
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        r = _rates(y[idx], p[idx])
        for k, v in r.items():
            samples[k].append(v)
    out = {}
    for k, vals in samples.items():
        v = np.asarray(vals, dtype=float)
        v = v[~np.isnan(v)]
        if len(v) and not np.isnan(point[k]):
            out[k] = {"point": round(float(point[k]), 4),
                      "ci_low": round(float(np.quantile(v, alpha / 2)), 4),
                      "ci_high": round(float(np.quantile(v, 1 - alpha / 2)), 4)}
    return {"n": n, "n_boot": n_boot, "level": 1 - alpha, "metrics": out}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("aggregate"); a.add_argument("--inputs", nargs="+", required=True)
    a.add_argument("--out", required=True)
    m = sub.add_parser("mcnemar"); m.add_argument("--a", required=True)
    m.add_argument("--b", required=True); m.add_argument("--out", required=True)
    b = sub.add_parser("bootstrap"); b.add_argument("--preds", required=True)
    b.add_argument("--n-boot", type=int, default=2000); b.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.cmd == "aggregate":
        paths = []
        for pat in args.inputs:
            paths.extend(glob.glob(pat))
        res = aggregate(sorted(set(paths)))
    elif args.cmd == "mcnemar":
        da, db = pd.read_csv(args.a), pd.read_csv(args.b)
        if len(da) != len(db) or not (da["y_true"].values == db["y_true"].values).all():
            raise SystemExit("the two prediction files must cover the same test set in the same order")
        res = mcnemar_exact(da["y_true"], da["y_pred"], db["y_pred"])
        res.update({"A": args.a, "B": args.b})
    else:
        d = pd.read_csv(args.preds)
        res = bootstrap_ci(d["y_true"], d["y_pred"], args.n_boot)
        res["file"] = args.preds
    save_json(res, args.out)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
