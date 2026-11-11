"""
Calibration analysis and temperature scaling (Guo et al., ICML 2017).

Tests the paper's claim that the SR-BH failure is a loss of calibration
rather than of ranking. Steps:

1. Save logits with evaluate.py --dump-logits for the validation split
   (in-distribution) and for each test set of interest.
2. Fit one temperature T on the VALIDATION logits by minimising the
   negative log-likelihood (no test data is used).
3. Report ECE, Brier score and NLL before/after scaling on every test set,
   plus reliability-diagram bins.
4. Re-run evaluate.py with --temperature T and --logits-in to see whether the
   calibrated scores change FPR/recall of the model and the hybrid.

Note: a temperature fitted on CSIC validation data can only fix
mis-calibration that also exists in-distribution. If SR-BH needs a different
temperature, report that honestly (option --fit-on lets you fit on a small
labelled target sample, clearly marked as using target labels).

Usage
-----
  python calibration.py --fit-logits results/csic/val_logits_s42.npy \
      --fit-split data/splits/csic2010/val.parquet \
      --eval results/csic/test_logits_s42.npy:data/splits/csic2010/test.parquet:csic \
      --eval results/srbh/test_logits_s42.npy:data/splits/srbh2020/test.parquet:srbh \
      --out results/calibration_s42.json --bins-dir results/figs
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from common import load_table, save_json, softmax_prob  # noqa: E402


def nll(logits, y, T):
    p = np.clip(softmax_prob(logits, T), 1e-12, 1 - 1e-12)
    return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))


def fit_temperature(logits, y, lo=0.05, hi=20.0, iters=80) -> float:
    """Golden-section search for T minimising NLL on log(T) (NLL is unimodal in practice)."""
    a, b = np.log(lo), np.log(hi)
    g = (np.sqrt(5) - 1) / 2
    c, d = b - g * (b - a), a + g * (b - a)
    fc, fd = nll(logits, y, np.exp(c)), nll(logits, y, np.exp(d))
    for _ in range(iters):
        if fc < fd:
            b, d, fd = d, c, fc
            c = b - g * (b - a); fc = nll(logits, y, np.exp(c))
        else:
            a, c, fc = c, d, fd
            d = a + g * (b - a); fd = nll(logits, y, np.exp(d))
    return float(np.exp((a + b) / 2))


def ece(prob, y, n_bins=15):
    """Expected calibration error of P(malicious), equal-width bins on [0,1]."""
    prob, y = np.asarray(prob), np.asarray(y)
    edges = np.linspace(0, 1, n_bins + 1)
    idx = np.clip(np.digitize(prob, edges[1:-1]), 0, n_bins - 1)
    total, rows = 0.0, []
    for b in range(n_bins):
        m = idx == b
        if m.any():
            conf, acc = prob[m].mean(), y[m].mean()
            total += m.mean() * abs(conf - acc)
            rows.append({"bin_low": edges[b], "bin_high": edges[b + 1],
                         "count": int(m.sum()), "mean_prob": float(conf),
                         "frac_malicious": float(acc)})
    return float(total), rows


def report(logits, y, T, name, bins_dir=None):
    out = {}
    for tag, t in (("before", 1.0), ("after", T)):
        p = softmax_prob(logits, t)
        e, rows = ece(p, y)
        out[tag] = {"ece": round(e, 4),
                    "brier": round(float(np.mean((p - y) ** 2)), 4),
                    "nll": round(nll(logits, y, t), 4),
                    "mean_prob_benign": round(float(p[y == 0].mean()), 4) if (y == 0).any() else None,
                    "mean_prob_malicious": round(float(p[y == 1].mean()), 4) if (y == 1).any() else None}
        if bins_dir:
            os.makedirs(bins_dir, exist_ok=True)
            pd.DataFrame(rows).to_csv(os.path.join(bins_dir, f"reliability_{name}_{tag}.csv"), index=False)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fit-logits", required=True, help=".npy logits of the fitting split")
    ap.add_argument("--fit-split", required=True, help="split file with the labels for --fit-logits")
    ap.add_argument("--eval", action="append", default=[],
                    help="logits.npy:split.parquet:name (repeatable)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--bins-dir")
    args = ap.parse_args()

    fl = np.load(args.fit_logits)
    fy = load_table(args.fit_split)["label"].to_numpy().astype(int)
    if len(fl) != len(fy):
        raise SystemExit("logits and labels differ in length")
    T = fit_temperature(fl, fy)
    res = {"temperature": round(T, 4), "fitted_on": args.fit_split,
           "fit_split": report(fl, fy, T, "fit", args.bins_dir), "eval": {}}
    for spec in args.eval:
        lp, sp, name = spec.split(":")
        lg = np.load(lp); yy = load_table(sp)["label"].to_numpy().astype(int)
        res["eval"][name] = report(lg, yy, T, name, args.bins_dir)
    save_json(res, args.out)
    print(json.dumps(res, indent=2))
    print(f"\nRe-evaluate with: evaluate.py ... --temperature {T:.4f} --logits-in <logits.npy>")


if __name__ == "__main__":
    main()
