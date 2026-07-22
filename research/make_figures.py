"""
Turn results/*.json (+ score dumps) into figure-ready CSVs that the LaTeX
pgfplots charts read directly. Run this after all experiments finish.

Outputs (in --fig-dir, default results/figs):
  metric_comparison.csv   method,precision,recall,f1,fpr
  per_class_recall.csv     attack_type,recall
  latency.csv              config,p50,p95,p99,rps
  adversarial.csv          mutation,evasion
  roc_<name>.csv           fpr,tpr           (needs a --dump-scores CSV)
  pr_<name>.csv            recall,precision  (needs a --dump-scores CSV)

The LaTeX figures \addplot table {...} these files, so the charts show your
real measured numbers with zero manual copying.

Usage
-----
  python make_figures.py --results results --fig-dir results/figs \
      --scores results/scores_hybrid.csv:hybrid results/scores_bert.csv:bert
"""
from __future__ import annotations

import argparse
import glob
import json
import os

import pandas as pd


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def metric_comparison(results_dir, out):
    """Collect every evaluate.py/baselines.py json into one comparison table."""
    rows = []
    for p in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        d = _load(p)
        name = os.path.splitext(os.path.basename(p))[0]
        if "metrics" in d:  # evaluate.py output
            m = d["metrics"]
            rows.append({"method": name, "precision": m.get("precision"),
                         "recall": m.get("recall"), "f1": m.get("f1"),
                         "fpr": m.get("fpr")})
        else:  # baselines.py output: dict of model->metrics
            for model, m in d.items():
                if isinstance(m, dict) and "f1" in m:
                    rows.append({"method": model, "precision": m.get("precision"),
                                 "recall": m.get("recall"), "f1": m.get("f1"),
                                 "fpr": m.get("fpr")})
    if rows:
        pd.DataFrame(rows).to_csv(out, index=False)
        print(f"metric_comparison -> {out} ({len(rows)} methods)")


def per_class(results_dir, out, prefer="hybrid"):
    cands = glob.glob(os.path.join(results_dir, f"*{prefer}*.json")) or \
            glob.glob(os.path.join(results_dir, "*.json"))
    for p in cands:
        d = _load(p)
        pcr = d.get("per_attack_recall")
        if pcr:
            pd.DataFrame([{"attack_type": k, "recall": v} for k, v in pcr.items()]
                         ).to_csv(out, index=False)
            print(f"per_class_recall -> {out} (from {os.path.basename(p)})")
            return


def latency(results_dir, out):
    rows = []
    for p in glob.glob(os.path.join(results_dir, "*latency*.json")):
        d = _load(p)
        lat = d.get("latency", {})
        rows.append({"config": d.get("mode", os.path.basename(p)),
                     "p50": lat.get("p50_ms"), "p95": lat.get("p95_ms"),
                     "p99": lat.get("p99_ms"),
                     "rps": lat.get("throughput_rps") or lat.get("achieved_rps")})
    if rows:
        pd.DataFrame(rows).to_csv(out, index=False)
        print(f"latency -> {out}")


def adversarial(results_dir, out):
    for p in glob.glob(os.path.join(results_dir, "*advers*.json")):
        d = _load(p)
        pm = d.get("per_mutation", {})
        if pm:
            pd.DataFrame([{"mutation": k, "evasion": v["evasion_rate"]}
                         for k, v in pm.items()]).to_csv(out, index=False)
            print(f"adversarial -> {out}")
            return


def roc_pr(scores_csv, name, fig_dir):
    from sklearn.metrics import roc_curve, precision_recall_curve
    df = pd.read_csv(scores_csv)
    fpr, tpr, _ = roc_curve(df["y_true"], df["y_score"])
    pd.DataFrame({"fpr": fpr, "tpr": tpr}).to_csv(
        os.path.join(fig_dir, f"roc_{name}.csv"), index=False)
    prec, rec, _ = precision_recall_curve(df["y_true"], df["y_score"])
    pd.DataFrame({"recall": rec, "precision": prec}).to_csv(
        os.path.join(fig_dir, f"pr_{name}.csv"), index=False)
    print(f"roc_{name}.csv / pr_{name}.csv written")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--fig-dir", default="results/figs")
    ap.add_argument("--scores", nargs="*", default=[],
                    help="pairs path.csv:name for ROC/PR curves")
    args = ap.parse_args()

    os.makedirs(args.fig_dir, exist_ok=True)
    metric_comparison(args.results, os.path.join(args.fig_dir, "metric_comparison.csv"))
    per_class(args.results, os.path.join(args.fig_dir, "per_class_recall.csv"))
    latency(args.results, os.path.join(args.fig_dir, "latency.csv"))
    adversarial(args.results, os.path.join(args.fig_dir, "adversarial.csv"))
    for spec in args.scores:
        path, _, name = spec.partition(":")
        roc_pr(path, name or "model", args.fig_dir)
    print(f"\nAll figure CSVs in {args.fig_dir}. The LaTeX charts read these.")


if __name__ == "__main__":
    main()
