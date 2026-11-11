"""
Learned fusion as an alternative to the fixed rule (paper: future work item).

Trains a small, interpretable model that combines the five binary rule
signals with the transformer score, and compares it against the deployed
fixed-rule fusion on the SAME test sets. Two learners:

  logreg : logistic regression over [s_dir, s_kw, s_inj, s_enc, s_ca, p(x)]
           -> coefficients are readable, so the decision stays explainable
  tree   : a depth-limited decision tree over the same features

Features are computed with the same rule engine the live service uses, so the
comparison is fair. The model is fit on the TRAIN split's rule signals and
model scores, and evaluated on the test split; the fixed-rule fusion needs no
fitting. Report both so a reviewer can see what a learned combiner buys.

Inputs: model scores saved by evaluate.py --dump-preds (the 'y_score'
column), one CSV per split, plus the matching split files for the rule
signals and labels.

Usage
-----
  python learned_fusion.py --learner logreg \
      --train-split data/splits/csic2010/train.parquet \
      --train-scores results/csic/model_train_s42.csv \
      --test-split  data/splits/csic2010/test.parquet \
      --test-scores results/csic/model_s42.csv \
      --out results/csic/learned_fusion_s42.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from common import load_table, save_json  # noqa: E402
from evaluate import metrics_block  # noqa: E402
from waf_rules import SIGNAL_NAMES, fuse_decision, signal_vector  # noqa: E402


def features(split_df: pd.DataFrame, scores: np.ndarray) -> np.ndarray:
    sig = np.array([signal_vector(m, u)
                    for m, u in zip(split_df["method"], split_df["raw_uri"])], dtype=float)
    return np.column_stack([sig, scores])


def load_scores(split_df, scores_csv):
    sc = pd.read_csv(scores_csv)
    if len(sc) != len(split_df):
        raise SystemExit(f"{scores_csv} has {len(sc)} rows but split has {len(split_df)}")
    return sc["y_score"].to_numpy()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--learner", choices=["logreg", "tree"], default="logreg")
    ap.add_argument("--train-split", required=True)
    ap.add_argument("--train-scores", required=True)
    ap.add_argument("--test-split", required=True)
    ap.add_argument("--test-scores", required=True)
    ap.add_argument("--tau-high", type=float, default=0.98)
    ap.add_argument("--tau-low", type=float, default=0.90)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    tr = load_table(args.train_split); te = load_table(args.test_split)
    Xtr = features(tr, load_scores(tr, args.train_scores))
    ytr = tr["label"].to_numpy().astype(int)
    te_scores = load_scores(te, args.test_scores)
    Xte = features(te, te_scores)
    yte = te["label"].to_numpy().astype(int)
    names = SIGNAL_NAMES + ["p_model"]

    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier, export_text

    if args.learner == "logreg":
        clf = LogisticRegression(max_iter=1000, class_weight="balanced",
                                 random_state=args.seed).fit(Xtr, ytr)
        interpret = {"coef": dict(zip(names, [round(float(c), 4) for c in clf.coef_[0]])),
                     "intercept": round(float(clf.intercept_[0]), 4)}
    else:
        clf = DecisionTreeClassifier(max_depth=4, class_weight="balanced",
                                     random_state=args.seed).fit(Xtr, ytr)
        interpret = {"tree": export_text(clf, feature_names=names)}

    learned_pred = clf.predict(Xte)
    fixed_pred = np.array([int(fuse_decision(m, u, p, args.tau_high, args.tau_low)[0])
                           for m, u, p in zip(te["method"], te["raw_uri"], te_scores)])

    res = {
        "learner": args.learner,
        "features": names,
        "interpretation": interpret,
        "learned_fusion": metrics_block(yte, learned_pred, te_scores),
        "fixed_fusion": metrics_block(yte, fixed_pred, te_scores),
        "test_set": args.test_split,
    }
    save_json(res, args.out)
    lf, ff = res["learned_fusion"], res["fixed_fusion"]
    print(f"learned : F1 {lf['f1']} FPR {lf['fpr']} recall {lf['recall']}")
    print(f"fixed   : F1 {ff['f1']} FPR {ff['fpr']} recall {ff['recall']}")
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
