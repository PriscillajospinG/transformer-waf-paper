"""
Classical ML baselines for the comparison table (Q2 reviewers require these).

TF-IDF (char n-grams, good for payloads) + {SVM, Random Forest, Logistic Reg}.
Char n-grams are used because attack payloads are sub-word / structural.

Usage
-----
  python baselines.py --train data/splits/csic2010/train.parquet \
                      --test  data/splits/csic2010/test.parquet \
                      --out results/baselines_csic.json
"""
from __future__ import annotations

import argparse
import json
import os

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.svm import LinearSVC

SEED = 42


def block(y, pred, score=None):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    d = {
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
    }
    if score is not None and len(set(y)) > 1:
        d["roc_auc"] = round(roc_auc_score(y, score), 4)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    tr, te = pd.read_parquet(args.train), pd.read_parquet(args.test)
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 4), min_df=2,
                          max_features=50000)
    Xtr = vec.fit_transform(tr["text"])
    Xte = vec.transform(te["text"])
    ytr, yte = tr["label"].to_numpy(), te["label"].to_numpy()

    results = {}

    svm = LinearSVC(random_state=SEED).fit(Xtr, ytr)
    results["tfidf_linearsvm"] = block(yte, svm.predict(Xte),
                                       svm.decision_function(Xte))

    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1,
                                random_state=SEED).fit(Xtr, ytr)
    results["tfidf_randomforest"] = block(yte, rf.predict(Xte),
                                          rf.predict_proba(Xte)[:, 1])

    lr = LogisticRegression(max_iter=1000, random_state=SEED).fit(Xtr, ytr)
    results["tfidf_logreg"] = block(yte, lr.predict(Xte),
                                    lr.predict_proba(Xte)[:, 1])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)
    for name, m in results.items():
        print(f"{name:22s} P {m['precision']} R {m['recall']} F1 {m['f1']} "
              f"FPR {m['fpr']} AUC {m.get('roc_auc','-')}")
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
