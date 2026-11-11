"""
Dataset preparation for the Transformer-WAF experiments.

Converts public web-attack datasets into ONE unified schema so every
downstream script (train / evaluate / ablation / cross-dataset) consumes the
same format:

    columns: text, text_raw, text_decoded, raw_uri, method, label,
             attack_type, dataset
      - text        : model input used by default (see --model-input)
      - text_raw    : "<METHOD> <raw URI, digits->{ID}>"
      - text_decoded: "<METHOD> <double-decoded URI, digits->{ID}>"
                      (this is what the live service feeds the model)
      - raw_uri     : original request path+query (for rule engine)
      - method      : HTTP method
      - label       : 0 = benign, 1 = malicious
      - attack_type : sqli|xss|path_traversal|encoding|other|benign
      - dataset     : source name (csic2010 / pkdd2007 / ...)

Supported sources
-----------------
1. CSIC 2010  (raw HTTP dumps OR the common Kaggle CSV)
2. ECML/PKDD 2007 (CSV export)
3. Generic labeled CSV (any dataset with a URL/payload column + label column)

Download (do this manually, then point --input at the files):
  CSIC 2010 raw : https://www.tic.itefi.csic.es/dataset/  (or Kaggle: "csic-2010")
  Combined CSIC+PKDD : https://github.com/msudol/Web-Application-Attack-Datasets
  FWAF : https://www.kaggle.com/datasets/evg3n1j/fwaf-dataset

Usage
-----
  python prepare_datasets.py --source csic_raw \
      --normal  data/raw/normalTrafficTraining.txt \
      --anomaly data/raw/anomalousTrafficTest.txt \
      --out data/processed/csic2010.parquet

  python prepare_datasets.py --source csv \
      --input data/raw/pkdd2007.csv --url-col request --label-col label \
      --dataset pkdd2007 --out data/processed/pkdd2007.parquet

  python prepare_datasets.py --split data/processed/csic2010.parquet \
      --out-dir data/splits/csic2010
"""
from __future__ import annotations

import argparse
import os
import re
import sys

import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from waf_rules import prepare_model_text, MODEL_INPUT_MODES  # noqa: E402

SEED = 42
MODEL_INPUT = "decoded"   # set from --model-input in main()


# ---------------------------------------------------------------------------
# Attack-type labelling (heuristic, only for reporting per-class recall)
# ---------------------------------------------------------------------------
def infer_attack_type(uri: str) -> str:
    u = (uri or "").lower()
    if any(k in u for k in ["union", "select", "or 1=1", "and 1=1", "drop", "'--", "sleep("]):
        return "sqli"
    if any(k in u for k in ["<script", "onerror", "onload", "alert(", "javascript:", "<img", "<svg"]):
        return "xss"
    if any(k in u for k in ["../", "..\\", "etc/passwd", "etc/shadow", "%2e%2e"]):
        return "path_traversal"
    if any(k in u for k in ["%00", "%3c", "%3e", "&#", "%27", "%22"]):
        return "encoding"
    return "other"


def _finalize(df: pd.DataFrame, dataset: str) -> pd.DataFrame:
    df = df.copy()
    df["method"] = df["method"].fillna("GET").str.upper()
    df["raw_uri"] = df["raw_uri"].fillna("/")
    df["label"] = df["label"].astype(int)
    df["dataset"] = dataset
    df["text_raw"] = [prepare_model_text(m, u, "raw")
                      for m, u in zip(df["method"], df["raw_uri"])]
    df["text_decoded"] = [prepare_model_text(m, u, "decoded")
                          for m, u in zip(df["method"], df["raw_uri"])]
    df["text"] = [prepare_model_text(m, u, MODEL_INPUT)
                  for m, u in zip(df["method"], df["raw_uri"])]
    df["attack_type"] = [
        "benign" if lbl == 0 else infer_attack_type(u)
        for lbl, u in zip(df["label"], df["raw_uri"])
    ]
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    return df[["text", "text_raw", "text_decoded", "raw_uri", "method",
               "label", "attack_type", "dataset"]]


# ---------------------------------------------------------------------------
# CSIC 2010 raw HTTP dump parser
# ---------------------------------------------------------------------------
_REQ_LINE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\S+)\s+HTTP", re.IGNORECASE)


def parse_csic_raw(path: str, label: int) -> pd.DataFrame:
    """Parse a CSIC 2010 raw traffic file into (method, raw_uri, label) rows.

    The raw files contain HTTP request blocks; for POST requests the body is on
    a later line. We capture the request line and append any body payload to the
    URI so injection payloads in POST bodies are not lost.
    """
    rows = []
    method = uri = None
    body_mode = False
    body = ""
    with open(path, "r", encoding="latin-1") as fh:
        for line in fh:
            m = _REQ_LINE.match(line.strip())
            if m:
                if method is not None:
                    full = uri + ("?" + body if body else "")
                    rows.append({"method": method, "raw_uri": full, "label": label})
                method, uri = m.group(1).upper(), m.group(2)
                body_mode = False
                body = ""
            elif method == "POST" and line.strip() == "":
                body_mode = True
            elif body_mode and line.strip():
                body = line.strip()
        if method is not None:
            full = uri + ("?" + body if body else "")
            rows.append({"method": method, "raw_uri": full, "label": label})
    # Strip scheme+host if present (keep path+query)
    for r in rows:
        r["raw_uri"] = re.sub(r"^https?://[^/]+", "", r["raw_uri"]) or "/"
    return pd.DataFrame(rows)


def load_csic_raw(normal_path: str, anomaly_path: str) -> pd.DataFrame:
    benign = parse_csic_raw(normal_path, 0)
    malic = parse_csic_raw(anomaly_path, 1)
    return _finalize(pd.concat([benign, malic], ignore_index=True), "csic2010")


# ---------------------------------------------------------------------------
# Generic CSV loader (CSIC CSV, PKDD, FWAF, etc.)
# ---------------------------------------------------------------------------
def load_csv(path: str, url_col: str, label_col: str | None, dataset: str,
             method_col: str | None = None, all_malicious: bool = False,
             malicious_values=("1", "anom", "anomalous", "attack", "malicious", "1.0"),
             body_col: str | None = None) -> pd.DataFrame:
    """
    Generic CSV loader (SR-BH 2020, PKDD 2007, FWAF, the 2025 ModSecurity
    capture, ...). For an attack-only corpus pass all_malicious=True and no
    label column. If body_col is given, a non-empty body is appended to the
    URI as a query string, as done for CSIC 2010 POST requests.
    """
    df = pd.read_csv(path, low_memory=False)
    if url_col not in df.columns:
        raise ValueError(f"--url-col '{url_col}' not in columns: {list(df.columns)}")
    out = pd.DataFrame()
    uri = df[url_col].fillna("/").astype(str)
    uri = uri.str.replace(r"^https?://[^/]+", "", regex=True)
    if body_col and body_col in df.columns:
        body = df[body_col].fillna("").astype(str).str.strip()
        sep = uri.str.contains(r"\?").map({True: "&", False: "?"})
        uri = uri.where(body == "", uri + sep + body)
    out["raw_uri"] = uri
    out["method"] = df[method_col].astype(str) if method_col and method_col in df.columns else "GET"
    if all_malicious:
        out["label"] = 1
    else:
        if not label_col or label_col not in df.columns:
            raise ValueError("give --label-col, or --all-malicious for attack-only data")
        lbl = df[label_col].astype(str).str.strip().str.lower()
        out["label"] = lbl.isin([str(v).lower() for v in malicious_values]).astype(int)
    return _finalize(out, dataset)


# ---------------------------------------------------------------------------
# Stratified splitting
# ---------------------------------------------------------------------------
def make_splits(parquet_path: str, out_dir: str,
                train=0.70, val=0.15, test=0.15, seed: int = SEED):
    """
    Stratified 70/15/15 split. Use the same --split-seed for every
    experiment so all seeds of training see the same test set.
    Attack-only corpora (one class) are written whole as test.parquet.
    """
    df = pd.read_parquet(parquet_path)
    os.makedirs(out_dir, exist_ok=True)
    if df["label"].nunique() < 2:
        df.reset_index(drop=True).to_parquet(os.path.join(out_dir, "test.parquet"))
        print(f"Single-class corpus: wrote all {len(df)} rows as {out_dir}/test.parquet")
        return
    train_df, temp = train_test_split(
        df, train_size=train, stratify=df["label"], random_state=seed)
    rel_val = val / (val + test)
    val_df, test_df = train_test_split(
        temp, train_size=rel_val, stratify=temp["label"], random_state=seed)
    for name, part in [("train", train_df), ("val", val_df), ("test", test_df)]:
        part.reset_index(drop=True).to_parquet(os.path.join(out_dir, f"{name}.parquet"))
    print(f"Splits written to {out_dir}")
    print(f"  train={len(train_df)}  val={len(val_df)}  test={len(test_df)}")
    print(f"  malicious ratio: "
          f"train={train_df['label'].mean():.3f} "
          f"val={val_df['label'].mean():.3f} "
          f"test={test_df['label'].mean():.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["csic_raw", "csv"])
    ap.add_argument("--normal"); ap.add_argument("--anomaly")
    ap.add_argument("--input"); ap.add_argument("--url-col"); ap.add_argument("--label-col")
    ap.add_argument("--method-col"); ap.add_argument("--dataset", default="custom")
    ap.add_argument("--split"); ap.add_argument("--out"); ap.add_argument("--out-dir")
    ap.add_argument("--split-seed", type=int, default=SEED)
    ap.add_argument("--model-input", choices=MODEL_INPUT_MODES, default="decoded",
                    help="which text goes into the 'text' column (default: "
                         "decoded, matching the live service)")
    ap.add_argument("--all-malicious", action="store_true",
                    help="attack-only CSV (e.g. the 2025 ModSecurity capture)")
    ap.add_argument("--body-col", help="optional request-body column to append")
    args = ap.parse_args()

    global MODEL_INPUT
    MODEL_INPUT = args.model_input

    if args.split:
        make_splits(args.split, args.out_dir or "data/splits", seed=args.split_seed)
        return

    if args.source == "csic_raw":
        df = load_csic_raw(args.normal, args.anomaly)
    elif args.source == "csv":
        df = load_csv(args.input, args.url_col, args.label_col,
                      args.dataset, args.method_col,
                      all_malicious=args.all_malicious, body_col=args.body_col)
    else:
        ap.error("provide --source or --split")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_parquet(args.out)
    print(f"Wrote {len(df)} rows -> {args.out}")
    print(df["label"].value_counts().to_dict())
    print(df["attack_type"].value_counts().to_dict())


if __name__ == "__main__":
    main()
