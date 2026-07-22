"""
Latency & throughput benchmark (Results 6.5 / GAP 1: deployable inline system).

Two independent measurements:

1. --mode offline : pure model inference latency on this machine.
   Reports p50/p95/p99 per-request latency and single-process throughput.
   Run with --model on CPU AND on GPU to report both.

2. --mode e2e : end-to-end latency through the LIVE Docker stack
   (nginx -> WAF -> backend). Sends concurrent HTTP requests and reports the
   full request latency percentiles the end user actually experiences.
   Compare: baseline app with WAF disabled vs. WAF enabled.

Usage
-----
  python latency_benchmark.py --mode offline --model models/bert_csic \
      --test data/splits/csic2010/test.parquet --n 2000 --out results/latency_offline.json

  python latency_benchmark.py --mode e2e --url http://localhost:8080/ \
      --n 2000 --concurrency 20 --out results/latency_e2e.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import sys
import time

import numpy as np
import pandas as pd


def pct(a):
    a = np.array(a)
    return {
        "count": int(a.size),
        "mean_ms": round(float(a.mean()), 3),
        "p50_ms": round(float(np.percentile(a, 50)), 3),
        "p95_ms": round(float(np.percentile(a, 95)), 3),
        "p99_ms": round(float(np.percentile(a, 99)), 3),
        "max_ms": round(float(a.max()), 3),
    }


def offline(args):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device).eval()

    texts = pd.read_parquet(args.test)["text"].tolist()[: args.n]
    # warmup
    with torch.no_grad():
        enc = tok(texts[:8], truncation=True, max_length=256,
                  padding=True, return_tensors="pt").to(device)
        model(**enc)

    lat = []
    with torch.no_grad():
        for t in texts:
            start = time.perf_counter()
            enc = tok([t], truncation=True, max_length=256,
                      padding=True, return_tensors="pt").to(device)
            _ = model(**enc).logits
            if device == "cuda":
                torch.cuda.synchronize()
            lat.append((time.perf_counter() - start) * 1000.0)

    stats = pct(lat)
    stats["device"] = device
    stats["throughput_rps"] = round(1000.0 / stats["mean_ms"], 1)
    return {"mode": "offline", "model": args.model, "latency": stats}


def e2e(args):
    import requests

    def one(_):
        start = time.perf_counter()
        try:
            requests.get(args.url, timeout=10)
        except Exception:
            return None
        return (time.perf_counter() - start) * 1000.0

    lat = []
    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for r in ex.map(one, range(args.n)):
            if r is not None:
                lat.append(r)
    wall = time.perf_counter() - t0

    stats = pct(lat)
    stats["concurrency"] = args.concurrency
    stats["achieved_rps"] = round(len(lat) / wall, 1)
    return {"mode": "e2e", "url": args.url, "latency": stats}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["offline", "e2e"], required=True)
    ap.add_argument("--model"); ap.add_argument("--test")
    ap.add_argument("--url", default="http://localhost:8080/")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = offline(args) if args.mode == "offline" else e2e(args)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
