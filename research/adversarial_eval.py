"""
Adversarial evasion evaluation (Results 6.x / GAP 5: robustness).

Takes malicious requests that the system currently BLOCKS, applies semantics-
preserving mutations (the kinds real attackers use), and measures how many
mutated payloads now EVADE detection. Reports evasion rate per mutation and
overall. This is the WAF-A-MoLE-style test that almost no transformer-WAF
paper includes; adding it materially strengthens the submission.

Mutation set (each preserves attack intent):
  - inline SQL comments:       ' OR 1=1  ->  '/**/OR/**/1=1
  - case randomization:        UNION SELECT -> uNiOn SeLeCt
  - URL-encoding of chars:     < -> %3C, ' -> %27
  - double URL-encoding:       ../ -> %252e%252e%252f
  - whitespace alternatives:   space -> %09 / + / /**/
  - trailing junk parameter:   &x=<random>

Usage
-----
  python adversarial_eval.py --model models/bert_csic \
      --test data/splits/csic2010/test.parquet --out results/adversarial_csic.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from urllib.parse import quote

import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from evaluate import model_probs  # noqa: E402
from waf_rules import fuse_decision, preprocess_request  # noqa: E402

random.seed(42)


def m_comment(u):
    return re.sub(r"\s+", "/**/", u)


def m_case(u):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in u)


def m_urlencode(u):
    return quote(u, safe="/?=&%")


def m_double_encode(u):
    return quote(quote(u, safe=""), safe="")


def m_ws_tab(u):
    return u.replace(" ", "%09")


def m_junk(u):
    sep = "&" if "?" in u else "?"
    return f"{u}{sep}x={random.randint(1000,9999)}"


MUTATIONS = {
    "inline_comment": m_comment,
    "case_random": m_case,
    "url_encode": m_urlencode,
    "double_encode": m_double_encode,
    "whitespace_tab": m_ws_tab,
    "junk_param": m_junk,
}


def blocked(model_dir, method, uri, tau_high, tau_low):
    p = model_probs(model_dir, [preprocess_request(method, uri)])[0]
    return fuse_decision(method, uri, p, tau_high, tau_low)[0], p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--sample", type=int, default=300,
                    help="max malicious samples to attack (speed)")
    ap.add_argument("--tau-high", type=float, default=0.98)
    ap.add_argument("--tau-low", type=float, default=0.90)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    df = pd.read_parquet(args.test)
    mal = df[df["label"] == 1]
    if len(mal) > args.sample:
        mal = mal.sample(args.sample, random_state=42)

    # keep only payloads that are actually blocked to begin with
    base_uris = mal["raw_uri"].tolist()
    base_methods = mal["method"].tolist()
    base_texts = [preprocess_request(m, u) for m, u in zip(base_methods, base_uris)]
    base_probs = model_probs(args.model, base_texts)
    caught = [(m, u) for m, u, p in zip(base_methods, base_uris, base_probs)
              if fuse_decision(m, u, p, args.tau_high, args.tau_low)[0]]

    n = len(caught)
    results = {"initially_blocked": n, "per_mutation": {}, "note":
               "evasion_rate = fraction of originally-blocked payloads that "
               "slip through after mutation (higher = weaker defense)"}

    for name, fn in MUTATIONS.items():
        mutated_uris = [fn(u) for _, u in caught]
        mutated_texts = [preprocess_request(m, u)
                         for (m, _), u in zip(caught, mutated_uris)]
        probs = model_probs(args.model, mutated_texts)
        evaded = 0
        for (m, _), u, p in zip(caught, mutated_uris, probs):
            if not fuse_decision(m, u, p, args.tau_high, args.tau_low)[0]:
                evaded += 1
        results["per_mutation"][name] = {
            "evaded": evaded,
            "evasion_rate": round(evaded / n, 4) if n else 0.0,
        }

    overall = (sum(v["evaded"] for v in results["per_mutation"].values())
               / (n * len(MUTATIONS))) if n else 0.0
    results["overall_evasion_rate"] = round(overall, 4)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)
    print(json.dumps(results, indent=2))
    print(f"saved -> {args.out}")


if __name__ == "__main__":
    main()
