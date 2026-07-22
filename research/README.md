# Research Pipeline — Reproducible Experiments for the Q2 Paper

This folder turns the engineering prototype into a publishable study. Every
script maps to a Results section in `../JOURNAL_PAPER_SKELETON.md` and closes a
gap listed in `../RESEARCH_GAP_ANALYSIS.md`.

All experiments consume ONE unified data schema (`text, raw_uri, method, label,
attack_type, dataset`) and reuse the SAME rule engine (`waf_rules.py`) that the
deployed WAF uses — so the ablation and baselines are scientifically comparable
to the live system.

## Install

```bash
pip install -r research/requirements.txt
```

Training needs a GPU (Google Colab T4 is enough). Everything else runs on CPU.

## Experiment → paper-section map

| Script | Produces | Paper section | Gap closed |
|---|---|---|---|
| `prepare_datasets.py` | unified datasets + splits | 4.2 | #1 real data |
| `train.py` | fine-tuned model(s) | 4.4 | #1, #7 model identity |
| `evaluate.py --mode model` | transformer metrics | 6.1 | #2 metrics |
| `baselines.py` | SVM/RF/LogReg comparison | 6.1 | #3 baselines |
| `evaluate.py` (rules/model/hybrid) | ablation | 6.3 | #4 ablation |
| `evaluate.py` (train A, test B) | cross-dataset | 6.2 | #6 generalization |
| `threshold_sweep.py` | FPR-vs-recall curve | 6.4 | #3 FP control |
| `latency_benchmark.py` | latency/throughput | 6.5 | #5, GAP 1 deployability |
| `adversarial_eval.py` | evasion rates | 6.x | #8, GAP 5 robustness |

## Step 1 — Get the data

Download manually (links in `prepare_datasets.py` header), then:

```bash
# CSIC 2010 (raw HTTP dumps)
python research/prepare_datasets.py --source csic_raw \
  --normal data/raw/normalTrafficTraining.txt \
  --anomaly data/raw/anomalousTrafficTest.txt \
  --out data/processed/csic2010.parquet
python research/prepare_datasets.py --split data/processed/csic2010.parquet \
  --out-dir data/splits/csic2010

# A second dataset for cross-dataset testing (e.g. PKDD 2007 CSV export)
python research/prepare_datasets.py --source csv --input data/raw/pkdd2007.csv \
  --url-col request --label-col label --dataset pkdd2007 \
  --out data/processed/pkdd2007.parquet
python research/prepare_datasets.py --split data/processed/pkdd2007.parquet \
  --out-dir data/splits/pkdd2007
```

## Step 2 — Train (repeat per base model)

```bash
python research/train.py --train data/splits/csic2010/train.parquet \
  --val data/splits/csic2010/val.parquet \
  --model bert-base-uncased --out models/bert_csic

python research/train.py ... --model ehsanaghaei/SecureBERT --out models/securebert_csic
python research/train.py ... --model distilbert-base-uncased --out models/distilbert_csic
```

## Step 3 — Main results + baselines (Table 6.1)

```bash
python research/evaluate.py --mode model --model models/bert_csic \
  --test data/splits/csic2010/test.parquet --out results/bert_csic_model.json
python research/baselines.py --train data/splits/csic2010/train.parquet \
  --test data/splits/csic2010/test.parquet --out results/baselines_csic.json
```

## Step 4 — Ablation (Table 6.3): rules vs model vs hybrid

```bash
python research/evaluate.py --mode rules  --test data/splits/csic2010/test.parquet --out results/csic_rules.json
python research/evaluate.py --mode model  --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/csic_model.json
python research/evaluate.py --mode hybrid --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/csic_hybrid.json
```
The hybrid must beat both individual arms (or you report and discuss honestly).

## Step 5 — Cross-dataset generalization (Table 6.2)

```bash
# model trained on CSIC, tested on PKDD (unseen distribution)
python research/evaluate.py --mode model --model models/bert_csic \
  --test data/splits/pkdd2007/test.parquet --out results/cross_csic_to_pkdd.json
```

## Step 6 — Threshold sensitivity (Fig 6.4)

```bash
python research/threshold_sweep.py --model models/bert_csic \
  --test data/splits/csic2010/test.parquet --out results/threshold_csic.csv
```

## Step 7 — Latency (Table 6.5) — run on CPU and GPU

```bash
python research/latency_benchmark.py --mode offline --model models/bert_csic \
  --test data/splits/csic2010/test.parquet --n 2000 --out results/latency_offline.json
# with the Docker stack up:
python research/latency_benchmark.py --mode e2e --url http://localhost:8080/ \
  --n 2000 --concurrency 20 --out results/latency_e2e.json
```

## Step 8 — Adversarial evasion (robustness)

```bash
python research/adversarial_eval.py --model models/bert_csic \
  --test data/splits/csic2010/test.parquet --out results/adversarial_csic.json
```

## Reproducibility notes

- All seeds fixed to 42. Report exact package versions from `requirements.txt`.
- Distilled variant (`distilbert`) is your latency-vs-accuracy trade-off story.
- Real `ehsanaghaei/SecureBERT` vs `bert-base-uncased` is your "does domain
  pretraining help HTTP request classification?" experiment.
- Keep `results/*.json` — they are the raw numbers behind every table/figure.
