# Research Pipeline — Experiments for the Journal Paper

Every script maps to a Results section and produces a JSON/CSV that the
paper reads. All experiments share ONE data schema and reuse the SAME rule
engine (`waf_rules.py`) that the deployed WAF runs, so the ablation and the
live system agree.

## Install

```bash
pip install -r research/requirements.txt
```

Training needs a GPU (Colab T4 is enough). Everything else runs on CPU.
`stats_tests.py` and `calibration.py` need only NumPy and pandas.

## What changed for the Q1 upgrade

These are the gaps a Q1 reviewer will raise, and the script that now closes
each one. None of these produce numbers by themselves — you run them on your
machine and the real outputs go into the paper.

| Gap | What to run | New/updated |
|---|---|---|
| One run, no variance | train with 5 seeds, then `stats_tests.py aggregate` | `train.py --seed`, `stats_tests.py` |
| No significance test | `stats_tests.py mcnemar` / `bootstrap` | `stats_tests.py` |
| Train/deploy input mismatch | `--model-input decoded` (now the default) | `prepare_datasets.py`, `waf_rules.py` |
| Model-only latency | `latency_benchmark.py --mode e2e` | already present |
| One dataset, one transfer direction | prepare a 2nd/3rd corpus, evaluate both ways | `prepare_datasets.py` (`--all-malicious`, `--body-col`) |
| Weak evasion test | all blocked payloads + external WAF-A-MoLE | `adversarial_eval.py` (see note) |
| Encoders not compared | train bert / securebert / distilbert | `train.py --model` |
| "Calibration not ranking" unproven | `calibration.py` (ECE + temperature scaling) | `calibration.py` |
| Rule layer refresh untested | `--rules-config` on the 2025 corpus | `waf_rules.py`, `evaluate.py` |
| Fixed fusion vs learned | `learned_fusion.py` | `learned_fusion.py` |
| Which branch fired | `branch_counts` in every `evaluate.py` run | `evaluate.py` |

## Step 1 — Data (decoded input is the default)

Download the corpora (links in `prepare_datasets.py`), then:

```bash
# CSIC 2010 — model input = double-decoded URI (matches the live service)
python research/prepare_datasets.py --source csic_raw \
  --normal data/raw/normalTrafficTraining.txt \
  --anomaly data/raw/anomalousTrafficTest.txt \
  --model-input decoded --out data/processed/csic2010.parquet
python research/prepare_datasets.py --split data/processed/csic2010.parquet \
  --out-dir data/splits/csic2010

# A real second corpus for cross-dataset (e.g. SR-BH 2020 CSV)
python research/prepare_datasets.py --source csv --input data/raw/srbh2020.csv \
  --url-col request --label-col label --dataset srbh2020 \
  --model-input decoded --out data/processed/srbh2020.parquet
python research/prepare_datasets.py --split data/processed/srbh2020.parquet \
  --out-dir data/splits/srbh2020

# The 2025 ModSecurity capture is attack-only:
python research/prepare_datasets.py --source csv --input data/raw/modsec2025.csv \
  --url-col uri --all-malicious --body-col body --dataset modsec2025 \
  --model-input decoded --out data/processed/modsec2025.parquet
python research/prepare_datasets.py --split data/processed/modsec2025.parquet \
  --out-dir data/splits/modsec2025   # writes the whole set as test.parquet
```

`text` is the decoded input; `text_raw` and `text_decoded` are also stored
so you can run the preprocessing ablation without rebuilding.

## Step 2 — Train (per seed, per encoder)

```bash
for s in 42 1 7 13 21; do
  python research/train.py --train data/splits/csic2010/train.parquet \
    --val data/splits/csic2010/val.parquet \
    --model bert-base-uncased --seed $s --out models/bert_csic_s$s
done
# encoder comparison (one seed is enough to start):
python research/train.py ... --model ehsanaghaei/SecureBERT --out models/securebert_csic_s42
python research/train.py ... --model distilbert-base-uncased --out models/distilbert_csic_s42
```

Each model dir gets a `run_meta.json` recording seed, encoder, library
versions and the exact settings — keep it with the results.

## Step 3 — Main results, ablation, baselines (per seed)

```bash
for s in 42 1 7 13 21; do
  for mode in model rules hybrid; do
    python research/evaluate.py --mode $mode --model models/bert_csic_s$s \
      --test data/splits/csic2010/test.parquet \
      --out results/csic/${mode}_s$s.json --dump-preds results/csic/${mode}_s$s.csv \
      --dump-logits results/csic/${mode}_logits_s$s.npy
  done
done
python research/baselines.py --train data/splits/csic2010/train.parquet \
  --test data/splits/csic2010/test.parquet --text-col text_decoded \
  --out results/csic/baselines.json
```

Aggregate across seeds and test significance:

```bash
python research/stats_tests.py aggregate --inputs "results/csic/hybrid_s*.json" \
  --out results/csic/hybrid_agg.json          # mean +/- std, ready for LaTeX
python research/stats_tests.py mcnemar --a results/csic/model_s42.csv \
  --b results/csic/hybrid_s42.csv --out results/csic/mcnemar_model_vs_hybrid.json
python research/stats_tests.py bootstrap --preds results/csic/hybrid_s42.csv \
  --out results/csic/hybrid_s42_ci.json
```

## Step 4 — Threshold sweep and operating points

```bash
python research/threshold_sweep.py --model models/bert_csic_s42 \
  --test data/splits/csic2010/test.parquet --text-col text \
  --out results/csic/threshold_s42.csv
# writes threshold_s42_points.json: best-recall threshold per FPR budget
```

## Step 5 — Cross-dataset, both directions

```bash
# CSIC-trained -> SR-BH and -> 2025 (zero-shot)
python research/evaluate.py --mode hybrid --model models/bert_csic_s42 \
  --test data/splits/srbh2020/test.parquet --out results/transfer/csic2srbh_hybrid.json \
  --dump-logits results/transfer/csic2srbh_logits.npy
python research/evaluate.py --mode hybrid --model models/bert_csic_s42 \
  --test data/splits/modsec2025/test.parquet --out results/transfer/csic2modsec_hybrid.json
# reverse direction: train on SR-BH, test on CSIC
python research/train.py --train data/splits/srbh2020/train.parquet \
  --val data/splits/srbh2020/val.parquet --model bert-base-uncased \
  --seed 42 --out models/bert_srbh_s42
python research/evaluate.py --mode hybrid --model models/bert_srbh_s42 \
  --test data/splits/csic2010/test.parquet --out results/transfer/srbh2csic_hybrid.json
```

## Step 6 — Calibration (tests the SR-BH explanation)

```bash
# save validation logits once, then fit temperature and measure ECE
python research/evaluate.py --mode model --model models/bert_csic_s42 \
  --test data/splits/csic2010/val.parquet --out results/csic/val_s42.json \
  --dump-logits results/csic/val_logits_s42.npy
python research/calibration.py --fit-logits results/csic/val_logits_s42.npy \
  --fit-split data/splits/csic2010/val.parquet \
  --eval results/csic/model_logits_s42.npy:data/splits/csic2010/test.parquet:csic \
  --eval results/transfer/csic2srbh_logits.npy:data/splits/srbh2020/test.parquet:srbh \
  --out results/calibration_s42.json --bins-dir results/figs
# then re-evaluate with the fitted temperature:
python research/evaluate.py --mode model --logits-in results/transfer/csic2srbh_logits.npy \
  --test data/splits/srbh2020/test.parquet --temperature <T> \
  --out results/transfer/csic2srbh_model_calibrated.json
```

## Step 7 — Rule refresh and learned fusion

```bash
# write a refreshed rule set (new keywords/patterns for modern payloads),
# then re-run the 2025 transfer to test the paper's prediction:
python research/evaluate.py --mode hybrid --model models/bert_csic_s42 \
  --test data/splits/modsec2025/test.parquet --rules-config configs/rules_2025.json \
  --out results/transfer/csic2modsec_refreshed.json

# fixed fusion vs a learned combiner over the same signals:
python research/evaluate.py --mode model --model models/bert_csic_s42 \
  --test data/splits/csic2010/train.parquet --out results/csic/model_train_s42.json \
  --dump-preds results/csic/model_train_s42.csv
python research/learned_fusion.py --learner logreg \
  --train-split data/splits/csic2010/train.parquet \
  --train-scores results/csic/model_train_s42.csv \
  --test-split data/splits/csic2010/test.parquet \
  --test-scores results/csic/model_s42.csv \
  --out results/csic/learned_fusion_s42.json
```

## Step 8 — Latency, end to end

```bash
python research/latency_benchmark.py --mode offline --model models/bert_csic_s42 \
  --test data/splits/csic2010/test.parquet --n 2000 --out results/latency_offline_gpu.json
# with the Docker stack up (WAF on), and again with it bypassed (WAF off):
python research/latency_benchmark.py --mode e2e --url http://localhost:8080/ \
  --n 2000 --concurrency 20 --out results/latency_e2e_on.json
```

## Step 9 — Adversarial evasion

The six fixed mutations are in `adversarial_eval.py`; run it over ALL blocked
payloads (`--sample 0`) and match the training input mode:

```bash
python research/adversarial_eval.py --model models/bert_csic_s42 \
  --test data/splits/csic2010/test.parquet --sample 0 --model-input decoded \
  --out results/csic/adversarial_hybrid_s42.json
```

For the **stronger, search-based** attack a Q1 reviewer will expect, use the
published open-source tool **WAF-A-MoLE** (Demetrio et al.) against the
detection service's `/analyze` endpoint, rather than a payload generator in
this repo. Report its evasion rate against the query budget. This keeps the
attack side reproducible and standard.

## Step 10 — Figures

```bash
python research/make_figures.py --results results --fig-dir results/figs \
  --scores results/csic/model_s42.csv:bert results/csic/hybrid_s42.csv:hybrid
```

## Reproducibility

- Train with several seeds; report mean +/- std and a significance test for
  every comparison the paper makes.
- Keep every `results/**/*.json`, `run_meta.json` and the exact commands.
- Record library versions (they are saved in `run_meta.json`).
- Do NOT fabricate any number. Each table cell should trace to a file in
  `results/`.
