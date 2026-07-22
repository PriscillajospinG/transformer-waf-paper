# Runbook — from code to a filled-in paper

Two stages: (A) generate the numbers, (B) drop them into the LaTeX and compile.
Nothing in the papers is fabricated — every red `[PLACEHOLDER]` is a value you
produce here.

---

## Stage A — Generate the results (once)

Easiest path is Google Colab (free T4 GPU). Local works too if you have a GPU.

### A0. Setup
```bash
pip install -r research/requirements.txt
```

### A1. Get datasets (manual download, links in research/prepare_datasets.py)
- CSIC 2010 raw files, and one more corpus (PKDD 2007 or SR-BH) for cross-dataset.
Then:
```bash
python research/prepare_datasets.py --source csic_raw \
  --normal data/raw/normalTrafficTraining.txt \
  --anomaly data/raw/anomalousTrafficTest.txt \
  --out data/processed/csic2010.parquet
python research/prepare_datasets.py --split data/processed/csic2010.parquet \
  --out-dir data/splits/csic2010
# repeat for the second dataset
```
→ fills **Table: Datasets** (journal Table II).

### A2. Train (GPU). Do bert first; add the others for the comparison.
```bash
python research/train.py --train data/splits/csic2010/train.parquet \
  --val data/splits/csic2010/val.parquet --model bert-base-uncased --out models/bert_csic
# optional variants:
python research/train.py ... --model ehsanaghaei/SecureBERT --out models/securebert_csic
python research/train.py ... --model distilbert-base-uncased --out models/distilbert_csic
```

### A3. Run every experiment
```bash
mkdir -p results
# main detection + baselines  -> Table: main
python research/evaluate.py --mode model  --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/bert_model.json
python research/baselines.py --train data/splits/csic2010/train.parquet --test data/splits/csic2010/test.parquet --out results/baselines.json
# ablation -> Table: ablation
python research/evaluate.py --mode rules  --test data/splits/csic2010/test.parquet --out results/rules.json
python research/evaluate.py --mode hybrid --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/hybrid.json
# cross-dataset -> Table: cross
python research/evaluate.py --mode model --model models/bert_csic --test data/splits/pkdd2007/test.parquet --out results/cross.json
# threshold sweep -> Fig: threshold  (produces a CSV to plot)
python research/threshold_sweep.py --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/threshold.csv
# latency -> Table: latency
python research/latency_benchmark.py --mode offline --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/latency_offline.json
python research/latency_benchmark.py --mode e2e --url http://localhost:8080/ --out results/latency_e2e.json   # Docker stack up
# adversarial -> Table: adv
python research/adversarial_eval.py --model models/bert_csic --test data/splits/csic2010/test.parquet --out results/adversarial.json
```

Each script prints a summary and writes JSON/CSV to `results/`.

---

## Stage B — Fill the LaTeX and compile

### B1. Where each number goes (journal `paper/journal/main.tex`)

| results file | LaTeX table/figure |
|---|---|
| prepare_datasets.py stdout | Table II (datasets) |
| results/bert_model.json, baselines.json, rules.json, hybrid.json | Table III (main) |
| results/rules.json, bert_model.json, hybrid.json | Table IV (ablation) |
| results/cross.json | Table V (cross-dataset) |
| results/threshold.csv | Fig. (threshold sweep) |
| results/latency_offline.json, latency_e2e.json | Table VI (latency) |
| results/adversarial.json | Table VII (adversarial) |
| headline F1/FPR/latency | Abstract + Conclusion |

Read a JSON like: `metrics.f1`, `metrics.fpr`, `metrics.precision`,
`metrics.recall`, `metrics.roc_auc`. Replace each `\ph{...}` with the value.
Search the .tex for `\ph` — when none remain, the paper has no placeholders left.

### B2. Threshold figure
Plot `results/threshold.csv` (x=threshold, y=fpr and recall). Either export a PDF
from matplotlib and `\includegraphics` it, or use pgfplots to read the CSV. Then
replace the placeholder `\fbox{...}` in Fig. (threshold).

### B3. Compile (Overleaf — recommended)
1. Create a new Overleaf project; upload `paper/journal/main.tex` and
   `paper/references.bib` (keep `references.bib` one level up, or change the
   `\bibliography{../references}` path to `\bibliography{references}` if you put
   them in the same folder).
2. Set compiler to **pdfLaTeX**. Run: pdfLaTeX → BibTeX → pdfLaTeX → pdfLaTeX.
3. Repeat for `paper/conference/main.tex`.

Overleaf already has `IEEEtran`, `algorithm`, `algpseudocode`, `tikz`,
`booktabs`, `pgfplots` — no installation needed.

---

## Before you submit (integrity + quality)

- [ ] No `\ph{...}` placeholders remain in either paper.
- [ ] **Verify every `references.bib` entry** against the real paper: exact
  author list, title, venue, year, DOI/arXiv ID. Entries currently marked with
  generic authors (`Author, and others`, `Anonymous`) MUST be corrected — do not
  submit with unverified authorship.
- [ ] Fill author/affiliation blocks (currently `\ph{Institution}` etc.).
- [ ] Model naming: if you did NOT fine-tune real SecureBERT, remove SecureBERT
  rows/claims and describe the encoder as BERT-base.
- [ ] Similarity check < 15–20%; keep journal↔conference textual overlap < 30%
  and cite the conference paper in the journal version.
- [ ] Figures are vector (PDF); tables render in IEEEtran two-column.
- [ ] Re-read Discussion/Limitations against your actual numbers (fail-open rate,
  evasion rate) so claims match evidence.
