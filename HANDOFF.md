# Project handoff: hybrid rule + transformer WAF (papers)

Authors: Priscilla Jospin G (corresponding), Rahul R, Karunya Institute of Technology and Sciences.
Repo: https://github.com/PriscillajospinG/transformer-waf-paper (private, branch main).
Paper files: `paper/journal/main.tex` (journal, Q1 target), `paper/conference/main.tex` (6-page IEEE, Saveetha conference, ID 26AIML894), `paper/references.bib` (84 entries, verified). Overleaf zips: `WAF_Journal_Overleaf.zip`, `WAF_Conference_Overleaf.zip`.
Code: `research/` (experiments), `colab/Q1_experiments.ipynb`, `waf/` (FastAPI detector), `nginx/`, `frontend/`, `scripts/`.
Second folder `transformer-waf-test` holds trained weights (`waf/model/weights/waf_model.pth`, 438 MB). Keep paper files identical in both folders.

## Rules from the user
- Never fabricate numbers or references. Real, verified sources only.
- One `main.tex` per paper. Same font and size everywhere. Journal abstract fully bold. Short table/figure captions.
- Make git commits one at a time; the user pushes.
- Do not change content when asked for format-only changes.
- Goal: lowest possible Turnitin AI score (user wants 0%) and low similarity (3%).

## System
Nginx `auth_request` -> FastAPI `/analyze` -> 200 allow / 403 block; fail-open on errors.
Tier 1: 8 direct signatures. Tier 2: rule signals (23 keywords, 6 injection regexes, 7 encoding regexes, special-char count). Tier 3: BERT probability. Tier 4 fusion, thresholds tau_h=0.98, tau_l=0.90; six block cases: s_dir; s_kw&s_inj; s_enc; p>tau_h & any signal; tau_l<=p<tau_h & (s_kw or s_ca); s_kw&s_ca.
Safelist endpoints (/socket.io/, /rest/, /api/, /assets/ ...) get Tier 1 + encoding checks only.

## Results currently in the journal (single earlier runs, not yet re-verified)
CSIC 2010 dedup 9,492 requests (68% malicious). BERT F1 0.949, FPR 0.064, AUC 0.974. TF-IDF SVM F1 0.965. Rules only F1 0.567, FPR 0.209. Hybrid F1 0.849, FPR 0.229. Latency median 12.7 ms, p99 18.2 ms (T4). Evasion 0.12% model-only, 0% hybrid. SR-BH zero-shot: model FPR 1.00, hybrid F1 0.971. 2025 ModSecurity corpus (attack-only): model recall 0.999, hybrid 0.151.

## Status (13 Nov 2026)
- Journal Turnitin (Nov 12 version): AI 21%, similarity 3%. Since then, rewrites in commits c9fd431 and 528ebd8 (about 97% of flagged passages reworded). Needs a fresh Overleaf compile and a new Turnitin run with "No Repository"; then rewrite only newly flagged passages.
- Conference paper: still missing the sixth fusion case; not recompiled after trims (check <=6 pages on Overleaf).
- Q1 experiments are written but NOT run: multi-seed mean/std, McNemar, bootstrap CIs, decoded-input retrain, calibration (ECE), learned fusion, rule refresh, encoder comparison, e2e latency (Docker), external WAF-A-MoLE. Run `colab/Q1_experiments.ipynb` on a T4 (start with SEEDS=[42]); datasets: CSIC 2010, 2025 Zenodo owasp.zip, SR-BH 2020 (Harvard Dataverse).
- Next: user uploads `results_q1.zip` (and `results/data_route.json`); update journal tables, figures and text with real measured numbers only.
- Add an AI-assistance disclosure line in the acknowledgments.
