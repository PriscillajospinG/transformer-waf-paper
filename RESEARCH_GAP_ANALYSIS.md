# Research Gap Analysis — Transformer-Based WAF
Survey of existing literature vs. your project, the gaps you can claim, and the fixes required before submission. Companion to `JOURNAL_PAPER_SKELETON.md`.

---

## 1. What the literature has already done (survey summary)

| Work / Area | What they did | Dataset(s) | Results | What they did NOT do |
|---|---|---|---|---|
| WADBERT (arXiv 2026) | Dual-channel BERT (request + URL channel) web attack detection | CSIC 2010 | 99.70% acc, 99.63% F1 | Offline only — no deployment, no latency, no blocking |
| BERT–LSTM hybrid (IET Info. Security 2024) | BERT embeddings + LSTM for SQLi detection | SQLi payload corpora | 97.3% acc | Single attack class, offline |
| XSS+SQLi DL (Sci. Reports 2023/24) | CNN/DL payload classifiers | Payload datasets | high acc | No system integration, no FPR-at-threshold analysis |
| Command injection DL (Sci. Reports 2024) | Novel DL for command injection | Custom | high acc | Single attack class |
| HTTP2vec (arXiv) | Self-supervised HTTP request embeddings | CSIC 2010 | — | Anomaly detection only, no inline system |
| ADL-WAF (arXiv 2025) | Dual-layer ML WAF (anomaly + threat) | Mixed | — | Closest competitor — study this paper closely; limited latency/deployment detail |
| DistilXIDS (Neurocomputing 2025) | Distilled transformer, real-time NIDS, explainable | DDoS/NIDS sets | >99% F1, low latency | Network intrusion (flows), not HTTP/WAF |
| WAF-A-MoLE (2020) | Adversarial mutation to EVADE ML WAFs | SQLi | shows ML WAFs evadable | Attack paper — defenses still open |
| SecureBERT / SecureBERT 2.0 (Aghaei et al., 2022/2025) | Domain-pretrained cybersecurity LM | CTI corpora | SOTA on cyber NLP tasks | Never applied to inline WAF request classification |
| XAI-in-IDS reviews (Frontiers 2025, PeerJ) | SHAP/LIME/attention explanations for detections | various | — | XAI rarely integrated into WAF decisions; overhead problem open |

**Pattern across ~90% of published transformer-WAF work:** train a model on CSIC 2010, report 99%+ accuracy, stop. Classification papers, not firewall papers.

---

## 2. The research gaps (what nobody or almost nobody has done)

These are the gaps YOUR paper can legitimately claim. Ranked by how well your existing project supports them.

**GAP 1 — Offline classifiers vs. deployed inline systems.** Papers report accuracy on frozen datasets; almost none deploy the model in the live blocking path and measure end-to-end p50/p99 latency, throughput, and detection under real traffic. Literature explicitly names this as future work. *Your nginx auth_request architecture already does the deployment part — you only need the measurements.* → **Your primary claim.**

**GAP 2 — No principled rule+transformer decision fusion.** Commercial WAFs are rules-only; academic ones are model-only. Confidence-banded fusion (block iff high AI confidence AND rule signal; uncertainty band handling; endpoint-aware policy; fail-open) is essentially unstudied with ablation evidence. *You built this — you need the ablation proving fusion beats either alone.* → **Your secondary claim.**

**GAP 3 — False-positive control as a first-class objective.** Papers optimize accuracy/F1; operators care about FPR at an operating point. Threshold sensitivity curves (FPR vs recall trade-off) with a justified operating point are rare. *Your dual-threshold design maps directly onto this.*

**GAP 4 — Cross-dataset generalization.** Nearly everything trains AND tests on CSIC 2010 (synthetic, 15+ years old). Train-on-one/test-on-another (CSIC → SR-BH 2020 real honeypot traffic) is rare and is the honest version of a "zero-day" claim. *Doable with your pipeline once real datasets are in.*

**GAP 5 — Adversarial robustness of transformer WAFs.** WAF-A-MoLE showed ML WAFs are evadable; almost no transformer-WAF paper tests evasion (encoding tricks, case mutation, comment injection, payload mutation) or reports robustness. *Optional but high-value: even a small evasion experiment lifts the paper a tier.*

**GAP 6 — Domain-pretrained vs. general LM for request classification.** Nobody has compared bert-base vs. real SecureBERT/DistilBERT for HTTP request classification under a latency budget. *Cheap to add: three fine-tuning runs on the same data.*

Gaps you should NOT chase (crowded/out of scope): raw accuracy leaderboards on CSIC 2010; XAI integration (own paper); federated/distributed WAF; LLM-based detection.

---

## 3. What is MISSING in your project (must-fix list)

Ordered. Items 1–6 are mandatory for any SCI Q2 journal; 7–9 strengthen it.

| # | Missing item | Current state | Fix |
|---|---|---|---|
| 1 | **Real training data** | 5,000 samples generated from 39 hard-coded templates | Train on CSIC 2010 + SR-BH 2020 (+ optional PKDD 2007 / FWAF / SecLists payloads). Proper 70/15/15 stratified splits, fixed seeds |
| 2 | **Measured metrics** | None — only pass/fail curl tests | Evaluation script: Precision, Recall, F1, FPR, ROC-AUC per dataset + per attack class |
| 3 | **Baselines** | None | ModSecurity+OWASP CRS on same test set; TF-IDF+SVM; TF-IDF+RandomForest; cite published CSIC numbers (e.g., WADBERT) |
| 4 | **Ablation** | None — rules likely catch everything before BERT runs | Three runs: rules-only / model-only / hybrid. This proves the transformer earns its latency cost |
| 5 | **Latency benchmark** | "50–80ms" claimed, never measured | wrk/locust against Docker stack: p50/p95/p99, max RPS, for nginx-only vs +rules vs +full pipeline |
| 6 | **Cross-dataset test** | Nothing | Train CSIC → test SR-BH (and reverse); per-class transfer analysis |
| 7 | Model identity | Named "SecureBERT" but uses bert-base-uncased | Fine-tune real SecureBERT (HuggingFace: ehsanaghaei/SecureBERT) and compare, or rename throughout |
| 8 | Adversarial evasion test | Nothing | Mutate blocked payloads (encodings, case, comments, whitespace); report evasion rate; cite WAF-A-MoLE |
| 9 | Broken/risky components | online_learning.py crashes (wrong constructor args) and label-poisons (allowed⇒benign); POST bodies not inspected; "outgoing traffic" claim false | Delete or fix online learning (move to future work); scope claims to request-line inspection; remove "zero-day"/"production-ready" language |

**Also missing for submission mechanics:** related-work bibliography (40+ refs), reproducibility package (seeds, scripts, README), vector figures, similarity check.

---

## 4. Your positioning statement (use in Intro and cover letter)

> "Prior transformer-based web attack detectors achieve near-perfect offline accuracy on CSIC 2010 but stop at classification: they are not deployed inline, report no latency, ignore false-positive control, and rarely test generalization beyond their training distribution. We present a deployable hybrid WAF that integrates a fine-tuned transformer into the live blocking path via nginx auth_request, governs decisions with a confidence-banded rule–model fusion policy designed to bound false positives, and evaluate it end-to-end: detection quality across datasets, ablation of each layer, threshold sensitivity, and measured latency/throughput under load."

---

## 5. Execution order (fixes → paper sections)

1. Dataset pipeline + retraining (fix #1, #7) → unblocks everything
2. Evaluation harness (fix #2) → Results 6.1
3. Baselines (fix #3) → Results 6.1
4. Ablation (fix #4) → Results 6.3 — supports GAP 2 claim
5. Cross-dataset (fix #6) → Results 6.2 — supports GAP 4 claim
6. Latency benchmark (fix #5) → Results 6.5 — supports GAP 1 claim
7. Threshold sweep → Results 6.4 — supports GAP 3 claim
8. (Optional) evasion experiment (fix #8) — supports GAP 5 claim
9. Code/claims cleanup (fix #9) + write paper per skeleton

---

## 6. Key sources

- [WADBERT: Dual-channel Web Attack Detection Based on BERT Models](https://arxiv.org/html/2601.21893)
- [BERT–LSTM SQL Injection Detection — IET Information Security 2024](https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/2024/5565950)
- [Securing web applications against XSS and SQLi — Scientific Reports](https://www.nature.com/articles/s41598-023-48845-4)
- [Command injection detection via deep learning — Scientific Reports 2024](https://www.nature.com/articles/s41598-024-74350-3)
- [ADL-WAF: Adaptive Dual-Layer WAF (arXiv)](https://arxiv.org/pdf/2511.12643)
- [HTTP2vec: Embedding of HTTP Requests (arXiv)](https://arxiv.org/pdf/2108.01763)
- [WAF-A-MoLE: Evading WAFs through Adversarial ML (arXiv)](https://arxiv.org/pdf/2001.01952)
- [SecureBERT: A Domain-Specific Language Model for Cybersecurity (arXiv)](https://arxiv.org/abs/2204.02685) · [SecureBERT 2.0 (arXiv)](https://arxiv.org/abs/2510.00240) · [HuggingFace model](https://huggingface.co/ehsanaghaei/SecureBERT)
- [DistilXIDS: lightweight explainable transformer NIDS — Neurocomputing](https://www.sciencedirect.com/science/article/abs/pii/S092523122503070X)
- [Lightweight Transformer Architectures for Edge Devices (arXiv 2026)](https://arxiv.org/abs/2601.03290)
- [SR-BH / multi-label web attack dataset — Computers & Security](https://www.sciencedirect.com/science/article/pii/S0167404822001833)
- [ECML/PKDD 2007 HTTP attack classification study](https://www.osti.gov/biblio/1113394)
- [Combined ECML/PKDD 2007 + CSIC 2010 datasets (GitHub)](https://github.com/msudol/Web-Application-Attack-Datasets)
- [FWAF dataset (Kaggle)](https://www.kaggle.com/datasets/evg3n1j/fwaf-dataset)
- [Overview of public datasets for web application attack detection](http://injoit.org/index.php/j1/article/view/1770)
- [XAI in intrusion detection — Frontiers in AI 2025](https://www.frontiersin.org/journals/artificial-intelligence/articles/10.3389/frai.2025.1526221/full)
