# Journal Paper Skeleton — Transformer-Based Web Application Firewall
**Target venues (Q1/Q2, SCI/Scopus):** Journal of Information Security and Applications (Elsevier), Computers & Security (Elsevier), Computer Networks (Elsevier), Cluster Computing (Springer), IEEE Access.
**Length target:** 25–35 manuscript pages double-spaced (≈8,000–11,000 words), 8–12 figures/tables, 40–60 references.

**Legend used below:**
- ✅ HAVE — you can write this today from the existing project
- ⚠️ PARTIAL — exists but must be corrected before writing
- ❌ MISSING — requires new experiments before this section can be written

---

## Title (pick one direction, refine later)

1. "A Hybrid Rule–Transformer Web Application Firewall with Inline Blocking and False-Positive-Controlled Decision Fusion"
2. "Deployable Transformer-Based Web Application Firewall: A Latency-Aware Hybrid Detection Architecture"
3. "Inline Detection of Web Attacks Using Fine-Tuned BERT with Multi-Tier Decision Fusion"

**Guidance:** Avoid "SecureBERT" in the title unless you actually fine-tune the real SecureBERT model (ehsanaghaei/SecureBERT). Avoid "AI-powered" and "zero-day" — reviewers see these as marketing terms. The title should promise exactly what the experiments deliver.

---

## Abstract (150–250 words) — write LAST

Template structure (one sentence each):
1. Problem: signature-based WAFs miss obfuscated/novel attacks and generate false positives.
2. Gap: prior transformer-based detectors are evaluated offline; few are deployed as real inline blocking systems with measured latency.
3. Proposal: hybrid architecture — nginx auth_request interception + tiered rules + fine-tuned BERT classifier + confidence-based decision fusion.
4. Evaluation: datasets used, key numbers (F1, FPR, cross-dataset F1, p99 latency). ❌ numbers missing
5. Result claim: e.g., "achieves F1 of X with FPR of Y at Z ms median latency, and retains F1 of W on an unseen dataset."
6. Significance: practical deployability of transformer-based inline WAFs.

---

## 1. Introduction (1.5–2 pages) — ✅ mostly writable now

Content flow:
- Para 1: Web attack landscape (SQLi, XSS, path traversal, command injection). Cite OWASP Top 10, recent breach statistics.
- Para 2: Limitations of rule-based WAFs (ModSecurity/CRS): brittle regex, maintenance burden, false positives on modern apps (WebSockets, SPAs). ✅ you have this argument in report.txt
- Para 3: Rise of ML/DL detection; why transformers (semantic understanding of payloads vs. token matching).
- Para 4: THE GAP — most transformer-WAF papers stop at offline classification. Real deployment questions unanswered: latency, false-positive control, decision fusion with rules, fail-open behavior. **This is your paper's identity.**
- Para 5: Contributions — numbered list, 4 items max:
  - C1: A deployable hybrid rule–transformer WAF architecture using nginx auth_request for transparent inline blocking (no app changes). ✅
  - C2: A multi-tier decision-fusion policy (signatures → anomaly rules → transformer confidence bands → endpoint-aware policy) designed to bound false positives. ✅ (design exists; effectiveness must be measured ❌)
  - C3: Empirical evaluation on N public datasets incl. cross-dataset generalization and ablation isolating the transformer's contribution. ❌
  - C4: Latency/throughput characterization of transformer inference in the inline blocking path. ❌
- Para 6: Paper organization.

**Pitfall:** do NOT claim "zero-day detection" as a contribution. Reframe as "generalization to attack variants unseen during training (cross-dataset evaluation)."

---

## 2. Related Work (1.5–2 pages) — ✅ writable now (literature search needed)

Organize in 4 subsections, each ending with the shortcoming your work addresses:

- **2.1 Rule/signature-based WAFs:** ModSecurity + OWASP CRS, commercial WAFs (Cloudflare, AWS WAF). Shortcoming: evasion via obfuscation, FP tuning burden.
- **2.2 Classical ML for web attack detection:** SVM, Random Forest, n-gram/TF-IDF features on CSIC 2010; anomaly detection approaches. Shortcoming: handcrafted features, poor generalization.
- **2.3 Deep learning & transformer-based detection:** CNN/LSTM payload classifiers; BERT/DistilBERT for SQLi/XSS detection; SecureBERT (Aghaei et al.) for cyber-domain language. Shortcoming: offline evaluation only, no deployment/latency analysis, no fusion with rules.
- **2.4 Comparison table:** rows = prior works, columns = {model, dataset(s), inline deployment?, latency reported?, FP control mechanism?, cross-dataset eval?}. Your row has ✓ in the columns others lack. **This table sells the paper.**

**Action:** collect 40+ references. Search terms: "BERT web attack detection", "transformer WAF", "HTTP request classification deep learning", "CSIC 2010", "malicious URL detection transformer".

---

## 3. System Architecture (2–3 pages) — ✅ fully writable now

- **3.1 Overview + Figure 1:** container topology (nginx / WAF service / backend), request flow with auth_request subrequest. Redraw your README diagram professionally (draw.io → PDF/vector).
- **3.2 Traffic interception:** nginx auth_request mechanism, X-Original-* header contract, why this gives zero-app-change deployment. ✅
- **3.3 Detection pipeline + Figure 2 (decision flowchart):** the exact logic from `evaluate_request()` and `/analyze`:
  - Tier 1 direct signatures → block
  - Tier 2 anomaly/encoding/injection rules
  - Tier 3 transformer inference (preprocessing: `METHOD URI`, digit→{ID} normalization, double URL-decode, 256 tokens)
  - Tier 4 fusion: block iff (p > τ_high AND rule signal) OR (τ_low ≤ p < τ_high AND keyword/char anomaly)
- **3.4 False-positive control:** safe-endpoint policy (Tier-1-only checks on whitelisted routes), CSRF header-consistency check, fail-open on inference error. ✅ — frame fail-open honestly as an availability-vs-security tradeoff and cite it again in Limitations.
- **3.5 Observability:** dashboard, structured JSON logging, stats API. Keep to 1 short paragraph + optional screenshot. NOT a contribution.

**Pitfall:** describe thresholds (0.90/0.98) as configurable parameters whose values are *derived from the sensitivity analysis in Section 6* — not magic numbers.

---

## 4. Methodology (2 pages) — ⚠️ rewrite after retraining

- **4.1 Problem formulation:** binary classification of HTTP request lines; define input space, labels.
- **4.2 Datasets — ❌ THE critical fix:**
  - CSIC 2010 (36k benign / 25k anomalous) — standard benchmark, enables comparison with prior work.
  - One modern set: SR-BH 2020, or FWAF, or PKDD 2007 — for cross-dataset testing.
  - Optional third source: payloads from SecLists/OWASP corpora injected into benign URL structures.
  - Table: per-dataset sample counts, benign/malicious ratio, attack-type breakdown.
  - Splits: 70/15/15 train/val/test, stratified; state random seeds.
  - **Delete all mention of the 39 synthetic templates from the paper. Current training data cannot appear in a Q2 submission.**
- **4.3 Preprocessing & tokenization:** normalization steps, WordPiece on bert-base-uncased, max_len 256, discussion of why digit-masking helps. ⚠️ exists in code; document it.
- **4.4 Model:** BERT-base + dropout(0.3) + linear head on [CLS]; fine-tuning setup (AdamW, lr=1e-5, epochs, batch size, early stopping on val F1). ⚠️ retrain required. Include the real SecureBERT as a second variant if feasible — "BERT vs. domain-pretrained SecureBERT" is a nice built-in experiment.
- **4.5 Decision fusion formalization:** write the Tier 1–4 logic as an algorithm box (Algorithm 1). ✅

---

## 5. Experimental Setup (1 page) — ❌ all new

- Hardware/software: CPU/GPU specs, PyTorch/transformers versions, Docker versions.
- Metrics: Accuracy, Precision, Recall, F1, FPR, ROC-AUC; justify FPR emphasis (operational cost of blocking legit users).
- Baselines (minimum set for Q2):
  1. ModSecurity v3 + OWASP CRS (paranoia level 1) on the same test set
  2. TF-IDF + SVM
  3. TF-IDF + Random Forest
  4. Optional: CNN or LSTM classifier
  5. At least one published transformer result on CSIC 2010 (cite their numbers)
- Load-testing tool for latency (wrk or locust), request mix description.

---

## 6. Results (3–4 pages) — ❌ all new; the paper lives or dies here

Planned tables/figures:
- **Table: main detection results** — all models × {P, R, F1, FPR, AUC} on each dataset's test split.
- **Table: cross-dataset generalization** — train CSIC → test modern set (and reverse). Expect degradation; analyze which attack classes transfer. This is your honest "unseen attacks" section.
- **Table: ablation** — rules-only / model-only / full hybrid. Must show hybrid > either alone (or report honestly and discuss). **Without this, a reviewer can claim the regexes do all the work.**
- **Figure: threshold sensitivity** — sweep τ_high, τ_low; plot F1 and FPR curves; mark chosen operating point.
- **Table/Figure: latency & throughput** — p50/p95/p99 per-request latency and max RPS for: nginx alone, +rules, +full pipeline; CPU (and GPU if available). Compare against ModSecurity overhead.
- **Table: per-attack-class recall** — SQLi / XSS / traversal / command injection / encoding.
- Optional: confusion matrices, ROC curves.

**Writing rule:** every claim in Sections 1–3 must map to a number here.

---

## 7. Discussion & Limitations (1 page) — write honestly; reviewers reward this

- Fail-open design trades security for availability — quantify how often it triggered.
- Only request-line/URI analyzed — POST bodies, headers, and response traffic not inspected (drop all "outgoing traffic" claims).
- Adversarial evasion (encoding tricks, payload mutation) not fully addressed — cite as future work, or add a small evasion experiment if time permits (strengthens the paper significantly).
- Concept drift; the online-learning idea and its label-poisoning risk (mention as future work; do NOT present the current broken script).
- Single-backend deployment; no distributed setting.

---

## 8. Conclusion & Future Work (0.5 page)

Restate contributions with the actual numbers. Future work: distillation/quantization for lower latency, body inspection, adversarial training, safe online adaptation.

---

## Pre-submission checklist

- [ ] All experiments reproducible: seeds fixed, scripts in repo, README for reproduction
- [ ] No "SecureBERT" naming unless real SecureBERT weights used
- [ ] No "zero-day", "production-ready", "unhackable" language anywhere
- [ ] 40+ references, ≥60% from last 5 years
- [ ] Figures vector (PDF/EPS), tables in journal format
- [ ] Plagiarism/similarity check < 15%
- [ ] Cover letter stating novelty: deployable hybrid inline WAF + FP-controlled fusion + latency characterization

## Experiment → Section dependency map (do in this order)

1. Dataset prep + retraining → unblocks Sections 4, 5
2. Main metrics + baselines → Table in 6.1
3. Cross-dataset run → 6.2
4. Ablation (rules/model/hybrid) → 6.3
5. Threshold sweep → 6.4
6. Latency benchmark → 6.5
7. Then write Results → Discussion → Intro claims → Abstract (in that order)

**Conference paper:** after experiments 1–4 exist, extract Sections 1, 3, and Tables 6.1 + 6.3 into a 6–8 page version for a Scopus-indexed IEEE/Springer conference. Submit that first while polishing the journal manuscript (ensure <30% overlap in text, and cite the conference version in the journal paper).
