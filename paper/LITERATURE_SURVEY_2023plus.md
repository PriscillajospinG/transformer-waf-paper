# Literature Survey — Recent Works (2023+)

Verified recent references now cited in both papers' survey sections. Foundational
models (BERT, Transformer, DistilBERT, TinyBERT), standard datasets (CSIC 2010,
PKDD 2007, SR-BH), and WAF-A-MoLE (2020) are necessarily older and retained as
canonical sources; everything below is 2023 or newer.

> ⚠️ Verify each entry's exact author list, venue and DOI/arXiv ID before
> submission. Entries marked "authors unconfirmed" need checking.

## Surveys / context
- **Kheddar (2025)** — *Transformers and LLMs for efficient intrusion detection: a comprehensive survey.* Information Fusion, vol. 124. arXiv:2408.07583. Reports 85–99% for BERT/GPT models across CSIC 2010, CICIDS2017, UNSW-NB15; flags deployment efficiency + explainability as open. → frames our survey.

## Transformer / deep detection (recent)
- **WADBERT (2026)** — Dual-channel web attack detection with BERT; ~99.7% acc, 99.63% F1 on CSIC 2010. arXiv:2601.21893.
- **Liu et al. (2024)** — Hybrid BERT–LSTM for SQL injection. IET Information Security. ~97.3% acc.
- **Thajeel et al. (2024)** — Novel DL vs XSS & SQLi. Nature Scientific Reports 14:1803. >99% on CSIC 2010 + payload testbeds.
- **Command-injection DL (2024)** — Nature Scientific Reports. doi:10.1038/s41598-024-74350-3.
- **Zhou, Yau, Gan, Liong (2025)** — *E-WebGuard: enhanced neural architectures for precision web attack detection.* Computers & Security, vol. 149. (Closest neural-WAF competitor.)
- **Yang & Peng (2025)** — BERT-based network for IDS. EURASIP J. Information Security. (authors confirmed)
- **SDN-BERT (2024)** — Unseen attack detection in SDN using a BERT-based LLM. arXiv:2412.06239. (authors unconfirmed)
- **Prasetyo et al. (2025)** — Classifying web-server cyber attacks via Transformer + transfer learning (RoBERTa/BERT). IJEEEMI.
- **Zero-day ensemble (2025)** — LSTM+GRU+stacked autoencoders for zero-day web attacks. arXiv:2504.14122. (authors unconfirmed)
- **Webshell DL (2024)** — Deep-learning webshell detection. arXiv:2412.05532. (authors unconfirmed)

## Classical ML (recent)
- **Payload ML (2024)** — SQLi/XSS/command-injection detection with SVM, Random Forest, XGBoost. J. Information Systems and Informatics.

## Compression / latency
- **DistilXIDS (2025)** — Lightweight, explainable distilled transformer for real-time NIDS. Neurocomputing. >99% F1, low latency.
- **Lightweight transformers for edge (2026)** — arXiv:2601.03290.

## Datasets (recent)
- **30-day ModSecurity dataset (2025)** — Malicious HTTP requests blocked by production OWASP ModSecurity. Data (MDPI) 10(11). doi:10.3390/data10110186.
- **SR-BH multi-label (2022)** — Real-traffic web-attack corpus. Computers & Security 120.

## Adversarial evasion (recent)
- **AdvSQLi (2024)** — Adversarial SQL injections vs real-world WAF-as-a-service. arXiv:2401.02615. (authors unconfirmed)
- **RL + pretrained LM evasive payloads (2024/25)** — Generating evasive payloads to assess WAFs. (PeerJ CS 2025 / IEEE TDSC 2024 line of work.)
- **WAF-A-MoLE (2020)** — Demetrio et al. Canonical evasion baseline.

## How the survey is structured in the papers
Journal Section II has four themes — rule-based; classical ML; deep/transformer
detection; and compression/datasets/adversarial — each closing with the gap it
leaves, followed by an explicit *Research gap* subsection and the positioning
table (Table I). Conference Section II is the condensed one-paragraph version.
The recurring, defensible gap: prior transformer detectors are evaluated
**offline**; inline deployment, measured latency, false-positive control,
cross-dataset generalisation and adversarial robustness are addressed rarely and
never together.

## Sources
- https://www.sciencedirect.com/science/article/abs/pii/S1566253525004208 (Kheddar survey)
- https://www.sciencedirect.com/science/article/abs/pii/S0167404824004322 (E-WebGuard)
- https://jis-eurasipjournals.springeropen.com/articles/10.1186/s13635-025-00191-w (BERT IDS)
- https://www.nature.com/articles/s41598-023-48845-4 (XSS/SQLi DL)
- https://www.nature.com/articles/s41598-024-74350-3 (command injection)
- https://arxiv.org/abs/2401.02615 (AdvSQLi)
- https://arxiv.org/pdf/2504.14122 (zero-day ensemble)
- https://arxiv.org/pdf/2412.06239 (SDN-BERT)
- https://doi.org/10.3390/data10110186 (30-day ModSecurity dataset)
- https://peerj.com/articles/cs-2975/ (ML WAF / evasion)
- https://arxiv.org/pdf/2001.01952 (WAF-A-MoLE)
