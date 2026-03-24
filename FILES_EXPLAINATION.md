# SecureBERT WAF: Complete Deep Codebase Explanation

This document explains every file currently present in this repository (excluding Git internals and Python bytecode caches).

Goal of this guide:
- Understand what each file does
- Understand why it exists and what problem it solves
- Understand what breaks if it is removed
- Understand key classes/functions and important logic

---

## 1. System Map (High-Level)

Architecture in this project:
1. Nginx container receives all external traffic on port 8080.
2. Nginx calls FastAPI WAF endpoint (/analyze) via auth_request before forwarding app traffic.
3. FastAPI WAF runs hybrid detection:
   - direct signatures
   - heuristic/rule checks
   - SecureBERT probability inference
4. WAF returns allow/block decision.
5. Nginx forwards to backend app if allowed, otherwise returns 403.
6. Dashboard frontend calls FastAPI API endpoints for logs/stats/testing.

---

## 2. Top-Level Files

## File: .env

What it does:
- Stores runtime environment variables used by Docker services.

Why it exists:
- Lets you configure token, CORS, timezone, logging without editing source code.

Problem it solves:
- Avoids hardcoding deployment-specific values.

If removed:
- Compose still runs with defaults from code/compose, but you lose easy customization.

Key values:
- API_TOKEN
- ALLOWED_ORIGINS
- LOG_LEVEL
- TZ

Important logic:
- This file is loaded by Docker Compose when running services.

---

## File: .env.example

What it does:
- Template showing required env keys and safe defaults.

Why it exists:
- Onboarding and documentation for collaborators.

Problem it solves:
- Prevents missing env confusion.

If removed:
- New users may guess wrong variable names and fail to configure securely.

Key fields:
- API_TOKEN, ALLOWED_ORIGINS, LOG_LEVEL, TZ

---

## File: .gitignore

What it does:
- Prevents logs, virtualenvs, weights, and generated files from being committed.

Why it exists:
- Keeps repo clean and avoids leaking large/sensitive artifacts.

Problem it solves:
- Prevents noisy diffs and oversized repositories.

If removed:
- You may accidentally commit logs, model files, and local environment data.

Important entries:
- nginx/logs/
- waf/model/weights/
- .env
- __pycache__/

---

## File: README.md

What it does:
- Main project documentation: architecture, setup, usage, plug-and-play guidance.

Why it exists:
- Entry point for users and evaluators.

Problem it solves:
- Reduces setup friction and explains intended workflow.

If removed:
- New users lose the quick start and operational instructions.

Important content:
- Docker and standalone run instructions
- Dashboard usage
- Plug-and-play replacement examples
- Detection layer explanation

Notes:
- Some sections include legacy assumptions (for example, older endpoint references); verify with current source when debugging.

---

## File: SECUREBERT_WAF_PROJECT_GUIDE.md

What it does:
- Student-friendly guide, viva script, debugging notes, and explanation narrative.

Why it exists:
- Presentation/teaching aid for demos and evaluation.

Problem it solves:
- Helps communicate architecture clearly to non-developer audiences.

If removed:
- Project still runs, but pedagogy and demo preparedness are reduced.

Important content:
- Step-by-step run and flow explanations
- Viva-ready summaries
- Practical debugging commands

---

## File: docker-compose.yml

What it does:
- Defines 3 containers and networking:
  - backend-app
  - waf-service
  - waf-nginx

Why it exists:
- Orchestrates full runtime stack with one command.

Problem it solves:
- Ensures reproducible local deployment of proxy + WAF + app.

If removed:
- You must manually run each component and network them yourself.

Key blocks and logic:
- backend-app:
  - Default APP_IMAGE points to bkimminich/juice-shop.
  - Container name can be overridden by APP_HOST.
- waf-service:
  - Built from waf/Dockerfile.
  - Read-only bind mount of ./waf to /app.
  - Drops Linux capabilities and runs non-root.
  - Healthcheck gates proxy startup.
- waf-nginx:
  - Renders nginx config from template using envsubst.
  - Exposes host port 8080.
  - Depends on healthy waf-service.

Important environment variables:
- APP_HOST, APP_PORT: target protected application
- API_TOKEN, ALLOWED_ORIGINS, LOG_LEVEL
- BLOCK_MESSAGE

---

## File: test_realtime.py

What it does:
- Sends a fixed sequence of benign and malicious requests and prints pass/fail in real-time.

Why it exists:
- Quick smoke test script for behavior verification.

Problem it solves:
- Fast confidence check after config/model changes.

If removed:
- Core runtime unaffected; testing becomes manual.

Key functions:
- get_waf_logs(): tails waf-service logs via docker-compose logs.
- test_request(): sends request, compares expected status.
- main(): executes test matrix and prints summary.

Important logic:
- Uses HEAD requests to reduce payload overhead.
- Expected values encode security assertions (200 for benign, 403 for attack patterns).

---

## File: waf_dashboard.py

What it does:
- CLI-oriented dashboard script that runs staged requests and prints multi-layer detection diagnostics.

Why it exists:
- Demonstration tool showing request-by-request decision reasoning.

Problem it solves:
- Makes internal detection process visible during demos.

If removed:
- No runtime break, but less observability for terminal-based demos.

Key functions:
- get_waf_logs(last_n)
- analyze_request(desc, method, path, expected_status)
- main()

Important logic:
- Parses recent logs to infer which detection layer fired.
- Reports timing and pass/fail for each attack scenario.

---

## 3. Frontend Dashboard Files

## File: frontend/index.html

What it does:
- Declares dashboard UI structure: KPI cards, charts, attack tester, and log table.

Why it exists:
- Human-friendly monitoring and interaction with WAF APIs.

Problem it solves:
- Provides live operational visibility without command-line tools.

If removed:
- WAF still works; dashboard route loses UI content.

Key sections:
- Navbar with status and clock
- Stat cards (total/blocked/allowed/rate)
- Attack type doughnut and timeline charts
- Attack tester input and quick buttons
- Live request log table

Important logic connection:
- Includes script.js and style.css
- Calls /api endpoints (proxied by nginx to waf-service)

---

## File: frontend/script.js

What it does:
- Implements dashboard behavior:
  - polling stats/logs
  - chart updates
  - attack test execution
  - UI updates

Why it exists:
- Turns static HTML into live monitoring app.

Problem it solves:
- Real-time visibility and interaction with WAF.

If removed:
- Dashboard becomes static and non-functional.

Key functions:
- updateClock()
- fetchStats()
- fetchLogs()
- testUrl()
- updateBar(), animateValue(), escapeHtml()

Important logic:
- API token resolution order:
  1. URL query token
  2. localStorage api_token
  3. default token
- Polling interval REFRESH_MS = 2000ms
- Stats endpoint updates:
  - counters
  - doughnut dataset
  - timeline differential increments
- Logs endpoint supports {logs, debug} response format.

---

## File: frontend/style.css

What it does:
- Dashboard styling: dark background, gradient cards, charts/table cosmetics, animations.

Why it exists:
- Improves readability and user experience.

Problem it solves:
- Default bootstrap theme is insufficient for security-monitoring UX.

If removed:
- UI remains functional but visually degraded.

Important styles:
- Gradient card classes
- Table truncation and fixed-width behavior
- Pulse animation for live badge
- Focus styles for tester input

---

## 4. Nginx Layer Files

## File: nginx/nginx.conf.template

What it does:
- Reverse proxy configuration template rendered at container startup.

Why it exists:
- Supports environment-based upstream substitution without rebuilding image.

Problem it solves:
- Makes backend target dynamic (APP_HOST/APP_PORT).

If removed:
- Nginx container cannot render runtime config; proxy enforcement fails.

Key blocks:
- limit_req_zone definitions for general and API traffic
- location /dashboard/: serves static frontend files
- location /api/: proxies dashboard API to waf-service
- location /: enforces auth_request /_waf_check before proxying app traffic
- location = /_waf_check: internal call to waf-service /analyze
- location = /blocked.html: block message response

Important logic:
- auth_request contract:
  - 2xx from /_waf_check means allow
  - 401/403 means deny
- Passes original metadata via headers:
  - X-Original-URI
  - X-Original-Query
  - X-Original-Request-URI
  - X-Original-Method
  - X-Original-IP

Resilience logic:
- In /_waf_check, 500/502/503/504 are mapped to /_waf_allow (204), creating fail-open behavior at proxy layer for upstream WAF outages.

---

## File: nginx/logs/access.log

What it does:
- Runtime access logs for proxied traffic.

Why it exists:
- Auditing, analytics, and training-data extraction.

Problem it solves:
- Tracks request path, status, and client info over time.

If removed:
- No historic traffic audit and training scripts lose input source.

Important observations from current file:
- Contains large number of blocked socket.io polling requests (403).
- Shows periods where benign assets/API were blocked historically.
- Useful for diagnosing false positives and behavior drift.

---

## File: nginx/logs/error.log

What it does:
- Nginx operational error logs.

Why it exists:
- Critical debugging source for upstream/connectivity failures.

Problem it solves:
- Explains 502 and auth_request failure root causes.

If removed:
- Troubleshooting upstream outages becomes much harder.

Important observations:
- Repeated connect() failed (111: Connection refused) toward waf-service upstream.
- auth_request unexpected status 502 confirms availability issue periods.

---

## 5. Script Utilities

## File: scripts/generate_benign.py

What it does:
- Generates random benign traffic against localhost:8080.

Why it exists:
- Provides realistic normal load for testing and log generation.

Problem it solves:
- Enables validation of false-positive rate under normal browsing/API behavior.

If removed:
- Harder to produce benign traffic quickly and consistently.

Key function:
- generate_benign()

Important logic:
- Random path selection from benign list
- Realistic browser User-Agent header
- Random sleep to mimic user pacing

---

## File: scripts/generate_malicious.py

What it does:
- Sends randomized attack payload requests (SQLi/XSS/path traversal/command injection).

Why it exists:
- Stress-tests detection and block behavior.

Problem it solves:
- Provides quick hostile traffic generation for verification.

If removed:
- Manual attack testing becomes slower and less consistent.

Key function:
- generate_malicious()

Important logic:
- Attack path list contains known signatures and variants
- Prints returned status for each payload

---

## File: scripts/verify_waf.py

What it does:
- Runs baseline allow/block verification suite with expected status codes.

Why it exists:
- Regression-style sanity check.

Problem it solves:
- Detects if recent changes broke expected security behavior.

If removed:
- You lose a lightweight acceptance check.

Key function:
- test_waf()

Important logic:
- Wait loop for service readiness
- Fixed expected outcomes:
  - benign => 200
  - attack => 403

---

## File: scripts/test_zero_day_detection.py

What it does:
- Broader test suite including zero-day-like variants, encoding, and anomaly tests.

Why it exists:
- Measures robustness beyond exact training signatures.

Problem it solves:
- Validates generalization claims for adversarial variants.

If removed:
- Harder to prove zero-day resilience.

Key function:
- test_waf_zero_day()

Important logic:
- Categorized tests:
  - benign
  - known attacks
  - unseen variants
  - encoding attacks
  - anomaly attacks
- Exit code reflects pass/fail for automation compatibility.

---

## File: scripts/fix_false_positive.py

What it does:
- Attempts targeted fine-tune to reduce specific false positives (example: apple search).

Why it exists:
- Rapid corrective loop for observed bad classifications.

Problem it solves:
- Quick adaptation after deployment without full retraining.

If removed:
- You still can retrain, but lose one-click tactical mitigation script.

Key function:
- fix_false_positive()

Important logic and caveats:
- Loads tokenizer and model weights
- Builds tiny corrective dataset with benign + malicious examples
- Fine-tunes and saves updated weights
- Restarts waf-service

Important code mismatch risk:
- Script instantiates WAFTransformer with arguments vocab_size, d_model, num_layers, but current WAFTransformer constructor accepts only num_classes.
- Script expects tokenizer.encode output with .ids, but current tokenizer returns PyTorch tensors dict.
- This script likely needs refactor to align with current model/tokenizer APIs.

---

## 6. WAF Service Container and Dependencies

## File: waf/Dockerfile

What it does:
- Builds the WAF inference/runtime image.

Why it exists:
- Standardized deployment of FastAPI + model dependencies.

Problem it solves:
- Eliminates machine-specific setup drift.

If removed:
- Compose cannot build waf-service image.

Important logic:
- Base image: python:3.10-slim
- Creates non-root user/group (uid/gid 1000)
- Installs dependencies from requirements.txt
- Copies app code into /app
- Sets torch cache paths and HOME
- Runs uvicorn app.main:app on port 8000

Security posture details:
- Non-root runtime user
- Works with compose-level cap_drop and no-new-privileges

---

## File: waf/requirements.txt

What it does:
- Declares Python dependencies used across service/training scripts.

Why it exists:
- Reproducible package installation.

Problem it solves:
- Avoids missing package errors and manual installs.

If removed:
- Docker build and local Python setup fail.

Key packages:
- fastapi, uvicorn
- torch, transformers, tokenizers
- pydantic, requests
- numpy, pandas, scikit-learn

---

## 7. Core WAF Application

## File: waf/app/main.py

What it does:
- Main FastAPI application implementing WAF decision engine and dashboard APIs.

Why it exists:
- This is the core enforcement logic behind /analyze and telemetry endpoints.

Problem it solves:
- Combines deterministic and ML detection for request filtering.

If removed:
- Nginx auth_request checks fail; no allow/block decision engine.

Key components:
- Logging setup:
  - log_event() emits structured JSON logs.
- FastAPI app + CORS middleware.
- Global runtime state:
  - model/tokenizer handles
  - stats counters
  - all_request_log ring buffer
- Detection constants and keyword lists.
- Safe endpoint policy:
  - SAFE_INTERNAL_PREFIXES
  - is_safe_internal_request()
  - is_strong_attack()
- Detection helpers:
  - detect_suspicious_keywords
  - detect_special_char_anomaly
  - detect_encoding_attacks
  - detect_injection_patterns
- Model inference:
  - infer_malicious_probability()
- Decision engine:
  - evaluate_request()
- Endpoints:
  - / (health)
  - /api/stats
  - /api/logs
  - /api/test
  - /analyze

Important decision logic walkthrough:
1. direct signatures block immediately (e.g., or 1=1, union select, <script, ../)
2. rule combinations can block (keyword + injection, encoding attacks)
3. AI probability is computed
4. high confidence + suspicious signal blocks
5. uncertainty + anomalies may block
6. otherwise allow

Balanced internal endpoint behavior:
- For paths matching SAFE_INTERNAL_PREFIXES, blocked results may be overridden to allowed unless is_strong_attack() returns true.
- This reduces false positives on system endpoints while still blocking obvious attacks.

Security APIs:
- /api/stats, /api/logs, /api/test require Bearer token via verify_api_token().

Failure strategy:
- /analyze catches unexpected exceptions and returns allow (fail-open) for availability.

---

## 8. Model and Tokenization Layer

## File: waf/model/transformer.py

What it does:
- Defines PyTorch classifier WAFTransformer using huggingface bert-base-uncased backbone.

Why it exists:
- Converts request text embeddings into binary malicious/benign logits.

Problem it solves:
- Detects semantic attack patterns beyond static signatures.

If removed:
- WAF still can run rule-based checks, but ML layer disappears and inference code fails.

Key class:
- WAFTransformer(nn.Module)

Important logic:
- Loads AutoModel.from_pretrained("bert-base-uncased")
- Uses CLS token embedding (last_hidden_state[:, 0, :])
- Applies dropout then linear classifier to produce logits

---

## File: waf/model/tokenizer.py

What it does:
- Wraps huggingface AutoTokenizer for request encoding.

Why it exists:
- Standardized preprocessing for model input.

Problem it solves:
- Ensures consistent tokenization and tensor output format.

If removed:
- Model inference cannot prepare input_ids/attention_mask.

Key class:
- HttpTokenizer

Key methods:
- _normalize_text(text): sanitizes null bytes and converts non-string input
- encode(text): returns padded/truncated tensors
- save(path), load(path): tokenizer persistence

Important logic:
- Max length guard (64 to 512)
- Safe fallback encoding on exception
- Logs truncation hints for observability

---

## 9. Model Weights and Tokenizer Artifacts

## File: waf/model/weights/waf_model.pth

What it does:
- Serialized model state_dict for WAFTransformer.

Why it exists:
- Allows model reuse at runtime without retraining.

Problem it solves:
- Startup loads trained parameters for inference.

If removed:
- App starts with randomly initialized model (or model unavailable flow), reducing detection reliability.

Artifact type:
- PyTorch archive file (detected as zip-format payload).

---

## File: waf/model/weights/tokenizer.json

What it does:
- Full tokenizer graph/config for fast tokenizer backend.

Why it exists:
- Reproducible tokenization behavior across environments.

Problem it solves:
- Prevents tokenizer drift between training/inference machines.

If removed:
- Tokenizer fallback may still load from model name remotely, but local deterministic behavior is reduced.

Important content:
- Special tokens [CLS], [SEP], [PAD], [MASK], [UNK]
- BertNormalizer, pre-tokenizer, post-processor templates

---

## File: waf/model/weights/tokenizer_config.json

What it does:
- Huggingface tokenizer metadata and special token mapping behavior.

Why it exists:
- Complements tokenizer loading and behavior options.

Problem it solves:
- Standardizes tokenizer class and options.

If removed:
- Some loads may still work, but metadata-driven behavior may degrade.

---

## File: waf/model/weights/special_tokens_map.json

What it does:
- Minimal map of reserved special tokens.

Why it exists:
- Ensures tokenizer knows IDs and symbolic names for key control tokens.

Problem it solves:
- Required by many tokenizer loading paths.

If removed:
- Tokenizer loading may fail or use defaults inconsistently.

---

## File: waf/model/weights/vocab.txt

What it does:
- WordPiece vocabulary list used by BERT tokenizer.

Why it exists:
- Core dictionary for token-id mapping.

Problem it solves:
- Enables deterministic tokenization.

If removed:
- Tokenization fails for local model assets.

---

## 10. Data Processing and Training Pipeline

## File: waf/data/normalizer.py

What it does:
- Normalizes parsed request logs into canonical textual format.

Why it exists:
- Reduces overfitting to IDs/noisy values and improves learning consistency.

Problem it solves:
- Raw logs contain unstable identifiers that hurt generalization.

If removed:
- Training data becomes noisier and less robust.

Key class:
- RequestNormalizer

Key method:
- normalize(log_entry)

Important logic:
- Replaces UUIDs with {UUID}
- Replaces pure-digit path segments with {ID}
- Optionally sanitizes body emails
- Output format: METHOD URI [BODY]

---

## File: waf/data/build_dataset.py

What it does:
- Parses nginx logs, normalizes entries, writes dataset file, and attempts tokenizer prep.

Why it exists:
- Data ingestion bridge from runtime logs to ML dataset.

Problem it solves:
- Converts operational traffic into trainable text samples.

If removed:
- No automated log-to-dataset pipeline.

Key function:
- build_dataset()

Important logic:
- Uses NginxLogParser.parse_file()
- Skips /_waf_check internal entries
- Normalizes each entry and writes line-by-line dataset

Caveat:
- Calls HttpTokenizer(vocab_size=1000) but current HttpTokenizer signature does not support vocab_size.
- This indicates code drift between training utilities and current tokenizer implementation.

---

## File: waf/train/train_pipeline.py

What it does:
- Generates synthetic benign/malicious data and trains SecureBERT classifier.

Why it exists:
- Produces initial model weights for inference.

Problem it solves:
- Bootstraps model training without requiring large curated dataset.

If removed:
- You lose in-repo training path and must rely on prebuilt weights.

Key elements:
- Synthetic template pools:
  - BENIGN_TEMPLATES
  - MALICIOUS_TEMPLATES with adversarial/zero-day-like variants
- generate_synthetic_data(num_samples)
- WAFDataset(Dataset)
- train_pipeline()

Important logic:
- Creates 5000 samples (half benign/half malicious)
- Uses HttpTokenizer.encode for tensors
- Fine-tunes WAFTransformer with AdamW lr=1e-5 for 3 epochs
- Saves tokenizer and model weights to waf/model/weights

---

## File: waf/train/online_learning.py

What it does:
- Reads logs and performs incremental fine-tuning (assumes allowed traffic is benign).

Why it exists:
- Supports adaptive drift correction over time.

Problem it solves:
- Helps model adapt to changing normal traffic patterns.

If removed:
- You lose automated incremental learning path.

Key function:
- online_learning(log_file, epochs)

Important logic:
- Loads current model and tokenizer
- Parses logs, filters status < 400 as benign
- Normalizes and fine-tunes with low learning rate
- Saves updated weights

Caveat:
- Similar constructor mismatch to other scripts:
  - Instantiates WAFTransformer with unsupported arguments (vocab_size, d_model, num_layers).
- Needs update to match current transformer.py API.

---

## File: waf/utils/log_parser.py

What it does:
- Parses nginx log lines into structured fields.

Why it exists:
- Provides reusable extraction for dataset/training scripts.

Problem it solves:
- Turns unstructured log strings into machine-usable dict records.

If removed:
- Dataset and online-learning scripts cannot parse access logs.

Key class:
- NginxLogParser

Key methods:
- parse_line(line)
- parse_file(file_path)

Important logic:
- Regex extracts ip/user/time/request/status/bytes/referer/ua/body
- Splits request line to method and URI
- URI unquote decoding

Note:
- Parser regex targets a specific nginx format; if log format changes, parser must be updated.

---

## 11. Repository-Wide Functional Consequences by File Category

If infra config files are removed:
- docker-compose.yml, waf/Dockerfile, nginx/nginx.conf.template
- System cannot be deployed end-to-end.

If detection core files are removed:
- waf/app/main.py, waf/model/transformer.py, waf/model/tokenizer.py
- WAF decisions and model inference collapse.

If model assets are removed:
- waf/model/weights/*
- Service may start but loses trained inference behavior.

If training/data files are removed:
- waf/train/*, waf/data/*, waf/utils/log_parser.py
- Retraining and adaptation workflows break.

If frontend is removed:
- frontend/*
- WAF still functions, but live dashboard/interactive testing disappears.

If scripts are removed:
- scripts/*, test_realtime.py, waf_dashboard.py
- No quick verification/generation/demo automation.

If environment/docs are removed:
- .env.example, README.md, SECUREBERT_WAF_PROJECT_GUIDE.md
- Operational onboarding and reproducibility degrade.

If logs are removed:
- nginx/logs/*
- Runtime system still works, but historical diagnostics/training source is lost.

---

## 12. End-to-End Runtime Sequence with File Participation

1. User request arrives at waf-nginx
   - Controlled by docker-compose.yml and nginx/nginx.conf.template
2. Nginx performs auth_request /_waf_check
   - Sends original request metadata headers to waf-service /analyze
3. FastAPI in waf/app/main.py receives /analyze
   - Reconstructs URI and method
   - Evaluates direct signatures and heuristic signals
   - Calls tokenizer/model if needed
4. tokenizer.py encodes normalized request text
5. transformer.py runs inference, returns logits -> malicious probability
6. main.py decides allow/block using thresholds + safe-internal policy
7. FastAPI returns 200 or 403 to nginx auth_request
8. Nginx forwards to backend app (allowed) or returns block response (denied)
9. Logs and stats are stored in main.py structures and nginx log files
10. frontend/script.js polls /api/stats and /api/logs to render dashboard

---

## 13. Current Codebase Quality Notes (Important for Deep Understanding)

1. Core runtime path (nginx + FastAPI + model inference + dashboard) is coherent and production-oriented in structure.
2. Several auxiliary training/fix scripts show API drift versus current model/tokenizer classes.
3. Model and tokenizer assets are present, allowing container startup without retraining.
4. Error logs show historical availability issues where waf-service was unreachable from nginx.
5. Balanced safe-internal endpoint logic in main.py addresses high false-positive risk on system endpoints.

---

## 14. Practical Study Checklist

Use this sequence to deeply learn the project hands-on:
1. Read docker-compose.yml and nginx/nginx.conf.template together.
2. Trace /analyze in waf/app/main.py from request headers to decision output.
3. Read tokenizer.py then transformer.py, then follow infer_malicious_probability in main.py.
4. Use scripts/verify_waf.py and scripts/test_zero_day_detection.py for behavior validation.
5. Open dashboard and correlate visible logs with nginx/logs/access.log and waf-service container logs.
6. Review training scripts and note where APIs need synchronization before retraining.

---

This file intentionally documents every current project file in the repository inventory to provide a complete architectural and code-level understanding.