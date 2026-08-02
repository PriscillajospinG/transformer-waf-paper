# Measuring real end-to-end latency (fills the gap: offline model latency ≠ deployed latency)

Your current latency number (11.7 ms median, 16.3 ms p99) is raw GPU model
inference only. It does not include nginx, the `auth_request` subrequest, Docker
networking, or the backend round trip — the actual path a client experiences.
This closes that gap using the `research/latency_benchmark.py --mode e2e` script
you already have, run on your Mac against the live stack.

## Step 1 — Copy your trained model weights locally

The WAF service loads weights from `waf/model/weights/waf_model.pth`. If you
only have the fine-tuned model inside the Colab notebook, download it:

In Colab, after Section 5 finishes training:
```python
trainer.save_model("bert_csic_final")
tok.save_pretrained("bert_csic_final")
import shutil; shutil.make_archive("bert_csic_final", "zip", "bert_csic_final")
from google.colab import files
files.download("bert_csic_final.zip")
```

Unzip it locally, then either point the WAF at it directly (simplest: copy the
`.bin`/`.safetensors` into `waf/model/weights/` matching the loader in
`waf/app/main.py`), or accept that for this latency test the exact weights
don't matter — inference cost is dominated by architecture and sequence length,
not by which fine-tuned checkpoint is loaded. **You can run this test with the
existing/default weights already in the repo** if you just want the network +
proxy overhead number; the important new information is the *added* latency of
the pipeline around the model, not the model number itself (you already have
that from Colab).

## Step 2 — Start the stack

```bash
cd "/Users/priscillajosping/Desktop/Final Project/transformer-waf-test"
docker-compose up -d --build
sleep 30   # let the model load
docker ps  # confirm waf-nginx, waf-service, backend-app are all up
curl -i http://localhost:8080/     # sanity check: should be 200
```

## Step 3 — Run the WAF-enabled e2e benchmark

```bash
python3 -m pip install requests --break-system-packages   # if needed
python3 research/latency_benchmark.py --mode e2e \
  --url http://localhost:8080/ \
  --n 500 --concurrency 10 \
  --out results/latency_e2e_waf.json
```
This measures the full path: client → nginx → `auth_request` subrequest to the
detection service → rules + model → nginx → backend → response. This is the
number that belongs in Table VI / the latency figure instead of (or alongside)
the offline model number.

## Step 4 — WAF-disabled baseline (isolates the WAF's added overhead)

To know how much of that latency is the WAF specifically (vs. Docker/nginx/backend
baseline), bypass the WAF and hit the backend directly. Two ways, pick whichever
is faster for you:

**A. Temporarily expose the backend port** — add `ports: ["3000:3000"]` under
`backend-app` in `docker-compose.yml`, `docker-compose up -d`, then:
```bash
python3 research/latency_benchmark.py --mode e2e \
  --url http://localhost:3000/ \
  --n 500 --concurrency 10 \
  --out results/latency_e2e_nowaf.json
```
Remove the port mapping afterward if you don't want the backend directly reachable.

**B. Or just report the WAF-enabled number alone** with a note that it includes
proxy + network overhead in addition to model inference — still a legitimate,
honest "deployed latency" figure even without the isolated baseline.

## Step 5 — Send me both JSON files (or just paste the printed summary)

I'll fold the real numbers into:
- Table VI (replacing/augmenting the offline-only latency table)
- The "deployable inline system" claim in the abstract/intro, which currently
  rests only on the offline number
- The Discussion, if WAF overhead turns out to be non-trivial relative to raw
  model inference

## What "good" looks like here

If e2e p50 is roughly `offline_model_latency + a few ms` (nginx/Docker overhead
is typically 1–5 ms for local traffic), that's a strong result worth stating
explicitly. If it's much higher, that's still useful — it's real data the current
paper is missing, and explaining *why* (e.g., auth_request round-trip, Python
GIL, single Uvicorn worker) becomes a legitimate Discussion point rather than a
gap reviewers find themselves.
