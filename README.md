# 🛡️ Transformer WAF — A Hybrid Rule + Transformer Web Application Firewall

**A research prototype: transparent inline detection of common web attacks (SQLi, XSS, path traversal, encoding) using a fine-tuned transformer combined with a deterministic rule engine.**

> ⚠️ **Research prototype, not a production security product.** It inspects the
> HTTP request line/URI (and POST body when available) for injection-style
> attacks. It does NOT stop application logic flaws, authentication bypass,
> DDoS, SSRF, or supply-chain attacks, and has not undergone production security
> hardening. The transformer base model is configurable (`WAF_BASE_MODEL`);
> the historical default is `bert-base-uncased`, NOT the SecureBERT model.

[![Status](https://img.shields.io/badge/Status-Research--Prototype-yellow)](https://github.com)
[![Model](https://img.shields.io/badge/Model-Configurable%20Transformer-blue)](https://huggingface.co/models)
[![Docker](https://img.shields.io/badge/Platform-Docker%20Compose-orange)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green)](#-license)

---

## 🚀 Project Overview

**SecureBERT WAF** is an intelligent Web Application Firewall that protects your applications from common and advanced web attacks.

### What Makes It Special?

✅ **AI-Powered** — Uses SecureBERT (fine-tuned BERT Transformer) to detect attacks  
✅ **Plug-and-Play** — Works with ANY web app (Node.js, Python, PHP, Java, etc.)  
✅ **Smart Detection** — Combines AI + rule-based filtering for accuracy  
✅ **Real-Time Dashboard** — See every request and attack in real-time  
✅ **Dockerized** — Deploy in seconds with Docker Compose  
✅ **No Code Changes** — Your app stays untouched



### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  CLIENT REQUESTS (Internet)                             │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────┐
        │   NGINX REVERSE PROXY    │
        │    (Port 8080)           │
        │  Intercepts All Traffic  │
        └──────────────┬───────────┘
                       │
                       ▼
        ┌──────────────────────────────────────┐
        │     WAF ANALYSIS (FastAPI)           │
        ├──────────────────────────────────────┤
        │  ✓ Layer 1: Rule-Based Signatures   │
        │  ✓ Layer 2: Pattern Detection       │
        │  ✓ Layer 3: AI Model (SecureBERT)   │
        │  ✓ Layer 4: Final Decision          │
        └──────────────┬───────────────────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
            ▼                     ▼
        🟢 ALLOW               🔴 BLOCK
            │                     │
            ▼                     ▼
      [Your App]            [403 Forbidden]
            │
            ▼
      ✅ Response Sent
      📊 Logged to Dashboard
```

---

## ⚙️ Features

| Feature | Description |
|---------|-------------|
| **AI Detection** | SecureBERT Transformer models request content semantically |
| **Rule-Based Filtering** | Catches known attack patterns (SQL injection, XSS, path traversal) |
| **Generalization to variants** | Transformer flags obfuscated/unseen variants of known attack classes (evaluate with the cross-dataset scripts in `research/`; avoid the term "zero-day") |
| **Real-Time Dashboard** | Live monitoring with charts and request logs |
| **Plug-and-Play** | Drop in front of ANY web application |
| **Docker Deployment** | One command: `docker-compose up -d --build` |
| **No App Changes** | Your application code stays 100% untouched |
| **Logging & Monitoring** | Every decision logged for audit trail |
| **Low Latency** | ~50-80ms per request |

---

## 🛠️ Requirements

| Requirement | Version | Notes |
|------------|---------|-------|
| **Docker** | Latest | [Install Docker](https://docker.com) |
| **Docker Compose** | Latest (1.29+) | Comes with Docker for Mac/Windows |
| **Disk Space** | ~4 GB | Model weights + images |
| **RAM** | 2+ GB | Running 3 containers |
| **CPU** | 2+ cores | Faster inference |

**Optional (for standalone mode):**
| Requirement | Version |
|------------|---------|
| **Python** | 3.10+ |
| **pip** | Latest |

---

## 🚀 Quick Start (60 Seconds)

### Step 1️⃣ — Clone the Repository

```bash
git clone https://github.com/PriscillajospinG/transformer-waf-test.git
cd transformer-waf-test
```

### Step 2️⃣ — Start the Project

```bash
docker-compose up -d --build
```

**First run takes 2-3 minutes** (downloads model + dependencies).

### Step 3️⃣ — Verify It's Running

```bash
docker ps
```

You should see 3 containers:
```
CONTAINER ID   IMAGE              NAMES
abc123def456   waf_waf-service    waf-service (running)
def789ghi012   nginx:latest       waf-nginx (running)
ghi345jkl678   juice-shop:latest  juice-shop (running)
```

### Step 4️⃣ — Access Your Protected App

| URL | Purpose |
|-----|---------|
| **http://localhost:8080/** | Your protected application |
| **http://localhost:8080/dashboard/** | WAF dashboard (see all requests) |

Done! 🎉 Your application is now protected.

---

## 🔌 Protect Your Own Application (Most Important!)

The main use case for SecureBERT WAF is protecting **YOUR** web application.

### How It Works

1. **No code changes** to your app
2. **Nginx routes** all traffic through the WAF
3. **WAF analyzes** each request
4. **Decision** is made (allow or block)
5. **Backend app** receives safe requests only

### Step-by-Step Setup

#### **Step 1 — Prepare Your Application**

Your application must be accessible **inside the Docker network**. You have 2 options:

**Option A: Your App Has a Dockerfile** (Recommended)
```bash
# Build your Docker image
docker build -t my-app:latest .
```

**Option B: Using a Public Docker Image**
```bash
# Examples:
# - Node.js: node:18, node:20
# - Python: python:3.11, python:3.10
# - PHP: php:8.2, php:8.1
# - Java: openjdk:17, openjdk:21
```

---

#### **Step 2 — Update docker-compose.yml**

Open `docker-compose.yml` and replace the `juice-shop` service with your application:

```yaml
version: '3.8'

services:
  # ============ YOUR APPLICATION ============
  my-app:                                    # Change this name
    image: my-app:latest                     # Your Docker image
    container_name: my-app-container
    restart: always
    ports:
      - "3000:3000"                          # <host>:<container port>
    environment:
      - NODE_ENV=production                  # Your app env vars
      - DATABASE_URL=${DB_URL}
      - API_KEY=${API_KEY}
      - TZ=Asia/Kolkata
    networks:
      - waf-net
    # Optional: Add volumes if your app needs them
    # volumes:
    #   - ./data:/app/data

  # ============ WAF SERVICE (Don't Change) ============
  waf-service:
    build:
      context: ./waf
      dockerfile: Dockerfile
    container_name: waf-service
    restart: always
    environment:
      - MODEL_PATH=/app/model/weights
      - TZ=Asia/Kolkata
    volumes:
      - ./waf:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    networks:
      - waf-net
    depends_on:
      - my-app

  # ============ NGINX (Don't Change) ============
  waf-nginx:
    image: nginx:latest
    container_name: waf-nginx
    restart: always
    environment:
      - TZ=Asia/Kolkata
    ports:
      - "8080:80"                            # WAF external port
    volumes:
      - ./nginx/nginx.conf.template:/etc/nginx/nginx.conf:ro
      - ./nginx/logs:/var/log/nginx
      - ./frontend:/usr/share/nginx/html/dashboard:ro
    depends_on:
      - my-app
      - waf-service
    networks:
      - waf-net

networks:
  waf-net:
    driver: bridge
```

**Key Fields to Change:**
- `my-app` → Your application service name
- `image: my-app:latest` → Your Docker image name
- `ports: - "3000:3000"` → Your app's port
- `container_name: my-app-container` → Unique name for your app

---

#### **Step 3 — Update nginx/nginx.conf.template**

Edit [nginx/nginx.conf.template](nginx/nginx.conf.template) and find the upstream definition (around line 22):

```nginx
# BEFORE:
upstream backend {
    server juice-shop:3000;
}

# AFTER:
upstream backend {
    server my-app:3000;         # Match your service name and port
}
```

**Key Changes:**
- `my-app` → Must match service name from docker-compose.yml
- `3000` → Must match container port

---

#### **Step 4 — Deploy Your Protected Application**

```bash
# Build and start
docker-compose up -d --build

# Wait for containers to start
sleep 30

# Verify all containers are running
docker ps

# Check logs if something fails
docker logs waf-service
docker logs waf-nginx
```

---

#### **Step 5 — Access Your Protected App**

| URL | Purpose |
|-----|---------|
| **http://localhost:8080/** | Your protected application |
| **http://localhost:8080/dashboard/** | WAF dashboard |

**Test a request:**
```bash
# Normal request (should work)
curl http://localhost:8080/

# Attack request (should be blocked)
curl "http://localhost:8080/?search=<script>alert(1)</script>"
```

---

### 📝 Examples for Different Applications

#### **Example 1: Protecting a Node.js App**

**Your docker-compose.yml:**
```yaml
services:
  nodejs-app:
    image: my-node-app:latest
    container_name: nodejs-app
    restart: always
    ports:
      - "4000:4000"
    environment:
      - NODE_ENV=production
      - PORT=4000
      - DATABASE_URL=mongodb://mongo:27017/mydb
      - TZ=Asia/Kolkata
    networks:
      - waf-net
```

**Your nginx.conf.template upstream:**
```nginx
upstream backend {
    server nodejs-app:4000;
}
```

**Deploy:**
```bash
docker-compose up -d --build
```

---

#### **Example 2: Protecting a Python Flask/Django App**

**Your docker-compose.yml:**
```yaml
services:
  python-app:
    build: ./my-python-app
    container_name: python-app
    restart: always
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://user:pass@postgres:5432/mydb
      - SECRET_KEY=your-secret-key
      - TZ=Asia/Kolkata
    networks:
      - waf-net
```

**Your nginx.conf.template upstream:**
```nginx
upstream backend {
    server python-app:5000;
}
```

---

#### **Example 3: Protecting a Java/Spring App**

**Your docker-compose.yml:**
```yaml
services:
  java-app:
    image: openjdk:17
    container_name: java-app
    restart: always
    ports:
      - "8888:8888"
    environment:
      - SERVER_PORT=8888
      - SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/mydb
      - TZ=Asia/Kolkata
    volumes:
      - ./app.jar:/app/app.jar
    command: java -jar /app/app.jar
    networks:
      - waf-net
```

**Your nginx.conf.template upstream:**
```nginx
upstream backend {
    server java-app:8888;
}
```

---

#### **Example 4: Protecting a PHP App**

**Your docker-compose.yml:**
```yaml
services:
  php-app:
    image: php:8.2-fpm
    container_name: php-app
    restart: always
    ports:
      - "9000:9000"
    volumes:
      - ./src:/app
    environment:
      - DB_HOST=mysql
      - DB_NAME=mydb
      - TZ=Asia/Kolkata
    networks:
      - waf-net
```

**Your nginx.conf.template upstream:**
```nginx
upstream backend {
    server php-app:9000;
}
```

---

### 🎯 Quick Configuration Checklist

Before running `docker-compose up -d --build`:

- ✅ Changed `services.my-app.image` to your image name
- ✅ Changed `services.my-app.ports` to your port
- ✅ Updated `upstream backend { server ... }` in nginx.conf.template
- ✅ Updated service name in `depends_on` section
- ✅ Added any required environment variables for your app
- ✅ Your Docker image builds with `docker build -t my-app:latest .`

---

## 🧪 Testing the WAF

Test that the WAF is actually working by sending requests:

### Test 1️⃣ — Normal Request (Should Allow ✅)

```bash
curl -v "http://localhost:8080/"
```

**Expected response:** `HTTP 200 OK`

---

### Test 2️⃣ — SQL Injection Attack (Should Block 🛑)

```bash
curl -v "http://localhost:8080/?search=' OR 1=1 --"
```

**Expected response:** `HTTP 403 Forbidden`

---

### Test 3️⃣ — XSS Attack (Should Block 🛑)

```bash
curl -v "http://localhost:8080/?search=<script>alert(1)</script>"
```

**Expected response:** `HTTP 403 Forbidden`

---

### Test 4️⃣ — Path Traversal Attack (Should Block 🛑)

```bash
curl -v "http://localhost:8080/../../etc/passwd"
```

**Expected response:** `HTTP 403 Forbidden`

---

### Test 5️⃣ — Custom Payload (From Dashboard)

Go to **http://localhost:8080/dashboard/** → Scroll to "Attack Tester" → Enter your payload → See result instantly.

---

## 📊 Dashboard Overview

The SecureBERT WAF Dashboard gives you **real-time visibility** into all requests.

### Dashboard URL

```
http://localhost:8080/dashboard/
```

### Key Sections

| Section | What It Shows |
|---------|--------------|
| **Stat Cards** | Total requests, blocked count, allowed count, block percentage |
| **Doughnut Chart** | Attack types: SQLi, XSS, Path Traversal, Encoding, Other |
| **Timeline Chart** | Blocked vs. Allowed requests over time |
| **Progress Bars** | Breakdown by attack type |
| **Request Log Table** | All recent requests: timestamp, IP, method, URI, status |
| **Attack Tester** | Send test payloads directly from the UI |

### Auto-Refreshing

The dashboard **automatically refreshes every 2 seconds** — you see requests live as they happen.

### Example Dashboard Metrics

```
Total Requests: 1,234
Blocked: 45 (3.6%)
Allowed: 1,189 (96.4%)

Attack Types:
- SQL Injection: 23
- XSS: 15
- Path Traversal: 5
- Encoding Attacks: 2
- Other: 0
```

---

## 🧠 Detection Logic (4 Layers)

SecureBERT uses **4 security layers** working together:

### Layer 1 — Signature Detection (1ms)

Simple pattern matching for known attacks:
- SQL keywords: `UNION`, `SELECT`, `DELETE`, `DROP`
- XSS patterns: `<script>`, `javascript:`, `onerror=`
- Path traversal: `../`, `..\\`, `etc/passwd`
- Encoding attacks: `%2e%2e`, `..%2f`

```plaintext
Example: Request has "UNION SELECT" → Likely SQL injection → Alert
```

---

### Layer 2 — Pattern Analysis (20ms)

Statistical analysis:
- High count of special characters → Suspicious
- Unusual encoding → Possible hiding
- Malformed requests → Protocol violations

```plaintext
Example: Request has 40% special chars → Unusual → Alert
```

---

### Layer 3 — AI Model Analysis (40ms)

SecureBERT Transformer semantically analyzes the request:
- Understands context and intent
- Detects zero-day variants
- Assigns confidence score (0 = safe, 1 = attack)

```plaintext
Example: New never-before-seen attack variant → 
         AI learns semantic patterns → Detects it anyway
```

---

### Layer 4 — Final Decision

Combines all layers:
- If **multiple layers agree** → Block request
- If **only one layer alerts** → Allow with caution
- If **AI confidence > 95%** → Block request

```plaintext
Signature Layer: Alert (SQLi pattern found)
Pattern Layer: Alert (suspicious encoding)
AI Layer: Alert (97% confidence = attack)
Final Decision: BLOCK (3/3 layers agree)
```

---

## 🐳 Docker Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Docker Network (waf-net)                │
├──────────────────────────────────────────────────────────┤
│                                                            │
│  ┌──────────────────┐        ┌──────────────────┐        │
│  │   NGINX Container │        │   WAF Container  │        │
│  ├──────────────────┤        ├──────────────────┤        │
│  │ • Reverse Proxy  │◄──────►│ • FastAPI        │        │
│  │ • Port 8080      │        │ • SecureBERT     │        │
│  │ • Dashboard Host │        │ • Port 8000      │        │
│  └────────┬─────────┘        └──────────────────┘        │
│           │                                               │
│           │                                               │
│           ▼                                               │
│  ┌──────────────────┐                                    │
│  │  APP Container   │                                    │
│  ├──────────────────┤                                    │
│  │ • Your App       │                                    │
│  │ • Node/Python/   │                                    │
│  │   Java/PHP       │                                    │
│  │ • Port Varies    │                                    │
│  └──────────────────┘                                    │
│                                                            │
└──────────────────────────────────────────────────────────┘

         ▲
         │ (Internet)
         │
    Client Requests
```

### Container Details

| Container | Purpose | Port (Internal) | Port (External) |
|-----------|---------|-----------------|-----------------|
| **waf-nginx** | Reverse proxy + dashboard | 80 | 8080 |
| **waf-service** | FastAPI + SecureBERT | 8000 | — |
| **my-app** | Your application | Varies | — |

### How Requests Flow

1. Client sends request to `http://localhost:8080/`
2. Nginx receives it on port 8080
3. Nginx forwards to WAF service (port 8000)
4. WAF analyzes and returns decision
5. If safe → Nginx forwards to your app
6. Response goes back through Nginx to client
7. Request logged to dashboard

---

## 🐛 Troubleshooting

### Issue: "503 Service Unavailable" or "502 Bad Gateway"

**Cause:** Containers still starting or not running.

**Solution:**
```bash
# Check if containers are running
docker ps

# Wait 30 seconds for model to load
sleep 30

# Check logs
docker logs waf-service

# Restart if needed
docker-compose restart waf-service
```

---

### Issue: "403 Forbidden" on ALL Requests (Even Normal Ones)

**Cause:** WAF is too strict or safe endpoints not configured.

**Solution:**

Edit [waf/app/main.py](waf/app/main.py) and find the `SAFE_ENDPOINTS` list:

```python
SAFE_ENDPOINTS = [
    "/rest/",
    "/api/",
    "/socket.io/",
    "/assets/",
    "/favicon.ico"
]
```

Add your app's endpoints:
```python
SAFE_ENDPOINTS = [
    "/rest/",
    "/api/",
    "/socket.io/",
    "/assets/",
    "/favicon.ico",
    "/dashboard/",         # Add your endpoints
    "/login/",
    "/register/",
    "/static/",
]
```

Restart:
```bash
docker-compose restart waf-service
```

---

### Issue: "Connection Refused" or "Cannot Reach Application"

**Cause:** Service name or port mismatch in docker-compose.yml or nginx.conf.template.

**Solution:**

1. Check docker-compose.yml service name:
   ```yaml
   services:
     my-app:              # ← This name
       image: my-app:latest
       ports:
         - "3000:3000"    # ← This port
   ```

2. Check nginx.conf.template upstream:
   ```nginx
   upstream backend {
       server my-app:3000;  # ← Must match service name and port
   }
   ```

3. Verify containers are running:
   ```bash
   docker ps
   docker logs my-app
   ```

---

### Issue: "POST Requests Failing" or "Request Body Missing"

**Cause:** Nginx not forwarding request body.

**Solution:**

Check [nginx/nginx.conf.template](nginx/nginx.conf.template) has:

```nginx
location / {
    auth_request /_waf_check;
    proxy_pass $backend;
    proxy_pass_request_body on;           # ← Must be ON
    proxy_set_header Content-Length $content_length;
```

If missing, add these lines and restart:
```bash
docker-compose restart waf-nginx
```

---

### Issue: "Dashboard Not Loading" or "API Is Unreachable"

**Cause:** Dashboard API endpoint misconfigured.

**Solution:**

Check [frontend/script.js](frontend/script.js) first few lines:

```javascript
const API_BASE = '/waf-api';  # ← Should be /waf-api
```

If different, update it:
```bash
# Edit the file
nano frontend/script.js

# Change API_BASE = '/waf-api'

# Restart Nginx
docker-compose restart waf-nginx
```

---

### Issue: "Port 8080 Already in Use"

**Cause:** Another service running on port 8080.

**Solution:**

Option A — Use a different port:
```yaml
# Edit docker-compose.yml
ports:
  - "8081:80"  # Changed from 8080 to 8081
```

Then access: `http://localhost:8081/`

Option B — Kill the process:
```bash
# Find what's using port 8080
lsof -i :8080

# Kill it
kill -9 <PID>
```

---

### Issue: "Model Not Downloading" or "Timeout"

**Cause:** Large model file (~500MB), slow internet.

**Solution:**
```bash
# Check logs
docker logs waf-service

# Wait longer on first run (5-10 minutes possible)
# Do NOT restart while downloading

# Once running:
docker exec waf-service curl -s http://localhost:8000/health
```

---

## 🔐 Security Notes

### ⚠️ Before Using in Production

| Item | Status | Notes |
|------|--------|-------|
| **API Token** | 🟡 Change | Edit `waf/app/main.py`, change `secure-api-token-change-me` |
| **HTTPS** | 🔴 Not Set | Add SSL certificate to Nginx |
| **Rate Limiting** | 🟡 Optional | Consider adding DDoS protection |
| **WAF Tuning** | 🟡 Required | Adjust thresholds for your app |
| **Monitoring** | 🟡 Basic | Add logging to ELK/Splunk for production |

### Default Configuration

```python
AI_CONFIDENCE_THRESHOLD = 0.95    # Block if AI confidence > 95%
UNCERTAINTY_THRESHOLD   = 0.85    # Flag as uncertain if 85-95%
```

If getting false positives, raise thresholds:
```python
AI_CONFIDENCE_THRESHOLD = 0.98    # More conservative (fewer blocks)
```

If attacks getting through, lower thresholds:
```python
AI_CONFIDENCE_THRESHOLD = 0.90    # More aggressive (more blocks)
```

---

### API Token

Change the default token in [waf/app/main.py](waf/app/main.py):

```python
@app.get("/api/stats")
def get_stats(authorization: str = Header(None)):
    token = "secure-api-token-change-me"  # ← Change this
    if authorization != f"Bearer {token}":
        return {"error": "Unauthorized"}, 401
```

Update dashboard in [frontend/script.js](frontend/script.js):

```javascript
const TOKEN = 'your-new-token';
headers: {
    'Authorization': `Bearer ${TOKEN}`
}
```

---

## 📌 Future Improvements

Planned enhancements for SecureBERT WAF:

| Feature | Timeline | Difficulty |
|---------|----------|-----------|
| **Rate Limiting** | Q2 2024 | Medium |
| **WebSocket Support** | Q2 2024 | Medium |
| **Distributed Deployment** | Q3 2024 | Hard |
| **Adaptive Learning** | Q3 2024 | Hard |
| **HTTPS/TLS Support** | Q1 2024 | Easy |
| **Performance Optimization** | Ongoing | Medium |
| **Multi-Model Ensemble** | Q4 2024 | Hard |
| **GraphQL Protection** | Q4 2024 | Medium |
| **API Rate Limiting** | Done ✅ | — |
| **Custom Rule Engine** | Done ✅ | — |

---

## 📚 Project Structure

```
transformer-waf-test/
├── waf/                          # Core WAF Engine
│   ├── app/
│   │   └── main.py              # FastAPI server + decision engine
│   ├── model/
│   │   ├── transformer.py       # SecureBERT classifier
│   │   ├── tokenizer.py         # Request tokenization
│   │   └── weights/             # Pre-trained model files
│   ├── data/
│   │   ├── normalizer.py        # URI normalization
│   │   └── build_dataset.py     # Training data generation
│   ├── train/
│   │   └── train_pipeline.py    # Model fine-tuning
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile               # Container image
│
├── frontend/                     # Web Dashboard
│   ├── index.html               # Dashboard UI
│   ├── script.js                # Real-time polling
│   └── style.css                # Styling
│
├── nginx/                        # Reverse Proxy
│   ├── nginx.conf.template      # Routing configuration
│   └── logs/                    # Access & error logs
│
├── scripts/                      # Testing Tools
│   ├── test_zero_day_detection.py
│   ├── generate_malicious.py
│   └── generate_benign.py
│
├── docker-compose.yml            # Container orchestration
└── README.md                     # This file!
```

---

## 🤝 Contributing

Found a bug? Have an idea? Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

MIT License — Free for educational and commercial use. See [LICENSE](LICENSE) for details.

---

## ❓ FAQ

### Q: Do I need to change my application code?
**A:** No! SecureBERT WAF is completely transparent. Your app doesn't know it exists.

### Q: What if I have false positives (WAF blocks legitimate traffic)?
**A:** Increase `AI_CONFIDENCE_THRESHOLD` in [waf/app/main.py](waf/app/main.py) from `0.95` to `0.98`, then restart.

### Q: Can I use this with HTTP only (not HTTPS)?
**A:** Yes! SecureBERT WAF works with HTTP. For HTTPS, add an SSL certificate to Nginx (see troubleshooting).

### Q: Does it work with microservices?
**A:** Not yet. It protects one backend service. Multi-service routing coming soon.

### Q: How much does it cost?
**A:** Free! MIT License. You can use it commercially without paying.

### Q: Is it production-ready?
**A:** No. This is a research prototype for evaluating hybrid transformer-based
detection. It lacks TLS termination, rate limiting, request-body inspection at
scale, and production security hardening. Do not rely on it as your only defense.

### Q: What attacks does it detect?
**A:** SQL injection, XSS, path traversal, command injection, encoding attacks, and unknown variants via AI.

### Q: Can I train the model with my own data?
**A:** Yes! See [waf/train/train_pipeline.py](waf/train/train_pipeline.py) for the training pipeline.

---

## 📞 Support

- 📖 Check [Troubleshooting](#-troubleshooting) section above
- 🐛 Open an issue on GitHub
- 💬 Discussions for questions and ideas

---

## 🙏 Acknowledgments

- **BERT Model**: Hugging Face Transformers library
- **FastAPI**: Modern Python web framework
- **Nginx**: Industry-standard reverse proxy
- **OWASP**: Security testing principles

---

---

**Status:** Research prototype  
**License:** MIT 📜

---

> 🛡️ **A research prototype for hybrid transformer-based web attack detection.** See `research/` for the reproducible evaluation pipeline and `JOURNAL_PAPER_SKELETON.md` / `RESEARCH_GAP_ANALYSIS.md` for the paper plan.
