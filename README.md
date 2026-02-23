<div align="center">

```
██╗   ██╗███████╗██████╗ ████████╗██╗ ██████╗  ██████╗
██║   ██║██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝ ██╔═══██╗
██║   ██║█████╗  ██████╔╝   ██║   ██║██║  ███╗██║   ██║
╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██║██║   ██║██║   ██║
 ╚████╔╝ ███████╗██║  ██║   ██║   ██║╚██████╔╝╚██████╔╝
  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝
```

**Web Application Security Auditing Suite**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)](https://www.python.org)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red?style=flat-square)](https://vertigo.xahico.com)
[![Cloud ML](https://img.shields.io/badge/ML-cloud--backed-8A2BE2?style=flat-square&logo=google-cloud)](https://vertigo.xahico.com)
[![Status: Active](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)]()

[**Documentation**](https://vertigo.xahico.com/docs) · [**Get a Key**](https://vertigo.xahico.com) · [**Support**](https://xahico.com/support)

</div>

---

## Overview

Vertigo is an AI-powered web application security auditing tool built for security engineers and audit teams. It combines a real Chromium browser engine with cloud-hosted machine learning to discover, classify, and score the full asset surface of modern web applications — including single-page applications, authenticated portals, and API-heavy backends.

> Vertigo is a licensed product. Cloud ML features require a valid API key from [vertigo.xahico.com](https://vertigo.xahico.com). Core crawling and fingerprinting work without a key.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        vertigo CLI                             │
│         auth  │  fingerprint  │  scan                          │
└──────────┬──────────────┬──────────────┬────────────────────────┘
           │              │              │
           ▼              ▼              ▼
┌──────────────────────────────────────────────────────────────┐
│                   Playwright Browser Engine                  │
│   ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│   │   Auth     │  │   Shallow    │  │     Deep Crawler     │ │
│   │   Engine   │  │   Crawler    │  │                      │ │
│   │            │  │  (Katana)    │  │  BFS + JS analysis   │ │
│   └─────┬──────┘  └──────┬───────┘  └──────────┬───────────┘ │
└─────────┼───────────────┼──────────────────────┼─────────────┘
          │               │                      │
          └───────────────┴──────────────────────┘
                          │
                          ▼  HTTPS  (feature vectors only — no raw HTML)
┌─────────────────────────────────────────────────────────────────┐
│               XAHICO Cloud ML Service (GCP)                     │
│                                                                 │
│   ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐  │
│   │  Form           │  │  Page           │  │  Anomaly      │  │
│   │  Classifier     │  │  Classifier     │  │  Detector     │  │
│   │  (RandomForest) │  │  (LightGBM)     │  │  (IsoForest)  │  │
│   └─────────────────┘  └─────────────────┘  └───────────────┘  │
│                                                                 │
│                        ┌─────────────────────────────────────┐  │
│                        │  Sample Ingestion + QA              │  │
│                        │  (continuous model improvement)     │  │
│                        └─────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Key design decision:** No ML models, training data, or weights are ever stored or executed on the client machine. All inference runs exclusively in the XAHICO cloud. The client package contains only the browser automation engine and HTTP plumbing.

---

## Features

### Authentication (`vertigo auth`)

Vertigo uses a real Chromium browser to log into web applications — not HTTP replay, not hardcoded form selectors.

- **ML-guided form detection** — the cloud classifier identifies login forms from DOM structure and text features, achieving reliable detection even on custom-styled or JavaScript-rendered auth pages
- **Multi-strategy submission** — tries all discovered submit triggers with proper event dispatch to handle JS-validated forms
- **Session capture** — extracts cookies, localStorage, sessionStorage, and request headers into a portable session object for use by subsequent commands
- **Success scoring** — a weighted multi-signal detector evaluates URL changes, cookie mutations, keyword presence, and form disappearance to determine whether authentication succeeded
- **MFA / CAPTCHA detection** — surfaces MFA prompts and CAPTCHA challenges rather than silently failing

### Fingerprinting (`vertigo fingerprint`)

Generates a stable, content-addressed fingerprint of a web application's asset surface.

- Powered by [Katana](https://github.com/projectdiscovery/katana) for fast shallow crawling
- Produces a deterministic **asset fingerprint** (SHA-256 of sorted endpoint hashes) suitable for change detection in CI pipelines
- Tracks endpoints, static resources, security headers, and cookies
- Supports authenticated crawling via session hand-off from `vertigo auth`

### Deep Scanning (`vertigo scan`)

Performs a deep, authenticated BFS crawl with ML-assisted analysis of every page visited.

**Endpoint discovery methods:**

| Method | What it finds |
|---|---|
| Browser navigation | Visited pages and redirect chains |
| Static code analysis | API paths in JS source (`fetch`, `axios`, XHR, jQuery) |
| Runtime interception | Live network requests via fetch/XHR instrumentation |
| Passive API observation | Normalised API call shapes with auth token detection |
| Endpoint registry probe | `/api/v1/schema`, `/.well-known/api-endpoints`, `/api/v1/exports` |
| Interaction simulation | Clicks, scrolls, and toggle interactions to trigger lazy API calls |

**Cloud ML classification:**

- **Page classifier** (LightGBM) — labels each visited page as `login`, `dashboard`, `admin`, `profile`, `api`, `form`, `list`, `detail`, `error`, or `static` from combined text and structural features
- **Anomaly detector** (Isolation Forest) — scores each HTTP response for statistical anomalies across 20 features including status codes, timing, headers, and DOM structure; flags responses with a score above 0.7

**Subdomain intelligence:**

- Detects subdomains during link extraction by comparing against the root domain (e.g. `api.example.com` discovered while crawling `app.example.com`)
- Deduplicates subdomain discoveries across the full crawl
- Optional controlled subdomain scanning via `-sub-depth` (default: detect only, do not scan)

---

## Installation

```bash
pip install xahico-vertigo
```

**Runtime dependencies:**

```bash
# Playwright browser (required for auth and scan)
playwright install chromium

# Katana (required for fingerprint)
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

**API key:**

```bash
export XAHICO_VERTIGO_API_KEY="XAHICO-your-key-here"
```

Get a key at [vertigo.xahico.com](https://vertigo.xahico.com). Fingerprinting works without a key; authentication and scanning require one.

---

## Usage

### Authenticate

```bash
# Basic authentication
vertigo auth https://app.example.com \
  -username admin \
  -password secret \
  -output session.json

# With a custom entry point
vertigo auth https://app.example.com \
  -entry /login \
  -username admin \
  -password secret

# Show the browser window (useful for debugging auth flows)
vertigo auth https://app.example.com \
  -no-headless \
  -username admin \
  -password secret
```

### Fingerprint

```bash
# Unauthenticated (no key required)
vertigo fingerprint https://app.example.com \
  -depth 3 \
  -limit 50

# Authenticated fingerprint
vertigo fingerprint https://app.example.com \
  -login /login \
  -username admin \
  -password secret \
  -output fingerprint.json
```

### Scan

```bash
# Unauthenticated scan
vertigo scan https://app.example.com \
  -depth 5 \
  -limit 100

# Authenticated scan
vertigo scan https://app.example.com \
  -login /login \
  -username admin \
  -password secret \
  -output scan.json

# With subdomain scanning (2 levels deep into each discovered subdomain)
vertigo scan https://app.example.com \
  -sub-depth 2 \
  -output scan.json

# Deep authenticated scan with debug output
vertigo scan https://app.example.com \
  --debug \
  -login /login \
  -username admin \
  -password secret \
  -depth 10 \
  -limit 500
```

### Common flags

| Flag | Commands | Description |
|---|---|---|
| `--debug` | all | Structured debug logging to stderr. Without this flag, no output is produced. |
| `-output <path>` | all | Write JSON result to file instead of stdout |
| `-silent` | all | Suppress JSON stdout output (useful when only saving to file) |
| `-depth <n>` | fingerprint, scan | Maximum crawl depth (default: 3) |
| `-limit <n>` | fingerprint, scan | Maximum URLs to visit (default: 10) |
| `-timeout <s>` | fingerprint, scan | Crawl timeout in seconds (default: 30) |
| `-sub-depth <n>` | scan | Crawl into discovered subdomains up to N levels deep (default: 0 = detect only) |
| `-headless` / `-no-headless` | auth, scan | Run browser headless or visible (default: headless) |
| `-login <path>` | fingerprint, scan | Entry path for pre-scan authentication |

---

## Cloud ML Models

All models run in the XAHICO cloud and are invoked automatically during scans. No model files are stored or executed locally.

| Model | Type | Purpose | Input | Output |
|---|---|---|---|---|
| Form Classifier | Random Forest + TF-IDF | Identify login forms from DOM text | Field labels, placeholders, button text | `is_login_form`, `confidence` |
| Page Classifier | LightGBM | Classify page type from content and structure | Page text, URL, title, 14 DOM features | `page_type`, `confidence` |
| Anomaly Detector | Isolation Forest | Score HTTP responses for statistical anomalies | 20 response features | `score` (0–1, higher = more anomalous) |

**Model improvement:** every classified form and scanned response is optionally submitted to the cloud (after quality verification) to improve model accuracy over time. Submissions are controlled server-side.

**Privacy:** the client never transmits raw page HTML, credentials, or cookie values to the cloud. Only derived feature vectors and metadata are sent.

---

## Output Format

All commands output JSON to stdout or to a file specified via `-output`. The schema is stable across patch versions — fields may be added in minor releases but will not be removed.

```json
{
  "metadata": {
    "status": "COMPLETE",
    "authenticated": true,
    "duration_ms": 14823,
    "stats": {
      "urls_visited": 34,
      "depth_reached": 5
    }
  },

  "asset_fingerprint": "sha256:a3f8c1d...",

  "endpoints": [
    {
      "url": "/api/v1/users",
      "method": "GET",
      "page_type": "api",
      "anomaly_score": 0.12,
      "discovered_via": "runtime_interception"
    },
    {
      "url": "/admin/settings",
      "method": "GET",
      "page_type": "admin",
      "anomaly_score": 0.88
    }
  ],

  "forms": [
    {
      "action": "/login",
      "method": "POST",
      "fields": ["username", "password"]
    }
  ],

  "dynamic_endpoints": [
    {
      "url": "/api/v1/users/{*}",
      "method": "POST",
      "discovered_via": "fetch"
    }
  ],

  "subdomains": {
    "discovered": ["api.example.com", "static.example.com"],
    "scanned": [],
    "sub_depth": 0
  },

  "summary": {
    "total_urls": 34,
    "total_endpoints": 48,
    "total_forms": 4,
    "dynamic_endpoints": 12,
    "anomalies": 2,
    "depth_reached": 5,
    "subdomains_discovered": 3,
    "subdomains_scanned": 0
  }
}
```

Pipe to `jq` for quick inspection:

```bash
vertigo scan https://app.example.com | jq '.summary'
```

---

## Debug Output

All debug output is suppressed unless `--debug` is passed. When enabled, structured log lines are written to stderr — one `key=value` pair per field, compatible with any log aggregator.

```
14:32:01  DEBUG  vertigo.scan.crawler           crawl_start          target='https://example.com'  depth=5  sub_depth=0
14:32:01  DEBUG  vertigo.scan.js_analyzer       interceptors_installed
14:32:02  DEBUG  vertigo.scan.crawler           url_loaded           url='https://example.com/'  status=200  elapsed_ms=843
14:32:02  DEBUG  vertigo.scan.crawler           subdomain_discovered  host='api.example.com'
14:32:03  DEBUG  vertigo.scan.page_classifier   page_classified      url='example.com/dashboard'  type=dashboard  confidence=0.934
14:32:04  DEBUG  vertigo.scan.anomaly_detector  anomaly_detected     score=0.8821  url='https://example.com/admin'
14:32:05  DEBUG  vertigo.scan.crawler           crawl_complete       status=COMPLETE  urls=34  endpoints=58  anomalies=1
```

---

## Licence

Vertigo is proprietary software. A valid `XAHICO_VERTIGO_API_KEY` is required for ML-backed features (authentication and deep scanning). Fingerprinting is available without a key.

- Licences are available at [vertigo.xahico.com](https://vertigo.xahico.com)
- Keys carry an expiry date and are validated against the XAHICO cloud on each invocation
- To revoke a key, contact [support@xahico.com](mailto:support@xahico.com)

---

<div align="center">
  Built by <a href="https://xahico.com">XAHICO Corporation</a> &nbsp;·&nbsp; <a href="https://vertigo.xahico.com">vertigo.xahico.com</a>
</div>
