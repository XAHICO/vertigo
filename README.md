<div align="center">

```
██╗   ██╗███████╗██████╗ ████████╗██╗ ██████╗  ██████╗
██║   ██║██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝ ██╔═══██╗
██║   ██║█████╗  ██████╔╝   ██║   ██║██║  ███╗██║   ██║
╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██║██║   ██║██║   ██║
 ╚████╔╝ ███████╗██║  ██║   ██║   ██║╚██████╔╝╚██████╔╝
  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝
```

**AI-Powered Web Application Security Auditing Suite**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/xahico-vertigo?style=flat-square&logo=pypi&color=blue)](https://pypi.org/project/xahico-vertigo)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red?style=flat-square)](https://vertigo.xahico.com)
[![Cloud ML](https://img.shields.io/badge/ML-cloud--backed-8A2BE2?style=flat-square&logo=google-cloud)](https://vertigo.xahico.com)
[![Status: Active](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)](https://vertigo.xahico.com)

[**Documentation**](https://vertigo.xahico.com/docs) · [**Get a Licence Key**](https://vertigo.xahico.com) · [**Support**](https://xahico.com/support)

</div>

---

## What is Vertigo?

Vertigo is a professional-grade web application security auditing tool for security engineers and red teams. It drives a real Chromium browser — not an HTTP client — and pairs that browser automation with cloud-hosted machine learning models to do things that traditional scanners cannot:

- **Log into modern web apps** that rely on JavaScript-rendered forms, SPA routing, or custom auth flows — without writing a single line of site-specific glue code
- **Classify every page** it visits (login, dashboard, admin, API, etc.) so you always know what you're looking at
- **Score every HTTP response** for anomalies using an Isolation Forest model trained on millions of real-world traffic samples
- **Fingerprint the full asset surface** in a way that is deterministic enough to diff between deployments in a CI pipeline

All ML inference runs exclusively in the XAHICO cloud. No model weights, training data, or feature vectors are ever stored on your machine. The client package contains only browser automation and HTTP plumbing — it is lightweight, pip-installable, and has no GPU or native ML dependencies.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           vertigo CLI                                │
│                auth  │  fingerprint  │  scan                         │
└─────────────────┬──────────────┬──────────────┬──────────────────────┘
                  │              │              │
                  ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Playwright Browser Engine                      │
│  ┌──────────────┐  ┌────────────────────┐  ┌──────────────────────┐ │
│  │  Auth Engine │  │  Shallow Crawler   │  │  Deep BFS Crawler    │ │
│  │              │  │  (Katana-backed)   │  │  JS analysis +       │ │
│  │ ML form det. │  │                    │  │  subdomain tracking  │ │
│  └──────┬───────┘  └─────────┬──────────┘  └──────────┬───────────┘ │
└─────────┼────────────────────┼─────────────────────────┼────────────┘
          │                    │                         │
          └────────────────────┴─────────────────────────┘
                               │  HTTPS (feature vectors only)
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│               XAHICO Cloud ML  (vertigo.services.xahico.com)           │
│                                                                        │
│  ┌────────────────────┐  ┌───────────────────┐  ┌──────────────────┐  │
│  │  Form Classifier   │  │  Page Classifier  │  │ Anomaly Detector │  │
│  │  (Random Forest)   │  │  (LightGBM)       │  │ (IsolationForest)│  │
│  └────────────────────┘  └───────────────────┘  └──────────────────┘  │
│                                                                        │
│             ┌──────────────────────────────────────────┐              │
│             │  Human-verified sample ingestion         │              │
│             │  (continuous model improvement)           │              │
│             └──────────────────────────────────────────┘              │
└────────────────────────────────────────────────────────────────────────┘
```

No ML artefacts live on the client. Raw HTML and credentials never leave your machine — only compact numeric feature vectors are sent to the cloud.

---

## Installation

```bash
pip install xahico-vertigo
```

Vertigo requires Python 3.9+ and a working Playwright installation. After installing, install the Chromium browser binary:

```bash
playwright install chromium
```

### Set your licence key

```bash
vertigo init
# Enter your XAHICO Vertigo licence key: xvg_xxxxxxxxxxxx
# [vertigo] Licence key saved to: ~/.bashrc, ~/.zshrc, ~/.profile
# [vertigo] Reload your shell or run:
#   export XAHICO_VERTIGO_LICENSE_KEY="xvg_xxxxxxxxxxxx"
```

`vertigo init` writes an `export` line to your shell profiles so the key is available in every new terminal. You can also supply the key directly and validate it in one step:

```bash
vertigo init --key xvg_xxxxxxxxxxxx --validate
# [vertigo] Validating key against XAHICO cloud … OK
# [vertigo]   Plan: pro  ·  Expires: 2027-01-01T00:00:00+00:00
```

Or set the environment variable manually:

```bash
export XAHICO_VERTIGO_LICENSE_KEY="xvg_xxxxxxxxxxxx"
```

> **Licence keys** are available at [vertigo.xahico.com](https://vertigo.xahico.com). Core crawling and fingerprinting work without a key. ML-backed features (form detection, page classification, anomaly scoring) require a valid key.

---

## Commands

### `vertigo init` — configure your licence key

```
vertigo init [--key KEY] [--validate]
```

| Flag | Description |
|---|---|
| `--key KEY` | Provide the key non-interactively (useful in CI) |
| `--validate` | Round-trip validate the key against the XAHICO cloud before saving |

---

### `vertigo auth` — authenticate to a web application

Drives Chromium to log into a target app. Vertigo uses ML-guided form detection to find and fill the login form — no hardcoded selectors, no site-specific plugins.

```
vertigo auth <target> -username <user> -password <pass> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-entry PATH` | `/` | URL path to start from |
| `-username STR` | — | Username / email |
| `-password STR` | `""` | Password |
| `-headless` / `-no-headless` | headless | Show or hide the browser window |
| `-output FILE` | stdout | Write JSON session to file |
| `-silent` | false | Suppress JSON output to stdout |
| `--debug` | false | Emit structured debug logs to stderr |

**Example — authenticate and save session:**

```bash
vertigo auth https://app.example.com \
    -username admin@example.com \
    -password hunter2 \
    -output session.json
```

**Example output (`session.json`):**
```json
{
  "success": true,
  "target": "https://app.example.com",
  "cookies": [
    {
      "name": "sessionid",
      "value": "abc123",
      "domain": "app.example.com",
      "httpOnly": true
    }
  ],
  "headers": {
    "Authorization": "Bearer eyJhbGciOiJ..."
  },
  "storage": {
    "localStorage": { "user_id": "42" },
    "sessionStorage": {}
  },
  "fingerprint": "d4e5f6a7b8c9..."
}
```

---

### `vertigo fingerprint` — generate a stable asset fingerprint

Shallow-crawls the application (powered by Katana) and produces a deterministic SHA-256 fingerprint of the full asset surface. Use the fingerprint in CI to detect unexpected changes between deployments.

```
vertigo fingerprint <target> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-entry PATH` | `/` | Crawl entry point |
| `-depth N` | `3` | Maximum crawl depth |
| `-limit N` | `10` | Maximum URLs to visit |
| `-concurrency N` | `3` | Parallel browser contexts |
| `-timeout N` | `30` | Per-page timeout in seconds |
| `-login PATH` | — | Login page path (enables authenticated crawl) |
| `-username STR` | — | Username for authenticated crawl |
| `-password STR` | — | Password for authenticated crawl |
| `-output FILE` | stdout | Write JSON result to file |

**Example — unauthenticated fingerprint:**

```bash
vertigo fingerprint https://app.example.com \
    -depth 4 -limit 50 \
    -output fingerprint.json
```

**Example — authenticated fingerprint:**

```bash
vertigo fingerprint https://app.example.com \
    -login /login \
    -username admin@example.com \
    -password hunter2 \
    -depth 4 -limit 100 \
    -output fingerprint.json
```

**Example output:**
```json
{
  "metadata": {
    "target": "https://app.example.com",
    "status": "COMPLETE",
    "urls_visited": 47,
    "duration_seconds": 12.4
  },
  "asset_fingerprint": "sha256:a1b2c3d4e5f6...",
  "resource_hashes": {
    "endpoints": ["GET /api/users", "POST /api/login"],
    "static_resources": ["https://cdn.example.com/app.js"],
    "security_headers": {
      "strict-transport-security": true,
      "content-security-policy": true,
      "x-frame-options": false
    }
  }
}
```

**Diff fingerprints in CI:**

```bash
# Capture baseline
vertigo fingerprint https://staging.example.com -output baseline.json

# After deployment, re-fingerprint and compare
vertigo fingerprint https://staging.example.com -output current.json

python -c "
import json
a = json.load(open('baseline.json'))['asset_fingerprint']
b = json.load(open('current.json'))['asset_fingerprint']
print('UNCHANGED' if a == b else f'CHANGED  {a} → {b}')
"
```

---

### `vertigo scan` — deep ML-assisted security scan

Performs a full BFS crawl, sending every visited page through all three cloud ML models: page classifier, form classifier, and anomaly detector.

```
vertigo scan <target> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-entry PATH` | `/` | Crawl entry point |
| `-depth N` | `3` | Maximum crawl depth |
| `-limit N` | `10` | Maximum URLs to visit |
| `-concurrency N` | `3` | Parallel browser contexts |
| `-timeout N` | `30` | Per-page timeout in seconds |
| `-login PATH` | — | Login page path (enables authenticated scan) |
| `-username STR` | — | Username |
| `-password STR` | — | Password |
| `-sub-depth N` | `0` | Crawl depth into discovered subdomains (`0` = detect only) |
| `-output FILE` | stdout | Write JSON report to file |
| `-silent` | false | Suppress stdout output |
| `--debug` | false | Verbose cloud request logging |

**Example — authenticated deep scan:**

```bash
vertigo scan https://app.example.com \
    -login /login \
    -username admin@example.com \
    -password hunter2 \
    -depth 5 -limit 200 \
    -sub-depth 2 \
    -output report.json
```

**Example output (excerpt):**
```json
{
  "metadata": {
    "target": "https://app.example.com",
    "status": "COMPLETE",
    "urls_visited": 183,
    "authenticated": true,
    "duration_seconds": 94.2
  },
  "pages": [
    {
      "url": "https://app.example.com/admin/users",
      "page_type": "admin",
      "page_type_confidence": 0.9741,
      "anomaly_score": 0.07,
      "forms": [
        {
          "is_login_form": false,
          "confidence": 0.9812,
          "action": "/admin/users/delete",
          "method": "POST"
        }
      ],
      "security_headers": {
        "x-frame-options": true,
        "content-security-policy": false,
        "strict-transport-security": true
      }
    },
    {
      "url": "https://app.example.com/api/v1/export",
      "page_type": "api",
      "page_type_confidence": 0.9960,
      "anomaly_score": 0.87,
      "anomaly_flag": true,
      "note": "High anomaly score — response deviates significantly from baseline"
    }
  ],
  "subdomains_discovered": ["api.example.com", "static.example.com"],
  "summary": {
    "admin_pages": 4,
    "api_endpoints": 31,
    "anomalous_pages": 2,
    "login_forms": 1,
    "missing_csp": 12
  }
}
```

---

## Python API

Vertigo is also usable as a Python library for scripting and integration into security automation pipelines.

```python
import vertigo
from vertigo.cloud_client import get_client

client = get_client()  # reads XAHICO_VERTIGO_LICENSE_KEY from environment

# Step 1 — Authenticate
session = vertigo.authenticate(
    target="https://app.example.com",
    entry="/login",
    username="admin@example.com",
    password="hunter2",
    headless=True,
    cloud_client=client,
)

if not session.success:
    raise RuntimeError(f"Auth failed: {session.failure_reason}")

# Step 2 — Fingerprint the authenticated surface
fp = vertigo.fingerprint(
    target="https://app.example.com",
    entry="/dashboard",
    depth=4,
    limit=100,
    session=session,
    cloud_client=client,
)
print("Asset fingerprint:", fp["asset_fingerprint"])

# Step 3 — Deep scan
report = vertigo.scan(
    target="https://app.example.com",
    entry="/dashboard",
    depth=5,
    limit=200,
    session=session,
    cloud_client=client,
    sub_depth=1,
)

flagged = [p for p in report.get("pages", []) if p.get("anomaly_score", 0) > 0.75]
print(f"High-anomaly pages: {len(flagged)}")
for page in flagged:
    print(f"  {page['url']}  score={page['anomaly_score']}")
```

### Using the cloud client directly

```python
from vertigo.cloud_client import CloudClient

client = CloudClient(api_key="xvg_xxxxxxxxxxxx", debug=True)

# Validate licence
info = client.validate_license()
# {"valid": True, "expires_at": "2027-01-01T00:00:00+00:00"}

# Classify a form snippet
result = client.classify_form(
    "<form><label>Email</label><input type=email><button>Sign in</button></form>"
)
# {"is_login_form": True, "confidence": 0.9741}

# Score an HTTP response for anomalies
result = client.detect_anomaly({
    "status_code": 200,
    "content_length": 48320,
    "response_time": 1820,
    "content_type": "application/json",
    "headers": {"x-frame-options": "DENY"},
    "num_forms": 0,
    "num_scripts": 0,
    "redirect_count": 0,
})
# {"score": 0.8712}  ← high score → investigate

# Submit a training sample (no licence key required)
client.submit_sample(
    sample_type="auth",
    sample_data={"form_html": "<form>...</form>", "url": "https://example.com/login"},
    label="login",
)
```

---

## Cloud ML Models

All inference is served from `vertigo.services.xahico.com`. Models are retrained continuously as new Human-verified samples are ingested.

| Model | Algorithm | Task | Input |
|---|---|---|---|
| Form Classifier | Random Forest + TF-IDF | Is this a login form? | DOM text features |
| Page Classifier | LightGBM + TF-IDF | What type of page is this? | Page text + 14 structural features |
| Anomaly Detector | Isolation Forest | Is this response anomalous? | 20 HTTP response features |

**Page types** returned by the page classifier: `login`, `dashboard`, `profile`, `admin`, `api`, `static`, `error`, `form`, `list`, `detail`, `unknown`.

**Anomaly score** ranges from `0.0` (indistinguishable from normal traffic) to `1.0` (highly anomalous). Scores above `0.75` are flagged in scan reports.

### Sample contribution

Every vertigo client can contribute training samples to improve model quality. Samples are verified before entering the training corpus — no manually curated labels required. Submission is fire-and-forget and will never raise an exception or disrupt your workflow.

---

## CI / CD Integration

### GitHub Actions — nightly scan

```yaml
name: Vertigo Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 2 * * *"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Vertigo
        run: |
          pip install xahico-vertigo
          playwright install chromium --with-deps

      - name: Fingerprint & scan
        env:
          XAHICO_VERTIGO_LICENSE_KEY: ${{ secrets.XAHICO_VERTIGO_LICENSE_KEY }}
        run: |
          vertigo fingerprint https://staging.example.com \
            -depth 4 -limit 100 \
            -login /login \
            -username ${{ secrets.SCAN_USER }} \
            -password ${{ secrets.SCAN_PASS }} \
            -output fingerprint.json

          vertigo scan https://staging.example.com \
            -depth 5 -limit 200 \
            -login /login \
            -username ${{ secrets.SCAN_USER }} \
            -password ${{ secrets.SCAN_PASS }} \
            -output scan_report.json

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: vertigo-reports
          path: "*.json"
```

### Pre-deployment anomaly gate

```bash
#!/usr/bin/env bash
export XAHICO_VERTIGO_LICENSE_KEY="xvg_xxxxxxxxxxxx"

vertigo scan "$STAGING_URL" \
    -login /login -username "$SCAN_USER" -password "$SCAN_PASS" \
    -depth 4 -limit 150 -silent \
    -output /tmp/report.json

ANOMALOUS=$(python -c "
import json, sys
r = json.load(open('/tmp/report.json'))
flagged = [p for p in r.get('pages',[]) if p.get('anomaly_score',0) > 0.8]
print(len(flagged))
")

if [ "$ANOMALOUS" -gt 0 ]; then
  echo "GATE FAILED: $ANOMALOUS anomalous page(s) detected" >&2
  exit 1
fi
echo "Gate passed."
```

---

## Security & Privacy

- **No raw HTML leaves your machine.** Only compact numeric feature vectors (< 1 KB per page) are sent to the XAHICO cloud.
- **No credentials are transmitted.** Usernames and passwords are used only by the local Playwright browser process.
- **No ML models are stored locally.** There are no pickle files, weights, or training data in the client package.
- **Licence keys are validated server-side** against Google Cloud Secret Manager. Each key is stored as a GCP Secret named `xvg_<fingerprint>` with a native GCP `expire_time` field — no expiry logic lives in the client.
- **TLS everywhere.** All cloud communication uses HTTPS/TLS 1.3.

---

## Requirements

| | Version |
|---|---|
| Python | 3.9 or later |
| Playwright | 1.40+ |
| BeautifulSoup4 | 4.12+ |
| OS | Linux, macOS, Windows |
| Chromium | installed via `playwright install chromium` |

Cloud ML features additionally require a valid `XAHICO_VERTIGO_LICENSE_KEY` and outbound HTTPS access to `vertigo.services.xahico.com`.

---

## Licence

Vertigo is proprietary software. See [LICENSE.txt](LICENSE.txt) for full terms. A time-limited evaluation licence is available at [vertigo.xahico.com](https://vertigo.xahico.com).

---

<div align="center">

Built by [XAHICO Corporation](https://xahico.com) · [vertigo.xahico.com](https://vertigo.xahico.com)

</div>
