# Email-Threat
## SIH 2026 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

---

## Project Overview

This platform analyses suspicious emails and provides:
- Email parsing and metadata extraction
- SPF, DKIM and DMARC authentication analysis
- AI-powered phishing and threat detection
- URL extraction and suspicious-link investigation
- Email routing analysis using Received headers
- IP address geolocation and infrastructure intelligence
- An explainable risk score (0–100)
- A downloadable PDF forensic investigation report
- A user-friendly web dashboard

---

## Module 1 — Email Ingestion and Parsing Engine (Complete)

Accepts a `.eml` file and extracts its full contents into a structured
Python dictionary ready for consumption by future modules.

### Prerequisites

- Python 3.10 or newer (tested on Python 3.14.2)
- No external packages are required for Module 1

Verify your Python version:
```powershell
python --version
```

---

### Repository Structure

```
Email-Threat/
├── src/
│   ├── __init__.py            ← Package entrypoint exporting public APIs
│   ├── email_parser.py        ← Module 1: Email parser & extractor
│   ├── auth_verifier.py       ← Module 2: SPF, DKIM, DMARC verifier
│   ├── url_analyzer.py        ← Module 3: URL threat analysis engine
│   ├── routing_analyzer.py    ← Module 4: Routing & GeoIP engine
│   ├── ai_text_analyzer.py    ← Module 5: AI phishing & scam-text classifier
│   ├── risk_scorer.py         ← Module 6: Evidence-based email risk scoring engine
│   ├── report_generator.py    ← Module 7: PDF forensic intelligence report generator
│   └── dashboard_pipeline.py  ← Module 8: Pipeline orchestrator for interactive UI
├── tests/
│   ├── __init__.py
│   ├── test_email_parser.py   ← Module 1 tests (61 tests)
│   ├── test_auth_verifier.py  ← Module 2 tests (38 tests)
│   ├── test_url_analyzer.py   ← Module 3 tests (49 tests)
│   ├── test_routing_analyzer.py ← Module 4 tests (37 tests)
│   ├── test_ai_text_analyzer.py ← Module 5 tests (26 tests)
│   ├── test_risk_scorer.py    ← Module 6 tests (32 tests)
│   ├── test_report_generator.py ← Module 7 tests (19 tests)
│   ├── test_dashboard_pipeline.py ← Module 8 tests: Pipeline orchestrator (12 tests)
│   └── test_dashboard_ui.py   ← Module 8 tests: UI & PDF export integration (5 tests)
├── samples/
│   ├── plain_text.eml         ← Synthetic plain-text sample
│   ├── multipart.eml          ← Synthetic multipart (text + HTML) sample
│   ├── phishing_sample.eml    ← Synthetic phishing-style sample
│   └── dkim_signed.eml        ← Synthetic DKIM-signed sample
├── reports/                   ← Generated PDF forensic investigation reports
├── demo_report.py             ← Module 7 runnable end-to-end PDF report demonstration
├── app.py                     ← Module 8 Streamlit forensic intelligence dashboard
├── requirements.txt
├── README.md
└── gautham.txt                ← Team test file (untouched)
```

---

### Running the Parser (Quick Demo)

Open PowerShell, navigate to the project root, then run:

```powershell
cd "C:\Users\hansi\OneDrive\Desktop\Email-Threat\Email-Threat"

python -c "
import json, sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file

result = parse_email_file('samples/plain_text.eml')
print('Subject :', result['email_metadata']['subject'])
print('From    :', result['email_metadata']['from'])
print('URLs    :', len(result['urls']))
print('Warnings:', result['parse_warnings'])
print('Errors  :', result['errors'])
"
```

To see the full JSON output:

```powershell
python -c "
import json, sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
result = parse_email_file('samples/phishing_sample.eml')
print(json.dumps(result, indent=2))
" | more
```

---

### Running the Automated Tests

```powershell
cd "C:\Users\hansi\OneDrive\Desktop\Email-Threat\Email-Threat"

# Run all tests with verbose output (recommended)
python -m unittest discover -s tests -v

# Run tests and show only failures
python -m unittest discover -s tests

# Run a single test class
python -m unittest tests.test_email_parser.TestPlainTextEmail -v
```

Expected output (all tests passing):
```
test_date_extracted (tests.test_email_parser.TestPlainTextEmail) ... ok
test_file_metadata (tests.test_email_parser.TestPlainTextEmail) ... ok
...
Ran 42 tests in 0.XXXs
OK
```

---

### Output Structure

`parse_email_file(path)` always returns a dictionary with these keys:

| Key                      | Type          | Description |
|--------------------------|---------------|-------------|
| `file_metadata`          | dict          | Filename, size, parse timestamp |
| `email_metadata`         | dict          | From, To, Cc, Subject, Date, etc. |
| `headers`                | dict          | All raw headers in original order |
| `received_headers`       | list[str]     | Routing hops (first = most recent) |
| `authentication_headers` | dict          | SPF, DKIM, DMARC evidence |
| `body`                   | dict          | `plain_text` and `html` content |
| `urls`                   | list[dict]    | Extracted URLs (never visited) |
| `parse_warnings`         | list[str]     | Non-fatal issues |
| `errors`                 | list[str]     | Fatal issues (parser stopped early) |

---

### Security Guarantees (Module 1)

- URLs are **extracted for analysis only** — never visited or opened
- Attachments are **identified but never executed**
- HTML is **extracted as raw text** — never rendered in a browser
- **Zero network requests** are made by any function in this module
- Email data is **never transmitted** to external services

---

### Known Limitations (Module 1)

1. SPF, DKIM and DMARC headers are **extracted as-is** — live DNS verification
   is not performed (that is Module 2's responsibility).
2. Attachments are detected and skipped — their contents are not read or analysed.
3. Nested multipart structures are walked correctly, but only the first
   `text/plain` and first `text/html` part are returned.
4. The maximum accepted file size is 25 MB.

---

## Module 2 — SPF, DKIM and DMARC Authentication Verification (Complete)

Performs rigorous email authentication analysis implementing a **Three-Layer Evidence Model**:
1. **Layer 1: Observed Evidence (Untrusted)** — Preserves raw header claims (`Received-SPF`, `Authentication-Results`, `Return-Path`) exactly as recorded by original receiving systems without treating them as verified facts.
2. **Layer 2: Independently Verified Checks**:
   - **DKIM**: Cryptographic signature verification using `dkimpy` against the email's original, un-decoded bytes and DNS public keys. Every signature is verified independently.
   - **SPF**: DNS TXT record retrieval only. Explicitly documents that SPF mechanism evaluation (`include`, `redirect`, `ip4`, `mx`, etc.) cannot be performed on uploaded `.eml` files without a delivery-time connecting IP. `independent_result` is always `not_checked`.
   - **DMARC**: RFC 7489 DNS policy lookup, structural tag-value parsing, Public Suffix List (PSL)-aware organizational domain alignment via `tldextract`, and fallback to organizational domain if a subdomain publishes no policy.
3. **Layer 3: Derived Conclusions**: Clear policy verdicts (`pass`, `indeterminate`, `none`, `temperror`, `permerror`). Because SPF cannot be independently evaluated from an uploaded file, DMARC never emits `fail` (failure of both SPF and DKIM is required to declare DMARC failure).

### Dependencies

```
dnspython>=2.9.0
dkimpy>=1.1.8
tldextract>=5.4.0
```

Install via:
```powershell
pip install -r requirements.txt
```

---

### Running the Verifier (Quick Demo)

```powershell
python -c "
import sys, json
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.auth_verifier import verify_authentication

sample = 'samples/dkim_signed.eml'
with open(sample, 'rb') as f:
    raw_bytes = f.read()

parsed = parse_email_file(sample)
report = verify_authentication(parsed, raw_bytes)

print('Overall Result :', report['overall_result'])
print('Summary        :', report['summary'])
print('DKIM Overall   :', report['dkim']['overall_result'])
print('SPF Independent:', report['spf']['independent_result'])
print('DMARC Result   :', report['dmarc']['result'])
"
```

---

### Running the Test Suite (All 211 Tests)

```powershell
# Run all 211 automated tests across Modules 1, 2, 3, 4, and 5
python -m unittest discover -s tests -v

# Run only Module 5 AI text classification tests (26 tests)
python -m unittest tests.test_ai_text_analyzer -v

# Run only Module 4 routing and geolocation tests (37 tests)
python -m unittest tests.test_routing_analyzer -v

# Run only Module 3 URL analysis tests (49 tests)
python -m unittest tests.test_url_analyzer -v

# Run only Module 2 authentication tests (38 tests)
python -m unittest tests.test_auth_verifier -v

# Run only Module 1 parser tests (61 tests)
python -m unittest tests.test_email_parser -v
```

---

## Module 3 — URL Threat Analysis Engine (Complete)

Performs comprehensive static, heuristic, lexical, and structural analysis on URLs extracted from emails, with **strict offline safety guarantees**.

### Core Features & Heuristics Evaluated

1. **Syntax & Component Extraction**: Protocol scheme, hostname, port, path, query parameters, fragment.
2. **IP Address Literals**: Identifies direct IPv4 and IPv6 host literals, categorized by scope (global/public, private, loopback, reserved), plus integer/dword obfuscation.
3. **Embedded Authority Credentials**: Detects deceptive `user:pass@host` or `brand.com@attacker.com` patterns; masks sensitive passwords in normalized logs.
4. **Punycode & IDN Homographs**: Flags `xn--` Punycode domains and detects non-Latin scripts (Cyrillic, Greek, etc.) visually mimicking ASCII characters.
5. **Brand Spoofing & Deceptive Subdomains**: Detects high-profile brand names (PayPal, Microsoft, Google, Apple, etc.) or pseudo-TLDs embedded in subdomains on unrelated organizational domains, including leetspeak typosquatting (e.g. `paypa1-restore`).
6. **Excessive Subdomain Depth**: Flags deep subdomain structures (>= 4 levels) typical of bulletproof infrastructure.
7. **Known URL Shorteners**: Identifies URL shortening domains (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that mask actual destinations.
8. **Payload File Extensions**: Flags direct download paths pointing to executables, scripts, or archives (`.exe`, `.scr`, `.bat`, `.iso`, `.zip`, `.apk`, etc.).
9. **Path Traversal & Obfuscation**: Detects directory traversal sequences (`../`, `..%2f`), null-byte injection (`%00`), and double percent-encoding (`%25`).
10. **High-Risk TLDs**: Flags disposable domains under high-abuse TLDs (`.xyz`, `.top`, `.buzz`, etc.).
11. **Scheme Analysis**: Flags executable/dangerous URI schemes (`javascript:`, `data:`, `file:`) with critical severity. Notes insecure plaintext HTTP transport (without treating HTTP alone as proof of malice).

### Security & Forensic Invariants

- **Zero Network Access**: Never opens, visits, crawls, or resolves DNS for any URL. Completely immune to token triggering, CSRF, or tracking-pixel activation.
- **Original Evidence Preservation**: Preserves the original raw URL unmodified for forensic records.
- **Safe Defanging**: Automatically generates human-safe representations (e.g., `hxxps://example[.]com/login`).
- **Bounded Scoring**: Produces an explainable heuristic risk score strictly bounded between 0 and 100 (`none`: 0, `low`: 1–29, `medium`: 30–69, `high`: 70–89, `critical`: 90–100).
- **Transparent Threat Intelligence Reporting**: Explicitly reports external reputation status as `not_checked` rather than falsely declaring URLs "safe".

---

### Running the URL Analyzer (Quick Demo)

```powershell
python -c "
import sys, json
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.url_analyzer import analyze_urls

# Parse email and pass directly to the URL analyzer
parsed = parse_email_file('samples/phishing_sample.eml')
url_report = analyze_urls(parsed)

print('Total URLs Analyzed   :', url_report['total_urls_analyzed'])
print('Max URL Risk Score    :', url_report['max_risk_score'])
print('Overall Risk Level    :', url_report['overall_url_risk_level'])
print('High-Risk URL Count   :', url_report['high_risk_url_count'])
print('Summary               :', url_report['summary'])
print('\nIndividual URL Findings:')
for item in url_report['results']:
    print(f'  [{item[\"risk_level\"].upper()}] {item[\"defanged_url\"]}')
    for ind in item['indicators']:
        print(f'     - {ind[\"title\"]} (+{ind[\"score_contribution\"]})')
"
```

---

## Module 4 — Email Routing Analysis and IP Geolocation Engine (Complete)

Performs forensic hop-by-hop analysis of `Received` headers, classifies candidate IP address scopes, enforces explicit trust boundaries, models chronological routes, and integrates an offline, decoupled IP geolocation provider.

### Core Features & Analysis Capabilities

1. **Header Parsing & Normalization**:
   - Parses unfolded, folded, and multi-line `Received` headers.
   - Extracts routing clauses: `from_host`, `by_host`, `protocol` (`with`), queue/message ID (`id`), recipient (`for`).
   - Extracts RFC 2822 timestamps with pattern fallback for malformed headers lacking semicolons.
   - Preserves original raw header text verbatim as forensic evidence.
2. **Evidence & Trust Boundaries**:
   - Solves the core forensic problem: **Received headers can be forged or prepended by attackers**.
   - Assigns explicit trust labels:
     - `verified_by_configured_source`: Hops recorded directly by your configured trusted receiving mail servers.
     - `untrusted_header_claim`: Hops reported by upstream, external, or unknown relays.
     - `parsed_but_unverified`: Hops successfully parsed when no trusted boundary configuration is supplied.
     - `not_checked`: Evidence or lookups that were not verified.
   - Never assumes the earliest IP found is the sender's authentic originating IP.
3. **Candidate IP Extraction & Classification**:
   - Scans and extracts bracketed and bare IPv4 and IPv6 addresses across all hops.
   - Uses standard-library `ipaddress` to strictly classify:
     - Global / Public routable IPs
     - Private networks (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
     - Loopback (`127.0.0.0/8`, `::1`)
     - Link-Local (`169.254.0.0/16`, `fe80::/10`)
     - Multicast (`224.0.0.0/4`, `ff00::/8`)
     - Reserved & documentation networks (e.g. RFC 5737 `TEST-NET`)
   - Deduplicates repeated IPs while preserving occurrences and hop associations.
   - **Strict Privacy & Safety Rule**: Private, loopback, link-local, multicast, reserved, and invalid IPs are **never** submitted to any geolocation provider.
4. **Decoupled Offline Geolocation Provider Interface**:
   - `BaseGeoLocationProvider`: Abstract base class allowing modular provider implementations.
   - `OfflineGeoIPProvider`: Supports offline MaxMind GeoLite2 City databases (`.mmdb`).
     - **Zero Automatic Downloads**: Never downloads databases automatically.
     - **Zero External API Calls**: Does not transmit email headers or IPs across the Internet.
     - **Graceful Degradation**: If no database path is configured or `geoip2` is not installed, marks lookups as `not_checked` with an informative reason rather than crashing or inventing data.
   - `MockGeoIPProvider`: In-memory mock provider enabling deterministic, zero-network unit testing.
5. **Route Order vs Chronological Order**:
   - Maintains document/header order (Hop 0 = recipient/newest MTA).
   - Reconstructs chronological route order (oldest timestamp first to newest last).
   - Flags ordering ambiguities and notes when timestamps are missing or malformed.
6. **Forensic Distinction (Mail Server Geolocation vs Human Location)**:
   - Geolocation coordinates indicate the hosting facility or data center of the relaying mail server.
   - Mail servers, corporate gateways, VPNs, cloud services, and webmail interfaces regularly relay mail from different regions than where the author physically resides.

---

### Running the Routing Analyzer (Quick Demo)

```powershell
python -c "
import sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.routing_analyzer import analyze_email_routing

parsed = parse_email_file('samples/phishing_sample.eml')
config = {'trusted_hosts': ['mx.example-victim.com']}
report = analyze_email_routing(parsed, config=config)

print('Total Hops Analyzed   :', len(report['hops']))
print('Trusted Hops Count    :', report['trust_analysis']['trusted_hops_count'])
print('Untrusted Hops Count  :', report['trust_analysis']['untrusted_hops_count'])
print('Trust Summary         :', report['trust_analysis']['summary'])
print('Route Order (Header)  :', report['route_order']['header_order'])
print('Route Order (Chrono)  :', report['route_order']['chronological_order'])
print('\nHop Details:')
for h in report['hops']:
    idx = h['index']
    trust = h['trust_label']
    f_h = h['from_host']
    b_h = h['by_host']
    print(f'  Hop {idx}: [{trust}] from {f_h} by {b_h}')

print('\nUnique IP Classifications:')
for ip in report['unique_ips']:
    ip_addr = ip['ip']
    label = ip['ip_type_label']
    elig = ip['is_eligible_for_geolocation']
    print(f'  IP: {ip_addr} ({label}) -> Eligible for GeoIP: {elig}')
"
```

---

## Module 5 — AI-Based Phishing and Scam-Text Classification Engine (Complete)

Performs deep textual classification of email subject lines and body text using fine-tuned sequence classification transformer models.

### Core Features & Design Principles

1. **Transformer-Based Architecture**:
   - Default Model: `aamoshdahal/email-phishing-distilbert-finetuned` (lightweight, high-speed DistilBERT sequence classifier).
   - Evaluates combined email context (`Subject: <subject>\n\n<body>`) as optimized during fine-tuning.
   - Enforces configurable context limits (`max_length=512` tokens) with explicit truncation detection and warnings.
2. **Verified Label Mapping Evidence**:
   - Solves the ambiguity of `LABEL_0` and `LABEL_1`:
     - The model's `config.json` lacks explicit `id2label` fields, causing Hugging Face Transformers to emit default synthetic labels (`LABEL_0`, `LABEL_1`).
     - Analysis of the author's published model card documentation (README.md) verified the exact training label encoding:
       - **Index 0 (`LABEL_0`) = `legitimate`**
       - **Index 1 (`LABEL_1`) = `phishing`**
   - Unmapped or unverified labels (e.g. multi-class models or missing configurations) are strictly marked `semantic_verdict = "unknown"` and `interpretation_status = "unverified_label_mapping"` rather than guessed.
3. **Decoupled Raw & Semantic Outputs**:
   - Preserves raw model output (`predicted_index`, `raw_label`, `confidence`, `probabilities` dictionary) completely separate from semantic interpretation.
4. **Calibrated Confidence Disclaimer**:
   - Explicitly notes that model softmax confidence represents statistical training distribution probability, **not** a calibrated probability of real-world maliciousness.
5. **Graceful Degradation & Zero Network Invariant**:
   - In ordinary environments without `torch` and `transformers` installed, the engine reports `analysis_status = "unavailable"` with a descriptive reason. It **never** fabricates fake heuristic outputs to mimic AI.
   - All automated unit tests run completely offline with mocked inference and zero live network or model downloading.
6. **Thread-Safe In-Memory Caching**:
   - Prevents expensive re-loading of model weights on every email via a thread-safe singleton cache (`_MODEL_CACHE`) with an explicit cache clearing utility (`clear_model_cache()`).

---

### Running the AI Text Analyzer (Quick Demo)

#### Demo A: Real Environment Check (Reports Unavailable Gracefully if PyTorch is not yet installed)
```powershell
python -c "
import sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.ai_text_analyzer import analyze_email_text

parsed = parse_email_file('samples/phishing_sample.eml')
report = analyze_email_text(parsed)

print('Analysis Status      :', report['analysis_status'])
print('Model Status         :', report['model_metadata']['model_status'])
print('Semantic Verdict     :', report['classification']['semantic_verdict'])
print('Interpretation Status:', report['classification']['interpretation_status'])
print('Risk Indication      :', report['risk_indication'])
print('Warnings             :', report['warnings'])
"
```

#### Demo B: Mocked/Simulated Model Run (Demonstrating Verified Classification)
```powershell
python -c "
import sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.ai_text_analyzer import analyze_email_text

parsed = parse_email_file('samples/phishing_sample.eml')

# Simulated model classifier output
mock_classifier = lambda text: {
    'predicted_index': 1,
    'raw_label': 'LABEL_1',
    'confidence': 0.9942,
    'probabilities': {'LABEL_0': 0.0058, 'LABEL_1': 0.9942},
    'is_truncated': False
}

report = analyze_email_text(parsed, config={'custom_classifier': mock_classifier})

print('Analysis Status      :', report['analysis_status'])
print('Model Status         :', report['model_metadata']['model_status'])
print('Raw Model Label      :', report['raw_model_output']['raw_label'])
print('Raw Confidence       :', report['raw_model_output']['confidence'])
print('Semantic Verdict     :', report['classification']['semantic_verdict'])
print('Interpretation Status:', report['classification']['interpretation_status'])
print('Mapping Evidence     :', report['classification']['mapping_evidence'])
print('Risk Indication      :', report['risk_indication'])
print('Subject Extracted    :', report['text_extracted']['subject'])
print('Body Preview         :', report['text_extracted']['body_preview'][:80])
"
```

---

## Module 6 — Evidence-Based Email Risk Scoring Engine (Complete)

Synthesizes, cross-correlates, and aggregates forensic findings across Modules 1 through 5 into a unified, explainable, bounded email threat assessment.

### Four-Pillar Evidence Architecture

| Pillar | Focus | Maximum Weight Budget | Key Indicators Evaluated |
|---|---|---|---|
| **Pillar 1: Identity & Authentication** | Modules 1 & 2 | **35 points** | Display-name brand impersonation, Return-Path domain mismatch, DKIM signature failure, DMARC policy failure, and sender spoofing. |
| **Pillar 2: URL & Link Threat Heuristics** | Module 3 | **35 points** | Subdomain brand deception, credential authority embedding, dangerous URI schemes (`javascript:`, `data:`), executable downloads (`.exe`, `.scr`), path traversal, homoglyphs, and high-abuse TLDs. Includes diminishing returns for repeated indicators. |
| **Pillar 3: AI Textual Phishing Intent** | Module 5 | **25 points** | Deep semantic classification via `aamoshdahal/email-phishing-distilbert-finetuned` weighted by softmax confidence. Evaluated with honest statistical caveats. |
| **Pillar 4: Transport & Routing Anomalies** | Module 4 | **15 points** | Relay hops, loop conditions, and chronological order inconsistencies. Public/foreign IPs are strictly neutral (0 points). |

### Core Scoring Formula & Principles

1. **Strict Range Bounding**:
   $$\text{Final Risk Score} \in [0, 100]$$
2. **Correlated Evidence Dampening**:
   Multiple occurrences of the same underlying threat indicator (e.g., 5 identical bit.ly shorteners) are scaled with diminishing returns ($1.0\times$ for the 1st, $+0.3\times$ for the 2nd, $+0.2\times$ for subsequent) and capped at the pillar's budget ceiling.
3. **Single-Signal Safeguard**:
   An isolated low-severity heuristic indicator (such as an unfamiliar TLD or single shortened link alone) is capped at a maximum score of 25 (Low risk) to prevent false positives without independent corroboration.
4. **Cross-Vector Synergy Bonus**:
   When multiple independent pillars simultaneously detect significant threats ($\ge 15$ points each, such as identity spoofing + phishing URL + AI phishing intent), a synergy bonus of $+10$ points is applied to reflect cross-vector coordination.
5. **Positive Signal Mitigations**:
   Cryptographic authentications (DKIM pass, DMARC pass, benign AI classification, clean verified URLs) mitigate risk scores by up to $-28$ points. Mitigations are automatically disabled if an active critical payload (`.exe`, `.scr`, dangerous URI scheme) is present.
6. **Honest Absence of Evidence**:
   Missing or unverified checks (`not_checked` SPF, absent GeoLite2 database, unavailable AI model, zero URLs, private routing hops) are strictly **0 points (NEUTRAL)** and never penalize the score.

### Risk Level Thresholds

- **0 – 19**: `none` (Minimal or No Threat Detected)
- **20 – 39**: `low` (Low Risk — Minor Informational Anomalies)
- **40 – 69**: `medium` (Medium Risk — Suspicious Indicators Present)
- **70 – 89**: `high` (High Risk — Phishing or Identity Spoofing Detected)
- **90 – 100**: `critical` (Critical Threat — Severe Phishing or Malicious Payload)

---

### Running Module 6 (Quick Demo)

```powershell
.\.venv\Scripts\python.exe -c "
import json, sys
sys.path.insert(0, '.')
from src.email_parser import parse_email_file
from src.url_analyzer import analyze_urls
from src.routing_analyzer import analyze_email_routing
from src.ai_text_analyzer import analyze_email_text
from src.risk_scorer import calculate_email_risk

# 1. Parse email
parsed = parse_email_file('samples/phishing_sample.eml')

# 2. Run analysis modules
urls = analyze_urls(parsed.get('urls', []))
routing = analyze_email_routing(parsed.get('received_headers', []))
ai = analyze_email_text(parsed.get('body', {}).get('plain_text', ''))

# 3. Calculate unified risk score
risk = calculate_email_risk(
    parsed_email=parsed,
    url_result=urls,
    routing_result=routing,
    ai_result=ai
)

print('=== EMAIL THREAT RISK ASSESSMENT ===')
print('Analysis Status     :', risk['analysis_status'])
print('Composite Risk Score:', str(risk['risk_score']) + '/100 (' + risk['risk_level'].upper() + ')')
print('Verdict Title       :', risk['verdict_title'])
print('Summary             :', risk['summary'])
print('\nPillar Scores:')
for p_name, p_data in risk['pillar_scores'].items():
    print('  -', p_name, ':', p_data['score'], '/', p_data['max_possible'], '(status: ' + p_data['status'] + ')')
print('\nTop Evidence Findings:')
for ev in risk['evidence']:
    print('  * [' + ev['severity'].upper() + '] ' + ev['title'] + ' (+' + str(ev['score_contribution']) + ' pts)')
print('\nRecommended Actions:')
for rec in risk['recommended_actions']:
    print('  >', rec)
"
```

---

---

## Module 7 — PDF Forensic Report Generation Engine (Complete)

Transforms already-computed multi-modular analysis outputs (Modules 1 through 6) into an executive-ready, print-friendly, mathematically auditable PDF forensic report using ReportLab Platypus.

### Forensic Document Architecture & Visual Palette

The generated PDF adheres to modern, professional cybersecurity design guidelines:
- **Palette**: Deep slate and navy primary tones (`#0f172a`, `#1e293b`) with high-contrast, curated risk badges (`critical` red, `high` orange, `medium` amber, `low` blue, `none` green).
- **Two-Pass Dynamic Numbered Canvas**: Employs a custom `NumberedCanvas` to calculate total pages dynamically, stamping running headers and accurate `Page X of Y` footers across documents of any length.
- **Defensive Cell Geometry**: All table cells are wrapped in constrained `Paragraph` flowables with explicit column widths to prevent page-margin clipping or layout distortion.
- **Repeatable Table Headers**: Long tables (such as URL findings and evidence ledgers) repeat column headers across page breaks for continuous readability.

### Report Sections & Forensic Elements

1. **Header & Case Identification**: Case/Reference identifier, RFC 3339 generation timestamp, engine version, and visual Composite Threat Score banner.
2. **Executive Forensic Summary**: High-level verdict, composite threat score out of 100, and primary threat drivers.
3. **Email Artifact & Message Metadata**: Subject, From, Return-Path, To, Message-ID, Date, artifact size, and a static file-integrity SHA-256 hash (with an explicit disclaimer that file hashes validate static artifact integrity, not sender identity).
4. **Four-Pillar Threat Vector Breakdown**: Budget allocation table displaying capped scores, budget caps, uncapped points, cap reductions, and signal counts for all four pillars.
5. **Sender Authentication Forensics**: Detailed SPF, DKIM, and DMARC status table. Clearly distinguishes verified, failed, not checked, unavailable, and errored states (e.g., SPF `not_checked` is never misrepresented as an authentication failure).
6. **Suspicious URL & Link Threat Heuristics**: Defanged target links (`hxxp://`), heuristic flags, severity levels, points contributions, and forensic explanations.
7. **Email Routing & Network Topology Forensics**: Relay hop table with IP scopes (public, private, loopback) and domain claims. Discloses offline mode when MaxMind GeoLite2 database is not installed, guaranteeing zero simulated or fabricated geographic coordinates.
8. **AI Semantic & Phishing Intent Classification**: Semantic verdict, model name (`aamoshdahal/email-phishing-distilbert-finetuned`), internal softmax confidence, execution status, and a mandatory scientific caveat explaining that model softmax confidence does not equal real-world Bayesian maliciousness probability.
9. **Mathematically Auditable Evidence Chain**: Complete accounting ledger showing raw points, occurrence counts, multi-occurrence dampening discounts, pillar cap adjustments, and effective score contributions, followed by the explicit mathematical reconciliation trail.
10. **Forensic Limitations & Incident Response Playbook**: Side-by-side presentation of unverified pipeline items and actionable SOC triage recommendations.
11. **Extracted Message Body Excerpt**: A safely bounded (default 600–800 chars), monospace snippet clearly labeled as untrusted email content.

### Privacy & Anti-Tampering Safeguards

- **Zero Outbound Sockets**: Report compilation is 100% offline. It makes zero HTTP requests, visits zero URLs, and runs zero scripts.
- **XML/HTML Entity Neutralization**: All email-derived text (subjects, senders, headers, body excerpts, URLs) is escaped via `html.escape` to neutralize `<script>`, `<img>`, and raw markup before ReportLab compilation.
- **Defanged Links**: URLs are rendered with defanged schemes (`hxxp://`, `hxxps://`) to prevent accidental clicks or URL execution.
- **No Legal Overclaiming**: Clear running footers disclaim certified chain-of-custody or legal admissibility guarantees.

---

### Running Module 7 Demonstration Script

To run the complete end-to-end pipeline on `samples/phishing_sample.eml` and generate the forensic PDF report:

```powershell
.\.venv\Scripts\python.exe demo_report.py
```

**Expected Output:**
```
========================================================================
SIH 2026 — AI-POWERED EMAIL THREAT DETECTION PLATFORM
MODULE 7 DEMONSTRATION: PDF FORENSIC REPORT GENERATION
========================================================================

[Step 1/7] Ingesting & Parsing Email Artifact: samples/phishing_sample.eml ...
  * Extracted Subject : URGENT: Your PayPal account has been suspended
  * Extracted Sender  : "PayPal Security Team" <security@paypa1-secure.totally-not-evil.com>
  * Extracted URLs    : 4 link(s)

[Step 2/7] Verifying Sender Authentication (SPF, DKIM, DMARC) ...
  * SPF Independent   : not_checked
  * DKIM Status       : none
  * DMARC Result      : none

[Step 3/7] Analyzing URL & Link Threat Heuristics ...
  * URLs Analyzed     : 4
  * Max Risk Score    : 55

[Step 4/7] Analyzing Email Transmission Hops & Routing ...
  * Total Hops        : 3
  * Anomalies Flagged : NO

[Step 5/7] Executing AI Phishing & Scam Intent Analysis ...
  * AI Verdict        : phishing
  * Model Confidence  : 0.9998

[Step 6/7] Synthesizing Multi-Pillar Evidence Risk Score ...
  * Final Risk Score  : 85 / 100 (HIGH)
  * Verdict Title     : High Risk — Phishing or Spoofing Detected
  * Reconciliation    : final_risk_score (85) = capped_pillar_scores_sum (75) + synergy_bonus (10) - mitigation_discount (0)

[Step 7/7] Generating PDF Forensic Intelligence Report ...

========================================================================
DEMONSTRATION REPORT GENERATED SUCCESSFULLY
========================================================================
Exact Generated PDF Path : ...\Email-Threat\reports\phishing_sample_forensic_report.pdf
PDF File Size            : ~13,377 bytes
Case Reference ID        : SIH-2026-DEMO-001
Final Risk Score         : 85 / 100 (HIGH)
Generation Timestamp     : 2026-10-20 08:16:28 UTC
========================================================================
```

---

### Python API Usage

#### Option A: End-to-End Helper
Run all modules on a raw `.eml` file and produce a forensic PDF in a single call:

```python
from src.report_generator import generate_email_forensic_report

result = generate_email_forensic_report(
    email_path="samples/phishing_sample.eml",
    output_path="reports/forensic_investigation.pdf",
    case_id="CASE-2026-ETH-001",
)

print("Generated PDF :", result["pdf_path"])
print("Risk Score    :", result["risk_score"], f"({result['risk_level']})")
```

#### Option B: Decoupled Render from Precomputed Results
Pass existing module outputs without re-running the AI model or analysis engines:

```python
from src.report_generator import generate_forensic_pdf

result = generate_forensic_pdf(
    email_data=parsed_email,
    auth_data=auth_result,
    url_data=url_result,
    routing_data=routing_result,
    ai_data=ai_result,
    risk_data=risk_report,
    output_path="reports/custom_report.pdf",
    case_id="TICKET-8841",
    include_body_excerpt=True,
    max_body_excerpt_chars=800,
)
```

---

## Module 8 — Interactive Forensic Intelligence Web Dashboard (Complete)

Provides a lightweight, offline-first local Streamlit web application (`app.py`) for investigating suspicious email files interactively.

### Key Features
1. **Artifact Ingestion**: Drag-and-drop `.eml` file upload (up to 25 MB) and quick sample buttons (`phishing_sample.eml`, `dkim_signed.eml`, `multipart.eml`, `plain_text.eml`).
2. **Safe Pre-Analysis Preview**: Sanitizes untrusted body text and neutralizes active links (`hxxps://`) without rendering HTML or JavaScript.
3. **Four-Pillar Threat Scoreboard**: Displays 0–100 risk score, risk level badge, and four pillar vectors with `Pre-Cap (Dampened)` points and budget capping reductions.
4. **Interactive Forensic Tabs**:
   - **Authentication**: Honest SPF `not_checked` context, DKIM cryptographic results, and DMARC alignment.
   - **URL Heuristics**: Defanged URL table, hostname extraction, and lexical threat indicators.
   - **Routing & Infrastructure**: Hop-by-hop transmission trace, IP classifications (Public / RFC 1918), and GeoIP status.
   - **AI NLP Intent**: DistilBERT intent verdict, model architecture telemetry, and epistemic confidence caveats.
   - **Evidence Ledger**: Scored indicator breakdown with dual-pathway mathematical audit trail.
   - **Recommendations & Limitations**: Actionable incident response playbooks and missing evidence categories.
5. **PDF Report Export**: One-click generation and instant download of verified `%PDF-` forensic investigation reports directly from the active payload.

### Launching the Dashboard

Open PowerShell in the project directory and run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

The application will launch locally at `http://localhost:8501`.

---

### Running the Full Test Suite

To run all 279 tests across all 8 platform modules:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**Test Breakdown by Module:**
- `tests/test_email_parser.py`: 61 tests (Module 1)
- `tests/test_auth_verifier.py`: 38 tests (Module 2)
- `tests/test_url_analyzer.py`: 49 tests (Module 3)
- `tests/test_routing_analyzer.py`: 37 tests (Module 4)
- `tests/test_ai_text_analyzer.py`: 26 tests (Module 5)
- `tests/test_risk_scorer.py`: 32 tests (Module 6)
- `tests/test_report_generator.py`: 19 tests (Module 7)
- `tests/test_dashboard_pipeline.py`: 12 tests (Module 8: Pipeline Orchestrator)
- `tests/test_dashboard_ui.py`: 5 tests (Module 8: UI & PDF Export Integration)
- **Total**: **279 passing tests** (Ran with 0 failures).