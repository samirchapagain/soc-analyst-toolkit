# SOC Analyst Toolkit

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/) [![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688)](https://fastapi.tiangolo.com/) [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SOC Analyst Toolkit is a production-oriented, zero-build investigation workspace for IOC enrichment, phishing analysis, detection engineering, alert triage, Sigma generation, and simulated SOAR response. `DEMO_MODE=true` works with no API keys.

## What's new in v2

- Paste-to-detect universal classifier with debounce, decoded payloads, IOC extraction, and timelines
- Extensible email and log rule catalogs with remediation guidance and MITRE mappings
- PDF incident/IOC reports plus JSON and CSV exports
- Sigma rule builder and starter templates
- Simulated playbooks with persisted run history
- JWT authentication and analyst/senior/admin roles
- SSE live alert stream, bulk IOC lookup, MITRE coverage, and alert IOC enrichment
- Search, filtering, pagination, tests, and GitHub Actions CI

## Features

The app includes Dashboard, IOC Lookup, Phishing Email, Log Analyzer, Alerts, Sigma Builder, Playbooks, and MITRE tabs. It uses FastAPI, SQLAlchemy 2.x, SQLite, TailwindCSS CDN, Chart.js CDN, and vanilla JavaScript with no npm or bundler.

The MITRE ATT&CK engine is fully offline. It ships 14 tactics, 100+ technique records, threat profiles, generated detection rules, kill-chain classification, heatmaps, and Sigma export. API keys are only needed for optional external IOC enrichment.

## Offline MITRE ATT&CK detection

Use the **Profiles** tab to load ransomware, phishing, APT, insider, crypto-miner, webshell, brute-force, credential-dump, lateral-movement, data-exfiltration, web-attack, C2, or LOLBin rulesets. The **Auto Rules** tab exposes generated rules and Sigma export. The MITRE tab shows technique coverage and links to ATT&CK.

## Live demo

Live demo: _coming soon_

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. API docs are at `/docs`.

## Docker

```powershell
Copy-Item .env.example .env
docker compose up --build
```

## Enable real APIs

Edit `.env`, add `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY`, then set `DEMO_MODE=false`. Provider failures are isolated; demo mode remains available without keys.

## API Keys & Free Tiers

| Provider | Free tier | Signup URL | What it unlocks |
|---|---|---|---|
| VirusTotal | 4 requests/minute | https://www.virustotal.com/gui/join-us | File, domain, URL, and IP reputation |
| AbuseIPDB | 1,000 requests/day | https://www.abuseipdb.com/register | IP abuse confidence and reports |
| AlienVault OTX | Generous community quota | https://otx.alienvault.com/ | Pulses and threat context |
| URLScan.io | 100 scans/day | https://urlscan.io/user/signup/ | URL page and verdict analysis |
| Shodan | Limited free quota | https://account.shodan.io/register | IP ports and exposed services |
| GreyNoise | 50 community requests/day | https://www.greynoise.io/ | Internet background-noise classification |
| IPinfo | 50,000 requests/month | https://ipinfo.io/signup | GeoIP, ASN, and ISP context |
| Have I Been Pwned | Paid API | https://haveibeenpwned.com/API/Key | Breach history for email indicators |
| Google Safe Browsing | 10,000 requests/day | https://console.cloud.google.com/ | Malware and phishing URL matches |
| IPQualityScore | Free tier available | https://www.ipqualityscore.com/create-account | Proxy, VPN, TOR, and fraud signals |
| MalwareBazaar | No key | https://bazaar.abuse.ch/ | Hash malware metadata |
| URLhaus | No key | https://urlhaus.abuse.ch/ | Malicious URL status and tags |

### How to enable live mode

Set `DEMO_MODE=false` in `.env`, add any provider keys, and restart Uvicorn. Mixed mode is supported: configured providers use live APIs while missing providers are shown as unavailable.

### Fallback behaviour

Every provider has a 10-second timeout, an in-memory quota guard, and isolated error handling. Successful results are cached in SQLite for 24 hours. Missing keys, provider errors, and exhausted local quotas never fail the overall IOC lookup; the response marks the provider as `unavailable`, `error`, or `rate_limited`. Provider calls are recorded for the Providers dashboard.

## How detection works

Paste any of these into the Dashboard universal box:

```text
From: Security <security@paypa1.example>
Subject: Urgent verify your account
Click here: http://evil.example/login
```

```text
4625 failed login for user admin from 10.0.0.8
```

```text
8.8.8.8
example.com
d41d8cd98f00b204e9800998ecf8427e
```

```text
cG93ZXJzaGVsbCAtZW5jIFo=
```

```json
{"event":"powershell -enc ZQB2AGkAbA=="}
```

The classifier identifies content types, runs matching analyzers, decodes safe base64/PowerShell payloads, extracts IOCs, and returns findings plus a timeline. Empty input is explicitly cleared and no-finding input returns a visible “No threat indicators found” state.

## Architecture

```text
Browser (single HTML + Tailwind/Chart.js)
        │ fetch + JWT + EventSource
FastAPI routers ── services (detect, IOC, email, logs, Sigma, playbooks)
        │                     │
 SQLAlchemy / SQLite      integrations.py (safe simulated actions)
        │
 Alerts, users, playbook runs, enriched alert IOCs
```

## MITRE ATT&CK coverage

| Rule | Technique | Severity |
|---|---|---|
| Brute Force | T1110 | High |
| Encoded PowerShell | T1059.001 | High |
| SQL Injection | T1190 | High |
| Port Scan | T1046 | Medium |
| Suspicious User Agent | T1595 | Medium |
| LSASS Access | T1003.001 | Critical |
| PsExec | T1021.002 | High |
| C2 Beacon | T1071 | Critical |
| New Service Install | T1543 | High |
| Scheduled Task | T1053.005 | High |
| Registry Run Keys | T1547.001 | High |
| Process Injection | T1055 | Critical |
| Credential Dumping | T1003 | Critical |
| Defense Evasion | T1562 | High |
| DNS C2 | T1071.004 | High |
| Web Shell | T1505.003 | Critical |
| Data Exfiltration | T1041 | High |
| Impossible Travel | T1078 | High |

## Tests and CI

```powershell
pip install -r requirements-dev.txt
pytest
```

GitHub Actions runs the test suite on every push and pull request.

## Project structure

```text
soc-analyst-toolkit/
├── app/
│   ├── main.py, database.py, models.py, schemas.py, integrations.py
│   ├── routers/       # API boundaries
│   ├── services/      # detection and business logic
│   └── static/index.html
├── tests/test_api.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
└── docker-compose.yml
```

## Screenshots

Place screenshots in `screenshots/`.

- `screenshots/provider-cards.png` — IOC provider cards
- `screenshots/providers-tab.png` — provider configuration and quota status

## Roadmap

v3: MISP integration, TheHive integration, real SOAR connectors, multi-tenant workspaces, PDF evidence bundles, and richer authentication policy controls.

## License

Released under the [MIT License](LICENSE).
