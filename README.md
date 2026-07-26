# Sentinel — AI-Native Application Security Platform

**Sentinel** is a state-of-the-art, AI-native application security scanning platform designed to eliminate false positives through multi-engine security scanning, AI-powered remediation diffs, CVSS v3.1 prioritization, and automated GitHub Pull Request fixes.

---

## 🌟 Key Features

1. **Multi-Engine Correlated Security Scanning**:
   - **SAST**: Static Application Security Testing via Semgrep.
   - **DAST**: Dynamic Application Security Testing via containerized OWASP ZAP (spider + passive scanning).
   - **IDOR / BOLA Detection**: Authenticated cross-account access control verification using explicit test credentials.
   - **Dependency Vulnerabilities**: Manifest auditing via `pip-audit` / `npm audit` against CVE databases.
   - **Secret Leak Detection**: Scanning for leaked API keys, tokens, and private keys via `detect-secrets` and high-entropy pattern matching.

2. **AI Post-Processing & Remediation Layer**:
   - Anthropic Claude integration reviewing findings against surrounding code context (~20 lines).
   - Generates plain-English security explanations, step-by-step exploit scenarios, and unified git diff patch fixes.
   - Re-labels low-confidence alerts (`confirmed` vs `low_confidence`) without deleting findings.

3. **CVSS v3.1 & Weighted Priority Scoring**:
   - Computes pure CVSS v3.1 base scores verified against official FIRST.org spec test vectors.
   - Calculates weighted priority scores (`CVSS Base Score * AI Confidence`).

4. **Automated GitHub Pull Request Remediation**:
   - One-click GitHub PR creation applying AI-suggested patch diffs to new branches.
   - Graceful content-drift handling preventing force-pushes or merge conflicts.

5. **Compliance Mapping & CSV Export**:
   - Maps security findings to **SOC 2**, **PCI DSS v4.0**, and **OWASP ASVS v4.0** controls.
   - Downloadable CSV compliance reports for audit readiness.

6. **Historical Security Trend Analytics**:
   - Tracks vulnerability counts, confirmed findings, and average CVSS ratings over time for repeat target scans.

7. **Explicit Target Authorization & Consent Gate**:
   - Mandatory authorization confirmation field requirement on scan submissions.
   - All authorization events are logged to the PostgreSQL `consent_log` database table with user timestamps.

---

## 🏗️ Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Celery, Redis.
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons.
- **Scanning Engines**: Semgrep CLI, OWASP ZAP, `pip-audit`, `detect-secrets`.
- **AI & Integrations**: Anthropic Claude API, GitHub REST API.

---

## 🚀 Local Development Setup

### 1. Prerequisites
- Docker & Docker Compose
- Python 3.12+
- Node.js 18+

### 2. Run with Docker Compose
```bash
docker-compose up --build
```
Access the services at:
- **Frontend App**: `http://localhost:3000`
- **FastAPI REST API**: `http://localhost:8000/docs`
- **OWASP ZAP Daemon**: `http://localhost:8080`

### 3. Local Development (Backend & Frontend)
```bash
# Backend Setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
python scripts/seed.py
pytest

# Frontend Setup
cd ../frontend
npm install
npm run dev
```

---

## 🧪 Testing Suite

Sentinel maintains 100% backend test suite pass rate across 26 unit test modules covering migrations, JWT auth, consent gates, SAST, DAST, IDOR, dependency audit, secret detection, AI validation, CVSS math formula, GitHub PR engine, compliance mapping, rate limiting, and target validation:

```bash
cd backend
pytest
```

---

## 📖 Deployment & Hardening Guide

Refer to [DEPLOYMENT.md](file:///Users/satyampandey/Application-Security-Scanner/DEPLOYMENT.md) for production Docker Compose setup, environment variable reference, worker sandbox hardening, and self-hosting security checklists.

---

## 📜 License

MIT License &copy; 2026 Sentinel Platform.
