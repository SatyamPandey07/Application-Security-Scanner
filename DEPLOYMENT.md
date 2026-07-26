# Sentinel Platform — Production Deployment & Hardening Guide

This document covers production deployment options, environment variables reference, sandbox security isolation, and self-hosting security checklists for **Sentinel**.

---

## 🚀 Quick Start (Production Docker Compose)

To launch Sentinel in production using container resource isolation:

```bash
# 1. Clone repository
git clone https://github.com/SatyamPandey07/Application-Security-Scanner.git
cd Application-Security-Scanner

# 2. Set Environment Variables
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY and SECRET_KEY

# 3. Launch Services
docker-compose -f docker-compose.prod.yml up -d
```

---

## 🔒 Self-Hosting Security Checklist

Before deploying Sentinel in a production environment:

1. [ ] **Explicit Consent Enforcement**: Ensure `POST /scans` retains the mandatory `"authorized": true` gate to log target owner consent in PostgreSQL `consent_log`.
2. [ ] **JWT Secret Key**: Change `SECRET_KEY` from default to a strong 64-character random secret.
3. [ ] **Sandboxed Worker Isolation**: Ensure Celery worker containers run with restricted network privileges to prevent scanned repositories from accessing internal cloud metadata endpoints (`169.254.169.254`).
4. [ ] **Rate Limiting**: Verify sliding-window rate limit is active (`10 requests / min / user`) on `/scans`.
5. [ ] **ZAP API Network Isolation**: Ensure OWASP ZAP container port `8080` is exposed **only** to the internal `api` and `worker` docker network, not publicly to the internet.
6. [ ] **DB Database Backups**: Configure daily automated volume snapshots for the `postgres_data` volume.

---

## ⚙️ Environment Variables Reference

| Variable | Description | Default | Required in Production |
| :--- | :--- | :--- | :---: |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://sentinel:sentinel@postgres:5432/sentinel` | **Yes** |
| `REDIS_URL` | Redis task queue broker URL | `redis://redis:6379/0` | **Yes** |
| `ZAP_API_URL` | OWASP ZAP REST API daemon URL | `http://zap:8080` | **Yes** |
| `SECRET_KEY` | JWT signing secret key | `super-secret-jwt-key` | **Yes** |
| `AI_VALIDATION_ENABLED` | Toggle AI false-positive remediation layer | `True` | No |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude remediation | `""` | Optional |

---

## 🛡️ Sandbox Worker Hardening Details

- **Clone Sandboxing**: Repository targets are cloned into isolated temporary directories (`tempfile.mkdtemp(prefix="sentinel_sast_")`).
- **Clean Teardown**: Temporary directories are unconditionally unlinked and destroyed in `finally` blocks post-scan.
- **Input Sanitization**: Traversal patterns (`..`), shell metacharacters (`;`, `|`, `` ` ``), and malicious target arguments are rejected before execution.
