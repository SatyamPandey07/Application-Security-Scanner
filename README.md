# Sentinel — AI-Native Application Security Platform

Sentinel is an application security scanning platform designed to ingest targets, run security checks, validate findings, and propose fix patches.

## Repository Structure

- `/backend`: Python FastAPI application and test suite.
- `/frontend`: Vite + React + Tailwind CSS web interface shell.
- `docker-compose.yml`: Multi-container development orchestration (API, Frontend, PostgreSQL, Redis).
- `.github/workflows/ci.yml`: Continuous Integration pipeline running backend tests and frontend production build.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/)
- [Python 3.11+](https://www.python.org/) (optional for direct backend development)
- [Node.js 20+](https://nodejs.org/) (optional for direct frontend development)

## Quick Start (Docker Compose)

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/sentinel.git
   cd sentinel
   ```

2. Spin up the application services:
   ```bash
   docker-compose up --build
   ```

3. Verify running services:
   - **Frontend App Shell**: [http://localhost:3000](http://localhost:3000)
   - **Backend API Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

## Local Development (Native)

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Running Tests

- Run backend pytest suite:
  ```bash
  cd backend && pytest
  ```
- Build frontend production bundle:
  ```bash
  cd frontend && npm run build
  ```
