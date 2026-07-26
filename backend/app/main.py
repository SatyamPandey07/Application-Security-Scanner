from fastapi import FastAPI
from app.api import auth, consent, scans, findings

app = FastAPI(title="Sentinel Security Scanner", version="0.1.0")

app.include_router(auth.router)
app.include_router(consent.router)
app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "sentinel-api"}
