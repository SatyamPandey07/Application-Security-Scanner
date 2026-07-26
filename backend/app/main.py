from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api import auth, consent, scans, findings
from app.db.session import SessionLocal
from app.db.models import User
from app.core.security import get_password_hash

DEMO_EMAIL = "demo@sentinel.io"
DEMO_PASSWORD = "SentinelDemo@2026"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Seed the demo user on startup so the app is immediately usable."""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == DEMO_EMAIL).first()
        if not existing:
            demo_user = User(
                email=DEMO_EMAIL,
                password_hash=get_password_hash(DEMO_PASSWORD),
                role="tester",
            )
            db.add(demo_user)
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(title="Sentinel Security Scanner", version="0.1.0", lifespan=lifespan)

app.include_router(auth.router)
app.include_router(consent.router)
app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "sentinel-api"}
