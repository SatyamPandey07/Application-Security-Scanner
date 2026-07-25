import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.base import Base
from app.db.session import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_auth.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_user_registration_and_login():
    # Register user
    reg_resp = client.post("/auth/register", json={"email": "user@example.com", "password": "securepassword123"})
    assert reg_resp.status_code == 201
    assert reg_resp.json()["email"] == "user@example.com"

    # Login user
    login_resp = client.post("/auth/login", data={"username": "user@example.com", "password": "securepassword123"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    assert token is not None

    # Get current user profile
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "user@example.com"


def test_consent_logging_requires_auth():
    # Request consent log without token should fail 401
    unauth_resp = client.post("/consent", json={"target": "https://example.com", "target_type": "url"})
    assert unauth_resp.status_code == 401

    # Register and login user
    client.post("/auth/register", json={"email": "tester@example.com", "password": "password123"})
    login_resp = client.post("/auth/login", data={"username": "tester@example.com", "password": "password123"})
    token = login_resp.json()["access_token"]

    # Record consent with token
    consent_resp = client.post(
        "/consent",
        json={"target": "https://example.com", "target_type": "url"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert consent_resp.status_code == 201
    data = consent_resp.json()
    assert data["target"] == "https://example.com"
    assert data["target_type"] == "url"

    # Fetch consents
    list_resp = client.get("/consent", headers={"Authorization": f"Bearer {token}"})
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
