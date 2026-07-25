import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.db.models import User
from passlib.hash import pbkdf2_sha256


def get_password_hash(password: str) -> str:
    return pbkdf2_sha256.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pbkdf2_sha256.verify(plain_password, hashed_password)


def seed_database(db_url: str = None):
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "sqlite:///./sentinel_dev.db")

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        existing = session.query(User).filter(User.email == "admin@sentinel.local").first()
        if not existing:
            hashed_pwd = get_password_hash("SentinelSecret123!")
            test_user = User(
                email="admin@sentinel.local",
                password_hash=hashed_pwd,
                role="admin"
            )
            session.add(test_user)
            session.commit()
            print("Successfully seeded test user: admin@sentinel.local")
        else:
            print("Test user admin@sentinel.local already exists.")
    except Exception as e:
        session.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        session.close()


if __name__ == "__main__":
    seed_database()
