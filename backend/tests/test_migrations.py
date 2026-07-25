import os
import pytest
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect
from scripts.seed import seed_database


@pytest.fixture
def temp_db_url(tmp_path):
    db_file = tmp_path / "test_migration.db"
    return f"sqlite:///{db_file}"


def test_migrations_up_down_and_seed(temp_db_url):
    backend_dir = os.path.dirname(os.path.dirname(__file__))
    alembic_cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", temp_db_url)
    alembic_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))

    # Upgrade to head
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(temp_db_url)
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    assert "users" in tables
    assert "consent_log" in tables
    assert "scans" in tables
    assert "findings" in tables

    # Run seed script
    seed_database(temp_db_url)

    # Downgrade to base
    command.downgrade(alembic_cfg, "base")

    inspector = inspect(engine)
    tables_after_downgrade = inspector.get_table_names()
    assert "users" not in tables_after_downgrade
    assert "consent_log" not in tables_after_downgrade
    assert "scans" not in tables_after_downgrade
    assert "findings" not in tables_after_downgrade
