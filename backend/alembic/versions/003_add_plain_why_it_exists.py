"""Add plain_why_it_exists field to findings table

Revision ID: 003_add_plain_why_it_exists
Revises: 002_add_plain_language_fields
Create Date: 2026-07-26 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '003_add_plain_why_it_exists'
down_revision: Union[str, None] = '002_add_plain_language_fields'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('plain_why_it_exists', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'plain_why_it_exists')
