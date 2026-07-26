"""Add plain-language fields and feature_area to findings table (PR 8)

Revision ID: 002_add_plain_language_fields
Revises: 001_create_core_tables
Create Date: 2026-07-26 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '002_add_plain_language_fields'
down_revision: Union[str, None] = '001_create_core_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('plain_title', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('plain_location', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('plain_whats_wrong', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('plain_real_world_impact', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('plain_risk_level', sa.String(length=120), nullable=True))
    op.add_column('findings', sa.Column('plain_what_to_do', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('feature_area', sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'feature_area')
    op.drop_column('findings', 'plain_what_to_do')
    op.drop_column('findings', 'plain_risk_level')
    op.drop_column('findings', 'plain_real_world_impact')
    op.drop_column('findings', 'plain_whats_wrong')
    op.drop_column('findings', 'plain_location')
    op.drop_column('findings', 'plain_title')
