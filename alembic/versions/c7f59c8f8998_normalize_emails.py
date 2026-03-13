"""normalize emails

Revision ID: c7f59c8f8998
Revises: 96c715b5c6a6
Create Date: 2026-03-12 10:47:12.540625

"""
from alembic import op


revision = "c7f59c8f8998"
down_revision = '96c715b5c6a6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE users SET email = LOWER(email)")


def downgrade() -> None:
    pass
