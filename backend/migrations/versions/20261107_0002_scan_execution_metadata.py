"""Persist measured discovery and check outcomes for each scan.

Revision ID: 20261107_0002
Revises: 20261107_0001
Create Date: 2026-11-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20261107_0002"
down_revision: Union[str, None] = "20261107_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Revision 0001 bootstraps fresh databases from current model metadata. Keep
    # this additive upgrade safe when that bootstrap already created the column.
    inspector = sa.inspect(op.get_bind())
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}
    if "execution_metadata" not in scan_columns:
        op.add_column("scans", sa.Column("execution_metadata", sa.JSON(), nullable=True))


def downgrade() -> None:
    # Keep scan evidence forward-only. Restore a verified backup for rollback.
    raise RuntimeError(
        "This evidence migration is forward-only. Restore a verified backup and use a reviewed data migration to roll back."
    )
