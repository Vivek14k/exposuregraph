"""Add account sessions, domain proof and scan ownership.

Revision ID: 20261107_0001
Revises:
Create Date: 2026-11-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from backend.database.models import Base

revision: str = "20261107_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # create_all is used only as an idempotent bootstrap here: legacy tables are
    # left intact, while missing tables are created from the current model metadata.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)

    inspector = sa.inspect(bind)
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}
    if "user_id" not in scan_columns:
        if bind.dialect.name == "sqlite":
            # SQLite cannot ALTER TABLE to add a foreign-key constraint. Alembic's
            # batch mode copies the existing rows into a replacement table and
            # preserves every legacy scan with a NULL owner.
            with op.batch_alter_table("scans", recreate="always") as batch_op:
                batch_op.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
                batch_op.create_foreign_key(
                    "fk_scans_user_id_users", "users", ["user_id"], ["id"], ondelete="RESTRICT",
                )
                batch_op.create_index("ix_scans_user_id", ["user_id"], unique=False)
        else:
            op.add_column("scans", sa.Column("user_id", sa.Integer(), nullable=True))
            op.create_foreign_key(
                "fk_scans_user_id_users", "scans", "users", ["user_id"], ["id"], ondelete="RESTRICT",
            )
            op.create_index("ix_scans_user_id", "scans", ["user_id"])

    existing_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("scans")}
    for name, columns in (
        ("ix_scans_status_id", ["status", "id"]),
        ("ix_scans_owner_status", ["user_id", "status"]),
    ):
        if name not in existing_indexes:
            op.create_index(name, "scans", columns)


def downgrade() -> None:
    raise RuntimeError(
        "This security migration is forward-only. Restore a verified backup and use a reviewed data migration to roll back."
    )
