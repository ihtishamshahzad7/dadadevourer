from alembic import op
import sqlalchemy as sa

revision = "0003_scan_lifecycle"
down_revision = "0002_scans"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"))
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_scans_heartbeat_at", "scans", ["heartbeat_at"])


def downgrade():
    op.drop_index("ix_scans_heartbeat_at", table_name="scans")
    op.drop_column("scans", "heartbeat_at")
    op.drop_column("scans", "max_attempts")
    op.drop_column("scans", "attempts")
