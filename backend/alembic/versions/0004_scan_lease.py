from alembic import op
import sqlalchemy as sa

revision = "0004_scan_lease"
down_revision = "0003_scan_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("lease_id", sa.String(64), nullable=True))
    op.create_index("ix_scans_lease_id", "scans", ["lease_id"])


def downgrade():
    op.drop_index("ix_scans_lease_id", table_name="scans")
    op.drop_column("scans", "lease_id")
