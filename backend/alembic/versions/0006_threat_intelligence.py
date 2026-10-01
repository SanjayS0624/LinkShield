from alembic import op
import sqlalchemy as sa

revision = "0006_threat_intelligence"
down_revision = "0005_brand_detection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("threat_intelligence", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "threat_intelligence")
