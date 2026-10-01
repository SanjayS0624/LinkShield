from alembic import op
import sqlalchemy as sa

revision = "0007_redirect_analysis"
down_revision = "0006_threat_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("redirect_analysis", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "redirect_analysis")
