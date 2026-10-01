from alembic import op
import sqlalchemy as sa

revision = "0004_domain_intelligence"
down_revision = "0003_risk_calculation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("domain_intelligence", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "domain_intelligence")
