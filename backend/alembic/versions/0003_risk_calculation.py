from alembic import op
import sqlalchemy as sa

revision = "0003_risk_calculation"
down_revision = "0002_scans_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("risk_calculation", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "risk_calculation")
