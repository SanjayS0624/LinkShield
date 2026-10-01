from alembic import op
import sqlalchemy as sa

revision = "0008_ai_explanation"
down_revision = "0007_redirect_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("ai_explanation", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "ai_explanation")
