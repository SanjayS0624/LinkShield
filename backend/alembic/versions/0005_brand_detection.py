from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from uuid import uuid4

revision = "0005_brand_detection"
down_revision = "0004_domain_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "brands",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("official_domains", sa.JSON(), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("keywords", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", name="uq_brands_name"),
    )
    op.add_column("scans", sa.Column("brand_analysis", sa.JSON(), nullable=True))

    brands = sa.table(
        "brands",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("name", sa.String()),
        sa.column("official_domains", sa.JSON()),
        sa.column("aliases", sa.JSON()),
        sa.column("keywords", sa.JSON()),
    )
    names = [
        ("Google", ["google.com"], ["goog"], ["google"]),
        ("Microsoft", ["microsoft.com", "live.com", "office.com"], ["ms", "microsoft"], ["microsoft", "office365"]),
        ("Apple", ["apple.com", "icloud.com"], ["apple"], ["apple", "icloud"]),
        ("Amazon", ["amazon.com", "amazon.in"], ["amazon"], ["amazon", "prime"]),
        ("PayPal", ["paypal.com"], ["paypal"], ["paypal"]),
        ("Instagram", ["instagram.com"], ["insta", "instagram"], ["instagram"]),
        ("Facebook", ["facebook.com", "fb.com"], ["facebook", "fb"], ["facebook"]),
        ("Netflix", ["netflix.com"], ["netflix"], ["netflix"]),
        ("GitHub", ["github.com"], ["github"], ["github"]),
        ("LinkedIn", ["linkedin.com"], ["linkedin"], ["linkedin"]),
    ]
    op.bulk_insert(brands, [
        {"id": uuid4(), "name": name, "official_domains": domains,
         "aliases": aliases, "keywords": keywords}
        for name, domains, aliases, keywords in names
    ])


def downgrade() -> None:
    op.drop_column("scans", "brand_analysis")
    op.drop_table("brands")
