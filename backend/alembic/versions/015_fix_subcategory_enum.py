"""Fix signal_category.subcategory schema drift vs. the ORM model.

Migration 001 created signal_category.subcategory as a native Postgres
enum (ai_security_subcategory_enum) with UPPERCASE labels (e.g.
'AI_INFRASTRUCTURE'). app/db/models.py's SignalCategory.subcategory has
always been declared as a plain `Column(String(100))`, and every writer
(AISignalGenerationResponse.ai_subcategory, SearchQueryUnderstanding,
AISecuritySubcategory.value, the public API, the frontend) uses the
lowercase string convention (e.g. 'ai_infrastructure') used everywhere
else in the taxonomy. Writing any real AI-generated subcategory value
therefore fails in production with:

    invalid input value for enum ai_security_subcategory_enum: "ai_infrastructure"

This was invisible to the default test suite because tests/conftest.py's
`db` fixture builds its schema from Base.metadata.create_all() (i.e. from
the ORM model - plain VARCHAR) rather than from these migrations, unless
TEST_DB_SCHEMA_SOURCE=alembic is set. Only a run against a real,
migrated database (or the opt-in alembic-schema test mode) surfaces it.

Fix: bring the real schema in line with the model that's been the actual
contract all along - a plain VARCHAR(100), matching every other free-form
classification field. No data is lost (every existing subcategory value
was NULL - AI Security subcategory generation has never successfully
persisted a non-null value before this fix).

Revision ID: 015_fix_subcategory_enum
Revises: 014_add_signal_visual
"""
from alembic import op
import sqlalchemy as sa

revision = '015_fix_subcategory_enum'
down_revision = '014_add_signal_visual'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        'signal_category',
        'subcategory',
        existing_type=sa.Enum(name='ai_security_subcategory_enum'),
        type_=sa.String(100),
        postgresql_using='subcategory::text',
    )
    op.execute('DROP TYPE ai_security_subcategory_enum')


def downgrade():
    ai_security_subcategory_enum = sa.Enum(
        'LLM_VULNERABILITY', 'AGENT_ABUSE', 'AI_DATA_LEAKAGE', 'MODEL_POISONING',
        'AI_SUPPLY_CHAIN', 'AI_INFRASTRUCTURE', 'AI_ENABLED_ATTACKS',
        'MISALIGNED_AI_PERMISSIONS', name='ai_security_subcategory_enum',
    )
    ai_security_subcategory_enum.create(op.get_bind())
    op.execute(
        "ALTER TABLE signal_category ALTER COLUMN subcategory TYPE ai_security_subcategory_enum "
        "USING upper(subcategory)::ai_security_subcategory_enum"
    )
