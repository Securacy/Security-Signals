"""Add signal_visual table for per-signal AI-generated threat visuals.

A SignalVisual is a unique, AI-generated image for exactly one Signal
(never shared between signals or reused as a generic category image) -
see app.intelligence.visual_service.ThreatVisualService. The row starts
PENDING and is created best-effort after a signal is already published
(SignalService.publish_signal); generation failure never blocks
publication, and the frontend falls back to a static category icon
whenever no GENERATED row exists.

This is purely additive - no existing table/column is touched, and
downgrade drops only this new table and enum type.

Revision ID: 014_add_signal_visual
Revises: 013_add_signal_is_current
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ENUM, UUID

revision = '014_add_signal_visual'
down_revision = '013_add_signal_is_current'
branch_labels = None
depends_on = None


def upgrade():
    visual_status_enum = ENUM('PENDING', 'GENERATED', 'FAILED', name='visual_status_enum')
    visual_status_enum.create(op.get_bind())

    op.create_table(
        'signal_visual',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=sa.func.gen_random_uuid()),
        sa.Column('signal_id', UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column('status', ENUM('PENDING', 'GENERATED', 'FAILED', name='visual_status_enum', create_type=False),
                   nullable=False, server_default='PENDING'),
        sa.Column('url', sa.String(1000), nullable=True),
        sa.Column('prompt_version', sa.String(50), nullable=False, server_default='v1'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(['signal_id'], ['signal.id'], name='fk_signal_visual_signal_id', ondelete='CASCADE'),
    )
    op.create_index('ix_signal_visual_signal_id', 'signal_visual', ['signal_id'], unique=True)
    op.create_index('ix_signal_visual_status', 'signal_visual', ['status'])


def downgrade():
    op.drop_index('ix_signal_visual_status', table_name='signal_visual')
    op.drop_index('ix_signal_visual_signal_id', table_name='signal_visual')
    op.drop_table('signal_visual')
    op.execute('DROP TYPE visual_status_enum')
