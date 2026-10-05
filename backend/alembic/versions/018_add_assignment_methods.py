"""Fix signal_category.assigned_by schema drift vs. the ORM model.

Migration 001 created assignment_method_enum with labels 'AI', 'MANUAL'.
app/db/models.py's AssignmentMethod enum has since been changed to
AI/HUMAN/HEURISTIC (values "ai"/"human"/"heuristic") without a matching
migration ever being added - the same class of drift already diagnosed
and fixed once in this repo for signal_category.subcategory (see
015_fix_subcategory_enum's docstring). It was invisible to the default
test suite because tests/conftest.py's `db` fixture builds its schema via
Base.metadata.create_all() (straight from the current Python model, which
already has HUMAN/HEURISTIC) rather than from these migrations.

It surfaced for real when SignalService.edit_signal_category (human-in-
the-loop category correction) became the first code path ever to pass a
real AssignmentMethod enum MEMBER (AssignmentMethod.HUMAN) to this column
instead of the literal string "AI" that every prior caller
(create_signal_from_ai) has always used. SQLAlchemy's native Enum type
binds a Python enum member by its NAME (e.g. "HUMAN"), not its `.value`
("human"), which is exactly why the existing 'AI'/'MANUAL' labels (whose
names already happened to equal valid labels) never exposed this: a real
Postgres database rejects "HUMAN" with
`invalid input value for enum assignment_method_enum: "HUMAN"`.

Fix: add the two missing labels so the real schema matches the names
AssignmentMethod actually sends ("AI" already exists; this adds "HUMAN"
and "HEURISTIC"). Purely additive - no existing label is renamed or
removed, so the legacy, now-unused 'MANUAL' label and every existing row
are left exactly as they are (removing an enum label safely would require
confirming no row still uses it, which this migration does not need to
do to fix the bug at hand).

Revision ID: 018_add_assignment_methods
Revises: 017_add_user_password_changed_at
"""
from alembic import op

revision = '018_add_assignment_methods'
down_revision = '017_add_user_password_changed_at'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE assignment_method_enum ADD VALUE IF NOT EXISTS 'HUMAN'")
    op.execute("ALTER TYPE assignment_method_enum ADD VALUE IF NOT EXISTS 'HEURISTIC'")


def downgrade() -> None:
    # Postgres cannot drop a single enum label without rebuilding the
    # type, which is only safe if no row uses it - not verified here.
    # Left as a no-op, matching this repo's existing approach of treating
    # additive enum-label migrations as forward-only where removal isn't
    # safely automatable.
    pass
