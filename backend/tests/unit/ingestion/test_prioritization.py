"""Unit tests for deterministic event scoring and category-coverage
selection (Changes 4/6/9/18). No database - SecurityEvent objects are
constructed in-memory with real field values, never persisted."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.db.models import EventSeverity, EventType, SecurityCategoryType, SecurityEvent
from app.ingestion.prioritization import (
    provisional_category, score_event, select_events_for_generation, EventScore,
)


def _event(name: str, description: str = "", severity=EventSeverity.MEDIUM, age_days: float = 0) -> SecurityEvent:
    return SecurityEvent(
        id=uuid4(),
        name=name,
        description=description,
        event_type=EventType.VULNERABILITY,
        severity=severity,
        created_at=datetime.now(timezone.utc) - timedelta(days=age_days),
    )


class TestProvisionalCategory:
    def test_ai_keywords_map_to_ai_security(self):
        event = _event("New prompt injection technique against LLM agents")
        assert provisional_category(event) == SecurityCategoryType.AI_SECURITY

    def test_design_keywords_map_to_insecure_design(self):
        event = _event("Authorization bypass due to missing access control on trust boundary")
        assert provisional_category(event) == SecurityCategoryType.INSECURE_DESIGN

    def test_ai_takes_priority_over_design_when_both_present(self):
        """AI Security is checked before Insecure Design (Change 9: AI is a
        major product priority) when an event's text matches both."""
        event = _event("AI agent privilege escalation via missing access control")
        assert provisional_category(event) == SecurityCategoryType.AI_SECURITY

    def test_no_keyword_match_falls_back_to_infrastructure(self):
        event = _event("Quarterly newsletter roundup of project announcements")
        assert provisional_category(event) == SecurityCategoryType.INFRASTRUCTURE

    def test_ransomware_keywords(self):
        event = _event("New ransomware strain observed encrypting shared drives")
        assert provisional_category(event) == SecurityCategoryType.RANSOMWARE


class TestScoreEvent:
    def test_design_relevant_event_scores_higher_than_generic(self):
        design_event = _event("Insecure design: broken trust boundary allows cross-tenant access")
        generic_event = _event("Minor documentation update")

        design_score = score_event(design_event, source_tier=1, evidence_count=1)
        generic_score = score_event(generic_event, source_tier=1, evidence_count=1)

        assert design_score.total > generic_score.total
        assert design_score.is_design_relevant is True
        assert generic_score.is_design_relevant is False

    def test_ai_relevant_flag_set_correctly(self):
        ai_event = _event("Claude agent tool abuse allows privilege escalation")
        scored = score_event(ai_event, source_tier=1, evidence_count=1)
        assert scored.is_ai_relevant is True

    def test_higher_tier_source_scores_higher_all_else_equal(self):
        event_a = _event("Some security event")
        event_b = _event("Some security event")  # same text, different tier

        tier1 = score_event(event_a, source_tier=1, evidence_count=1)
        tier3 = score_event(event_b, source_tier=3, evidence_count=1)

        assert tier1.total > tier3.total

    def test_more_evidence_scores_higher_all_else_equal(self):
        event_a = _event("Some security event")
        event_b = _event("Some security event")

        few = score_event(event_a, source_tier=1, evidence_count=1)
        many = score_event(event_b, source_tier=1, evidence_count=5)

        assert many.total > few.total

    def test_more_recent_scores_higher_all_else_equal(self):
        recent = _event("Some security event", age_days=0)
        old = _event("Some security event", age_days=30)

        recent_score = score_event(recent, source_tier=1, evidence_count=1)
        old_score = score_event(old, source_tier=1, evidence_count=1)

        assert recent_score.total > old_score.total

    def test_never_fabricates_severity_uses_real_field(self):
        """Severity contribution is read from the real, already-stored
        SecurityEvent.severity - never invented at scoring time."""
        critical = _event("Some event", severity=EventSeverity.CRITICAL)
        low = _event("Some event", severity=EventSeverity.LOW)

        critical_score = score_event(critical, source_tier=1, evidence_count=1)
        low_score = score_event(low, source_tier=1, evidence_count=1)

        assert critical_score.total > low_score.total


class TestSelectEventsForGeneration:
    def test_empty_input_selects_nothing(self):
        selection = select_events_for_generation([])
        assert selection.selected == []

    def test_never_selects_more_than_available_real_candidates(self):
        """A category with only 1 real qualifying event gets 1, never a
        fabricated 2nd or 3rd (Change 6/16)."""
        scored = [score_event(_event("Insecure design flaw in auth architecture"), 1, 1)]

        selection = select_events_for_generation(scored, min_per_category=1, max_per_category=3)

        assert len(selection.selected) == 1

    def test_respects_max_per_category(self):
        scored = [
            score_event(_event(f"Insecure design flaw #{i} in auth architecture"), 1, 1)
            for i in range(10)
        ]

        selection = select_events_for_generation(scored, min_per_category=1, max_per_category=3, max_total=30)

        design_count = sum(
            1 for s in selection.selected if s.provisional_category == SecurityCategoryType.INSECURE_DESIGN
        )
        assert design_count <= 3

    def test_respects_max_total(self):
        scored = [
            score_event(_event(f"Insecure design flaw #{i} in auth architecture"), 1, 1)
            for i in range(50)
        ]

        selection = select_events_for_generation(scored, max_total=5)

        assert len(selection.selected) <= 5

    def test_empty_categories_reported_not_fabricated(self):
        """Only categories with zero real candidates appear as empty -
        never filled with invented data."""
        scored = [score_event(_event("Insecure design flaw in auth architecture"), 1, 1)]

        selection = select_events_for_generation(scored)

        assert "ransomware" in selection.empty_categories
        assert "insecure_design" not in selection.empty_categories

    def test_ai_fraction_never_exceeds_real_ai_candidate_count(self):
        """Boosting toward the ~25% AI target only reorders real
        candidates - it must never select more AI events than actually
        exist."""
        scored = [score_event(_event("Prompt injection against an AI agent"), 1, 1)]  # only 1 real AI candidate
        scored += [
            score_event(_event(f"Insecure design flaw #{i} in auth architecture"), 1, 1)
            for i in range(10)
        ]

        selection = select_events_for_generation(scored, ai_target_fraction=0.5)

        ai_count = sum(1 for s in selection.selected if s.provisional_category == SecurityCategoryType.AI_SECURITY)
        assert ai_count == 1  # can't exceed the single real AI candidate

    def test_no_duplicate_events_in_selection(self):
        event = _event("Insecure design flaw in auth architecture")
        scored = [score_event(event, 1, 1)]

        selection = select_events_for_generation(scored)

        ids = [s.event.id for s in selection.selected]
        assert len(ids) == len(set(ids))


class TestPriorityCategories:
    """Feature 2/4: real category coverage state (stale/absent categories
    from compute_category_health) gets first claim on selection slots -
    but only among real, already-scored candidates that exist this run."""

    def test_priority_category_candidate_selected_over_higher_scored_non_priority(self):
        # A weak ransomware candidate (few keyword hits, low score) vs a
        # strong design candidate (many keyword hits, high score). Without
        # priority_categories, capacity would favor the stronger candidate
        # first; with ransomware flagged as coverage-priority, it must
        # still be selected within max_per_category regardless of order.
        weak_ransomware = score_event(_event("New ransomware strain observed"), 1, 1)
        strong_design = score_event(
            _event("Critical authorization bypass: broken trust boundary, missing access control, privilege escalation"),
            1, 1,
        )
        scored = [strong_design, weak_ransomware]

        selection = select_events_for_generation(
            scored, min_per_category=1, max_total=30, priority_categories={"ransomware"},
        )

        selected_categories = {s.provisional_category.value for s in selection.selected}
        assert "ransomware" in selected_categories
        assert "insecure_design" in selected_categories  # still selected too, just not favored in ordering

    def test_priority_category_with_zero_real_candidates_stays_empty(self):
        """Flagging a category as coverage-priority never fabricates a
        candidate for it - a real candidate must actually exist."""
        scored = [score_event(_event("Insecure design flaw in auth architecture"), 1, 1)]

        selection = select_events_for_generation(scored, priority_categories={"ransomware"})

        assert "ransomware" in selection.empty_categories
        assert not any(s.provisional_category.value == "ransomware" for s in selection.selected)

    def test_no_priority_categories_behaves_identically_to_default(self):
        """Backward compatibility: omitting priority_categories (None or
        empty set) must not change selection versus the pre-existing
        behavior."""
        scored = [
            score_event(_event(f"Insecure design flaw #{i} in auth architecture"), 1, 1)
            for i in range(5)
        ]

        without = select_events_for_generation(scored, max_total=30)
        with_empty = select_events_for_generation(scored, max_total=30, priority_categories=set())

        assert {s.event.id for s in without.selected} == {s.event.id for s in with_empty.selected}

    def test_priority_category_selection_respects_max_per_category_cap(self):
        scored = [
            score_event(_event(f"New ransomware strain variant #{i}"), 1, 1)
            for i in range(10)
        ]

        selection = select_events_for_generation(
            scored, max_per_category=3, max_total=30, priority_categories={"ransomware"},
        )

        ransomware_count = sum(1 for s in selection.selected if s.provisional_category.value == "ransomware")
        assert ransomware_count <= 3
