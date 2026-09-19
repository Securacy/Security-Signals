"""Unit tests for the centralized freshness policy
(app/ingestion/freshness_policy.py)."""

from datetime import datetime, timedelta, timezone

from app.ingestion.freshness_policy import (
    FreshnessPolicy, compute_freshness_cutoff, is_stale_entry,
)

_POLICY = FreshnessPolicy(grace_period=timedelta(hours=6), max_current_signals_per_category=3)


class TestComputeFreshnessCutoff:
    def test_no_checkpoint_returns_none(self):
        """A source's first-ever run has nothing to compare against."""
        assert compute_freshness_cutoff(None, _POLICY) is None

    def test_checkpoint_minus_grace(self):
        checkpoint = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
        cutoff = compute_freshness_cutoff(checkpoint, _POLICY)
        assert cutoff == datetime(2026, 1, 10, 6, 0, tzinfo=timezone.utc)

    def test_larger_grace_period_pushes_cutoff_further_back(self):
        checkpoint = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
        wide_policy = FreshnessPolicy(grace_period=timedelta(hours=24), max_current_signals_per_category=3)
        cutoff = compute_freshness_cutoff(checkpoint, wide_policy)
        assert cutoff == datetime(2026, 1, 9, 12, 0, tzinfo=timezone.utc)


class TestIsStaleEntry:
    def test_no_cutoff_never_stale(self):
        published = datetime(2020, 1, 1, tzinfo=timezone.utc)
        assert is_stale_entry(published, None) is False

    def test_missing_published_timestamp_never_stale(self):
        """Missing/unparseable timestamps (already normalized to None by
        the adapters) are conservatively treated as not-stale - dedup, not
        freshness filtering, is what stops repeat processing."""
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert is_stale_entry(None, cutoff) is False

    def test_entry_older_than_cutoff_is_stale(self):
        cutoff = datetime(2026, 1, 10, tzinfo=timezone.utc)
        published = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert is_stale_entry(published, cutoff) is True

    def test_entry_newer_than_cutoff_is_not_stale(self):
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        published = datetime(2026, 1, 10, tzinfo=timezone.utc)
        assert is_stale_entry(published, cutoff) is False

    def test_entry_exactly_at_cutoff_is_not_stale(self):
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert is_stale_entry(cutoff, cutoff) is False


class TestFreshnessPolicyFromSettings:
    def test_builds_from_settings_fields(self):
        class FakeSettings:
            freshness_grace_hours = 12
            max_current_signals_per_category = 5

        policy = FreshnessPolicy.from_settings(FakeSettings())
        assert policy.grace_period == timedelta(hours=12)
        assert policy.max_current_signals_per_category == 5
