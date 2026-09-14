"""Unit tests for the pure helper functions in analytics_service.py - no
database needed."""

from datetime import datetime, timezone, timedelta

import pytest

from app.services.analytics_service import (
    _month_key, _month_range, _subtract_months, _dominant_theme,
    _split_principles,
)


class TestSubtractMonths:
    def test_same_year(self):
        assert _subtract_months(2026, 9, 3) == (2026, 6)

    def test_crosses_year_boundary(self):
        assert _subtract_months(2026, 2, 3) == (2025, 11)

    def test_subtract_zero(self):
        assert _subtract_months(2026, 9, 0) == (2026, 9)

    def test_subtract_full_year(self):
        assert _subtract_months(2026, 9, 12) == (2025, 9)

    def test_subtract_january_by_one(self):
        assert _subtract_months(2026, 1, 1) == (2025, 12)


class TestMonthKey:
    def test_requires_timezone_aware_datetime(self):
        naive = datetime(2026, 5, 1)
        with pytest.raises(ValueError):
            _month_key(naive)

    def test_utc_datetime_bucketed_correctly(self):
        dt = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
        assert _month_key(dt) == "2026-05"

    def test_non_utc_datetime_converted_to_utc_before_bucketing(self):
        """A timestamp just after local midnight in a negative-offset zone
        can still be the previous UTC day/month - bucketing must convert to
        UTC first, not use the naive year/month of the original tzinfo."""
        # 2026-06-01 00:30 in UTC-5 is 2026-06-01 05:30 UTC - same month,
        # but the reverse direction (a positive offset near midnight UTC)
        # is the case that would actually flip the month if conversion were
        # skipped:
        dt = datetime(2026, 5, 31, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
        # 23:30 on May 31 at UTC-5 is 04:30 UTC on June 1.
        assert _month_key(dt) == "2026-06"


class TestMonthRange:
    def test_returns_requested_number_of_months(self):
        now = datetime(2026, 9, 14, tzinfo=timezone.utc)
        keys = _month_range(3, now=now)
        assert keys == ["2026-07", "2026-08", "2026-09"]

    def test_includes_current_month_last(self):
        now = datetime(2026, 1, 10, tzinfo=timezone.utc)
        keys = _month_range(2, now=now)
        assert keys[-1] == "2026-01"

    def test_single_month_window(self):
        now = datetime(2026, 9, 14, tzinfo=timezone.utc)
        assert _month_range(1, now=now) == ["2026-09"]

    def test_window_crossing_year_boundary(self):
        now = datetime(2026, 1, 14, tzinfo=timezone.utc)
        keys = _month_range(3, now=now)
        assert keys == ["2025-11", "2025-12", "2026-01"]


class TestDominantTheme:
    def test_empty_counts_returns_none(self):
        assert _dominant_theme({}) is None

    def test_single_category(self):
        assert _dominant_theme({"vulnerability": 5}) == {"category": "vulnerability", "count": 5}

    def test_highest_count_wins(self):
        counts = {"vulnerability": 3, "iam": 10, "ransomware": 1}
        assert _dominant_theme(counts) == {"category": "iam", "count": 10}

    def test_tie_broken_alphabetically(self):
        counts = {"vulnerability": 5, "iam": 5}
        assert _dominant_theme(counts) == {"category": "iam", "count": 5}


class TestSplitPrinciples:
    def test_empty_string_returns_empty_list(self):
        assert _split_principles("") == []

    def test_single_principle(self):
        assert _split_principles("Least Privilege") == ["Least Privilege"]

    def test_multiple_principles_split_on_separator(self):
        assert _split_principles("Least Privilege; Defense in Depth") == [
            "Least Privilege", "Defense in Depth",
        ]

    def test_placeholder_text_counted_as_a_single_principle(self):
        """The pre-fix placeholder ("AI-Generated Security Principle") and
        any signal with no real AI principles still counts as one entry -
        analytics doesn't need to special-case it, just split faithfully."""
        assert _split_principles("AI-Generated Security Principle") == [
            "AI-Generated Security Principle"
        ]
