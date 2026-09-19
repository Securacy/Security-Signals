"""Unit tests for _compute_coverage_status (Section 14) - a pure function
over already-computed real fields, so every state transition can be tested
deterministically without a database."""

from datetime import datetime, timedelta, timezone

from app.services.category_health_service import (
    CoverageStatus, SourceHealth, _compute_coverage_status,
)

_NOW = datetime.now(timezone.utc)


def _source(enabled=True):
    return SourceHealth(
        name="Test Source", tier=1, enabled=enabled, consecutive_failures=0,
        last_success=None, last_failure=None,
    )


class TestSourceFailure:
    def test_no_sources_at_all_is_source_failure(self):
        status = _compute_coverage_status(
            source_health=[], has_current_coverage=False, is_stale=False,
            last_current_signal_at=None, last_new_article_at=None,
        )
        assert status == CoverageStatus.SOURCE_FAILURE

    def test_all_sources_disabled_is_source_failure(self):
        status = _compute_coverage_status(
            source_health=[_source(enabled=False), _source(enabled=False)],
            has_current_coverage=True, is_stale=False,
            last_current_signal_at=_NOW, last_new_article_at=None,
        )
        assert status == CoverageStatus.SOURCE_FAILURE

    def test_source_failure_takes_priority_even_with_current_coverage(self):
        """Even real, existing coverage doesn't hide an operational
        problem with the category's own dedicated sources."""
        status = _compute_coverage_status(
            source_health=[_source(enabled=False)],
            has_current_coverage=True, is_stale=False,
            last_current_signal_at=_NOW, last_new_article_at=_NOW,
        )
        assert status == CoverageStatus.SOURCE_FAILURE

    def test_at_least_one_enabled_source_is_not_source_failure(self):
        status = _compute_coverage_status(
            source_health=[_source(enabled=False), _source(enabled=True)],
            has_current_coverage=False, is_stale=False,
            last_current_signal_at=None, last_new_article_at=None,
        )
        assert status != CoverageStatus.SOURCE_FAILURE


class TestStale:
    def test_covered_and_stale_is_stale(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=True, is_stale=True,
            last_current_signal_at=_NOW - timedelta(days=60), last_new_article_at=None,
        )
        assert status == CoverageStatus.STALE


class TestNewContent:
    def test_article_newer_than_current_signal_is_new_content(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=True, is_stale=False,
            last_current_signal_at=_NOW - timedelta(days=5),
            last_new_article_at=_NOW - timedelta(hours=1),
        )
        assert status == CoverageStatus.NEW_CONTENT

    def test_new_article_with_no_coverage_at_all_is_new_content(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=False, is_stale=False,
            last_current_signal_at=None, last_new_article_at=_NOW,
        )
        assert status == CoverageStatus.NEW_CONTENT

    def test_article_older_than_current_signal_is_not_new_content(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=True, is_stale=False,
            last_current_signal_at=_NOW,
            last_new_article_at=_NOW - timedelta(days=10),
        )
        assert status != CoverageStatus.NEW_CONTENT


class TestUnchangedAndNoQualifyingEvent:
    def test_covered_not_stale_no_newer_article_is_unchanged(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=True, is_stale=False,
            last_current_signal_at=_NOW, last_new_article_at=_NOW - timedelta(days=1),
        )
        assert status == CoverageStatus.UNCHANGED

    def test_not_covered_and_no_article_is_no_qualifying_event(self):
        status = _compute_coverage_status(
            source_health=[_source()], has_current_coverage=False, is_stale=False,
            last_current_signal_at=None, last_new_article_at=None,
        )
        assert status == CoverageStatus.NO_QUALIFYING_EVENT

    def test_never_fabricates_coverage_when_none_exists(self):
        """No combination of real inputs should ever produce
        has_current_coverage-implying output when there genuinely is none -
        confirmed by construction (has_current_coverage is a passed-in real
        fact, this function only ever reads it, never invents it)."""
        for is_stale in (True, False):
            for last_article in (None, _NOW):
                status = _compute_coverage_status(
                    source_health=[_source()], has_current_coverage=False, is_stale=is_stale,
                    last_current_signal_at=None, last_new_article_at=last_article,
                )
                assert status in (
                    CoverageStatus.SOURCE_FAILURE,
                    CoverageStatus.NEW_CONTENT,
                    CoverageStatus.NO_QUALIFYING_EVENT,
                )
