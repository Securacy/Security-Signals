"""Weekly signal-generation pipeline.

After ingestion, this selects the most important, best-covered set of real
SecurityEvents (see app/ingestion/prioritization.py) and generates real
Signals for them through the existing AI + human-review lifecycle
(app/services/signal_service.py) - it never bypasses review, never
auto-publishes, and never invents an event, article, or AI response.

If there are zero qualifying candidate events, or every real AI generation
call fails, this completes successfully with zero signals created - that is
a normal outcome (Change 11), not an error, and previously published
signals are completely untouched either way.
"""

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.db.models import Article, EventArticleMapping, SecurityEvent, Signal, Source
from app.ingestion.prioritization import EventScore, score_event, select_events_for_generation
from app.intelligence.ai_service import AISecurityError, AISignalService
from app.intelligence.schemas.signal_request import AISignalGenerationRequest
from app.services.category_health_service import compute_category_health
from app.services.signal_service import SignalService
from app.logging import get_logger

logger = get_logger(__name__)

# Safety bounds: how many un-signaled events to even consider scoring, and
# how many real AI generation calls (real cost, real Bedrock quota) one
# weekly run may make. Coverage targets in select_events_for_generation
# operate within this cap, never beyond it.
MAX_EVENTS_CONSIDERED = 80
MAX_SIGNALS_PER_RUN = 30


class WeeklySignalPipeline:
    """Selects real candidate events and generates real signals for them."""

    def __init__(self, session: Session, ai_service: Optional[AISignalService] = None):
        self.session = session
        self._ai_service = ai_service
        self.signal_service = SignalService(session)

    def _get_ai_service(self) -> AISignalService:
        """Lazily build the production Bedrock-backed service only when
        actually needed, so constructing a pipeline for scoring/selection
        alone (e.g. in tests) never requires real AWS credentials."""
        if self._ai_service is None:
            from app.config import get_settings
            self._ai_service = AISignalService.from_settings(get_settings())
        return self._ai_service

    def _candidate_events(self) -> List[SecurityEvent]:
        """Real, already-ingested events with no signal yet, most recently
        seen first, bounded by MAX_EVENTS_CONSIDERED."""
        return (
            self.session.query(SecurityEvent)
            .outerjoin(Signal, Signal.event_id == SecurityEvent.id)
            .filter(Signal.id.is_(None))
            .order_by(SecurityEvent.created_at.desc())
            .limit(MAX_EVENTS_CONSIDERED)
            .all()
        )

    def _articles_for_event(self, event: SecurityEvent) -> List[Article]:
        return (
            self.session.query(Article)
            .join(EventArticleMapping, EventArticleMapping.article_id == Article.id)
            .filter(EventArticleMapping.event_id == event.id)
            .all()
        )

    def _source_tier(self, articles: List[Article]) -> int:
        """Highest (numerically lowest) tier among an event's linked
        sources' current VERIFIED_FEEDS entry. Defaults to 1 when a
        source's tier isn't found (e.g. a source removed from
        VERIFIED_FEEDS since ingestion) - never penalizes real data for a
        lookup gap."""
        from app.ingestion.sources import VERIFIED_FEEDS

        tier_by_name = {f['name']: f.get('tier', 1) for f in VERIFIED_FEEDS}
        source_ids = {a.source_id for a in articles}
        if not source_ids:
            return 1
        sources = self.session.query(Source).filter(Source.id.in_(source_ids)).all()
        tiers = [tier_by_name.get(s.name, 1) for s in sources]
        return min(tiers) if tiers else 1

    def _score_candidates(self, events: List[SecurityEvent]) -> List[EventScore]:
        scored = []
        for event in events:
            articles = self._articles_for_event(event)
            tier = self._source_tier(articles)
            scored.append(score_event(event, source_tier=tier, evidence_count=len(articles)))
        return scored

    def _generate_signal_for(self, scored: EventScore) -> Optional[Signal]:
        """One real AI generation call over one real event's real linked
        articles. Returns None (never raises) on any failure - the caller
        logs and moves to the next candidate."""
        event = scored.event
        articles = self._articles_for_event(event)

        request = AISignalGenerationRequest(
            event_id=str(event.id),
            event_title=event.name[:500],
            event_description=(event.description or "")[:10000],
            article_titles=[a.title for a in articles],
            article_summaries=[(a.description or "")[:1000] for a in articles],
        )

        ai_response = self._get_ai_service().generate_signal(request)

        signal = self.signal_service.create_signal_from_ai(event_id=event.id, ai_response=ai_response)
        for article in articles:
            self.signal_service.add_evidence(
                signal_id=signal.id,
                source_url=article.url,
                source_title=article.title,
                excerpt=(article.description or event.description or "")[:2000],
            )
        return signal

    def _priority_categories(self) -> List[str]:
        """Categories that get first claim on this run's real, already-
        scored candidates (passed to select_events_for_generation as
        priority_categories) - never a fabrication mechanism, only an
        allocation order among candidates that actually exist this run.

        Two sources of priority, both allocation-only:
          1. Real, already-persisted coverage gaps (Feature 2): a category
             the PUBLISHED feed currently lacks, or only has stale coverage
             for, from compute_category_health() - read-only, never
             fabricates a category's state.
          2. AI Security is a standing product priority (Section 19): it
             always gets priority allocation when real AI-security
             candidates exist this run, independent of whether it happens
             to already have current coverage - "AI Security receives
             priority among real qualifying candidates," never a forced
             quota. If zero real AI-security candidates exist this run,
             this changes nothing: select_events_for_generation only ever
             allocates priority slots to candidates that are actually
             there (see its priority_categories docstring) - it does not
             and cannot invent one.
        """
        try:
            health = compute_category_health(self.session)
            gap_categories = [h.category for h in health if not h.has_current_coverage or h.is_stale]
        except Exception as e:
            # Coverage analysis is an optimization for candidate
            # prioritization, not a correctness requirement - if it can't
            # be computed this run, selection simply falls back to its
            # normal (still coverage-aware) ordering.
            logger.warning("category_health_unavailable_for_prioritization", error=str(e))
            gap_categories = []

        priority = set(gap_categories)
        priority.add('ai_security')
        return sorted(priority)

    def run(self) -> Dict[str, Any]:
        """Run one weekly selection + generation cycle. Never raises -
        every per-event failure is caught, logged, and skipped so one bad
        event can't take down the whole run."""
        candidates = self._candidate_events()
        stale_or_absent = self._priority_categories()
        result: Dict[str, Any] = {
            'candidates_considered': len(candidates),
            'selected_count': 0,
            'generated_count': 0,
            'failed_count': 0,
            'category_counts': {},
            'empty_categories': [],
            'ai_fraction': 0.0,
            'generated_signal_ids': [],
            'priority_categories': stale_or_absent,
        }

        if not candidates:
            logger.info("weekly_pipeline_no_candidate_events", priority_categories=stale_or_absent)
            return result

        scored = self._score_candidates(candidates)
        selection = select_events_for_generation(
            scored, max_total=MAX_SIGNALS_PER_RUN, priority_categories=set(stale_or_absent),
        )
        result['selected_count'] = len(selection.selected)
        result['category_counts'] = {cat: len(items) for cat, items in selection.by_category.items()}
        result['empty_categories'] = selection.empty_categories
        result['ai_fraction'] = selection.ai_fraction

        if not selection.selected:
            logger.info("weekly_pipeline_no_events_selected", candidates=len(candidates))
            return result

        for scored_event in selection.selected:
            try:
                signal = self._generate_signal_for(scored_event)
                # Commit per-generated-signal (mirrors IngestionOrchestrator's
                # per-source commit): a generated DRAFT signal must actually
                # be persisted the moment it's created, not left pending on
                # the caller's session - the scheduled job (see
                # app/scheduler/ingestion_scheduler.py) never issues its own
                # commit after this call, so without this every signal this
                # method "generates" would silently vanish when the
                # scheduler's session closes, even though generated_count
                # reports success.
                self.session.commit()
                result['generated_count'] += 1
                result['generated_signal_ids'].append(str(signal.id))
            except AISecurityError as e:
                # Real AI/validation failure for this one event - skip it,
                # never fabricate a replacement signal.
                result['failed_count'] += 1
                logger.warning(
                    "weekly_pipeline_generation_failed",
                    event_id=str(scored_event.event.id),
                    error=str(e),
                )
            except Exception as e:
                result['failed_count'] += 1
                logger.error(
                    "weekly_pipeline_unexpected_error",
                    event_id=str(scored_event.event.id),
                    error=str(e),
                    error_type=type(e).__name__,
                )

        logger.info(
            "weekly_pipeline_completed",
            candidates_considered=result['candidates_considered'],
            selected_count=result['selected_count'],
            generated_count=result['generated_count'],
            failed_count=result['failed_count'],
            ai_fraction=result['ai_fraction'],
            empty_categories=result['empty_categories'],
            priority_categories=result['priority_categories'],
        )
        return result
