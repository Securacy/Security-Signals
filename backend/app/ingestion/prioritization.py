"""Deterministic event prioritization and category-coverage selection.

Security Signals is threat-modeling-first (see AI prompt in
app/intelligence/ai_service.py and the taxonomy in
app/db/models.SecurityCategoryType): the weekly pipeline must not simply
generate a signal for whatever ingestion happened to fetch most recently.
This module scores already-ingested SecurityEvents and picks which ones are
worth spending a real AI generation call on, weighting:

  1. Insecure Design / Threat Modeling relevance
  2. AI Security relevance
  3. High-impact/popular security significance
  4. Source authority (tier)
  5. Evidence breadth (corroborating sources)
  6. Recency (lowest-weighted - a very recent but trivial event should not
     automatically outrank a highly significant design/security event)

Everything here is a deterministic function of real, already-ingested data
(event title/description text, real source tier, real evidence count, real
timestamps) - never an LLM call, never fabricated data. The provisional
category bucketing in this module is a coverage-shaping heuristic only; the
signal's REAL, authoritative category always comes from Claude's validated
structured output (AISignalGenerationResponse.category), never from here.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.db.models import EventSeverity, SecurityEvent, SecurityCategoryType

# Design/threat-modeling relevance - highest selection priority per the
# product's threat-modeling-first requirement.
_DESIGN_KEYWORDS = {
    'trust boundary', 'authorization', 'authentication', 'privilege',
    'access control', 'business logic', 'fail-open', 'fail open',
    'cross-tenant', 'multi-tenant', 'isolation', 'insecure design',
    'architecture', 'trust relationship', 'segregation of duties',
    'session', 'workflow', 'default credential', 'misconfiguration',
    'permission', 'bypass', 'privilege escalation', 'object ownership',
    'idor', 'broken access control', 'insecure direct object',
}

_AI_KEYWORDS = {
    'prompt injection', 'llm', 'large language model', 'ai agent',
    'agentic', 'model poisoning', 'genai', 'generative ai', 'chatbot',
    'copilot', 'claude', 'gpt', 'machine learning model', 'rag pipeline',
    'ai model', 'ai system', 'ai-generated', 'ai infrastructure',
    'training data', 'model weights', 'jailbreak',
}

_HIGH_IMPACT_KEYWORDS = {
    'remote code execution', 'rce', 'critical', 'actively exploited',
    'zero-day', 'zero day', 'ransomware', 'supply chain', 'data breach',
    'authentication bypass', 'authorization bypass', 'wormable',
    'widely used', 'in the wild', 'cisa', 'exploited in the wild',
}

# Provisional-category keyword buckets, used ONLY to shape which events get
# an AI generation call so category coverage is reasonable - never written
# to a Signal. Checked in this order; the first match wins.
_PROVISIONAL_CATEGORY_KEYWORDS: List[Tuple[SecurityCategoryType, set]] = [
    (SecurityCategoryType.AI_SECURITY, _AI_KEYWORDS),
    (SecurityCategoryType.INSECURE_DESIGN, _DESIGN_KEYWORDS),
    (SecurityCategoryType.IAM, {
        'identity', 'single sign-on', 'sso', 'oauth', 'saml', 'mfa',
        'multi-factor', 'credential', 'password', 'token theft',
    }),
    (SecurityCategoryType.CLOUD_SECURITY, {
        'aws', 'azure', 'gcp', 'cloud storage', 's3 bucket', 'kubernetes',
        'container', 'iam role', 'cloud misconfiguration',
    }),
    (SecurityCategoryType.SUPPLY_CHAIN, {
        'supply chain', 'dependency', 'package registry', 'npm', 'pypi',
        'malicious package', 'build pipeline', 'ci/cd', 'sbom',
    }),
    (SecurityCategoryType.DATA_PRIVACY, {
        'data breach', 'pii', 'personal data', 'gdpr', 'data leak',
        'data exposure', 'privacy',
    }),
    (SecurityCategoryType.RANSOMWARE, {
        'ransomware', 'malware', 'trojan', 'botnet', 'worm',
    }),
    (SecurityCategoryType.THREAT_INTEL, {
        'threat actor', 'apt', 'campaign', 'nation-state', 'cisa advisory',
        'threat intelligence',
    }),
    (SecurityCategoryType.APP_API, {
        'api', 'rest endpoint', 'graphql', 'web application', 'xss',
        'sql injection', 'csrf', 'ssrf',
    }),
]

_SEVERITY_SCORE = {
    EventSeverity.CRITICAL: 10.0,
    EventSeverity.HIGH: 6.0,
    EventSeverity.MEDIUM: 2.0,
    EventSeverity.LOW: 0.0,
}

_TIER_SCORE = {1: 8.0, 2: 4.0, 3: 1.0}

_RECENCY_DECAY_DAYS = 10.0
_RECENCY_MAX_SCORE = 10.0


@dataclass
class EventScore:
    """A deterministic priority score for one SecurityEvent, plus the
    provisional category bucket used only for coverage-shaping."""
    event: SecurityEvent
    total: float
    provisional_category: SecurityCategoryType
    is_ai_relevant: bool
    is_design_relevant: bool
    is_high_impact: bool
    source_tier: int
    evidence_count: int


def _keyword_hits(text: str, keywords: set) -> int:
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower)


def provisional_category(event: SecurityEvent) -> SecurityCategoryType:
    """Best-effort keyword bucket for coverage-shaping only. Falls back to
    INFRASTRUCTURE when nothing matches - never AI_SECURITY or
    INSECURE_DESIGN by default, since those must be earned by an actual
    keyword match, not assumed."""
    text = f"{event.name} {event.description or ''}"
    for category, keywords in _PROVISIONAL_CATEGORY_KEYWORDS:
        if _keyword_hits(text, keywords) > 0:
            return category
    return SecurityCategoryType.INFRASTRUCTURE


def score_event(
    event: SecurityEvent,
    source_tier: int = 1,
    evidence_count: int = 1,
    now: Optional[datetime] = None,
) -> EventScore:
    """Score one event. Every input is real, already-ingested data - no
    LLM call, no fabricated severity/impact/exploitation status."""
    now = now or datetime.now(timezone.utc)
    text = f"{event.name} {event.description or ''}"

    design_hits = _keyword_hits(text, _DESIGN_KEYWORDS)
    ai_hits = _keyword_hits(text, _AI_KEYWORDS)
    impact_hits = _keyword_hits(text, _HIGH_IMPACT_KEYWORDS)

    if event.created_at:
        age_days = max((now - event.created_at).total_seconds() / 86400.0, 0.0)
    else:
        age_days = _RECENCY_DECAY_DAYS
    recency_score = max(0.0, _RECENCY_MAX_SCORE - age_days)

    severity_score = _SEVERITY_SCORE.get(event.severity, 0.0)
    tier_score = _TIER_SCORE.get(source_tier, 1.0)
    evidence_score = min(evidence_count, 3) * 2.0

    # Weights reflect the required ranking order (Change 6/18): design >
    # AI > high-impact > architectural impact (folded into design) >
    # recency > source authority > evidence > coverage (coverage itself is
    # applied afterward in select_events_for_generation, not as a score
    # term).
    total = (
        design_hits * 14.0
        + ai_hits * 12.0
        + impact_hits * 8.0
        + severity_score
        + tier_score
        + evidence_score
        + recency_score
    )

    return EventScore(
        event=event,
        total=total,
        provisional_category=provisional_category(event),
        is_ai_relevant=ai_hits > 0,
        is_design_relevant=design_hits > 0,
        is_high_impact=impact_hits > 0,
        source_tier=source_tier,
        evidence_count=evidence_count,
    )


@dataclass
class CoverageSelection:
    """Result of category-coverage-aware selection."""
    selected: List[EventScore] = field(default_factory=list)
    by_category: Dict[str, List[EventScore]] = field(default_factory=dict)
    empty_categories: List[str] = field(default_factory=list)
    ai_fraction: float = 0.0


def select_events_for_generation(
    scored_events: List[EventScore],
    min_per_category: int = 1,
    max_per_category: int = 3,
    max_total: int = 30,
    ai_target_fraction: float = 0.25,
    priority_categories: Optional[set] = None,
) -> CoverageSelection:
    """Pick which scored events get a real AI generation call this run.

    A coverage TARGET, never a fabrication quota (Change 6/16): a category
    with zero real qualifying candidates is simply left out of `selected`
    and reported in `empty_categories` - nothing is invented to fill it.
    Selection order: highest-scored candidates first, category coverage is
    then extended by picking additional strong candidates from otherwise-
    empty categories (still real, already-scored candidates - never new
    ones), and AI Security is boosted toward `ai_target_fraction` of the
    total only by reordering which real candidates get picked, never by
    inventing extra ones.

    `priority_categories` (Feature 2/4: category coverage guarantee) names
    categories that real, already-persisted current-signal state (from
    app/services/category_health_service.py) shows are currently stale or
    entirely absent from the published feed. When given, those categories
    get first claim on up to `max_per_category` real candidates in Pass 1,
    ahead of already-well-covered categories - still only ever selecting
    from real, already-scored candidates that exist this run. A priority
    category with zero real candidates is still left empty; this only
    changes ordering/allocation among what's real, never what's invented.
    """
    if not scored_events:
        return CoverageSelection(empty_categories=[c.value for c in SecurityCategoryType])

    by_category: Dict[SecurityCategoryType, List[EventScore]] = {}
    for scored in scored_events:
        by_category.setdefault(scored.provisional_category, []).append(scored)
    for bucket in by_category.values():
        bucket.sort(key=lambda s: s.total, reverse=True)

    selected: List[EventScore] = []
    selected_ids = set()

    def _take(scored: EventScore) -> None:
        if scored.event.id in selected_ids:
            return
        selected.append(scored)
        selected_ids.add(scored.event.id)

    # Pass 0: categories real coverage analysis flagged as stale/absent get
    # first claim on up to max_per_category of their strongest real
    # candidates, ahead of everything else.
    if priority_categories:
        for category in SecurityCategoryType:
            if category.value not in priority_categories:
                continue
            for scored in by_category.get(category, [])[:max_per_category]:
                if len(selected) >= max_total:
                    break
                _take(scored)

    # Pass 1: guarantee up to `min_per_category` of the strongest real
    # candidates in every category that actually has any.
    for category in SecurityCategoryType:
        for scored in by_category.get(category, [])[:min_per_category]:
            if len(selected) >= max_total:
                break
            _take(scored)

    # Pass 2: extend coverage toward `max_per_category` per category,
    # highest-scored overall first, respecting the per-category cap.
    remaining_sorted = sorted(scored_events, key=lambda s: s.total, reverse=True)
    for scored in remaining_sorted:
        if len(selected) >= max_total:
            break
        current_in_category = sum(
            1 for s in selected if s.provisional_category == scored.provisional_category
        )
        if current_in_category >= max_per_category:
            continue
        _take(scored)

    # Pass 3: nudge toward the AI-security coverage target by swapping in
    # additional real, already-scored AI candidates for the weakest
    # non-AI picks - never by adding fabricated entries. Only ever removes
    # a pick that was itself a real candidate, and only if a stronger-fit
    # real AI candidate exists to replace it with.
    target_ai_count = round(len(selected) * ai_target_fraction)
    current_ai_count = sum(1 for s in selected if s.provisional_category == SecurityCategoryType.AI_SECURITY)
    if current_ai_count < target_ai_count:
        unused_ai = [
            s for s in by_category.get(SecurityCategoryType.AI_SECURITY, [])
            if s.event.id not in selected_ids
        ]
        weakest_non_ai = sorted(
            [s for s in selected if s.provisional_category != SecurityCategoryType.AI_SECURITY],
            key=lambda s: s.total,
        )
        for ai_candidate, weak_pick in zip(unused_ai, weakest_non_ai):
            if current_ai_count >= target_ai_count:
                break
            selected.remove(weak_pick)
            selected_ids.discard(weak_pick.event.id)
            _take(ai_candidate)
            current_ai_count += 1

    final_by_category: Dict[str, List[EventScore]] = {}
    for scored in selected:
        final_by_category.setdefault(scored.provisional_category.value, []).append(scored)

    all_categories = {c.value for c in SecurityCategoryType}
    categories_with_real_material = {s.provisional_category.value for s in scored_events}
    empty_categories = sorted(
        c for c in all_categories
        if c not in final_by_category and c not in categories_with_real_material
    ) + sorted(
        c for c in categories_with_real_material
        if c not in final_by_category
    )

    ai_fraction = (
        sum(1 for s in selected if s.provisional_category == SecurityCategoryType.AI_SECURITY) / len(selected)
        if selected else 0.0
    )

    return CoverageSelection(
        selected=selected,
        by_category=final_by_category,
        empty_categories=empty_categories,
        ai_fraction=ai_fraction,
    )
