"""Canonical internal-to-public category taxonomy mapping.

Security Signals classifies every Signal using the detailed, 10-value
internal taxonomy (app.db.models.SecurityCategoryType) - that taxonomy is
NOT changing and remains the system of record for provenance,
classification, ingestion, analytics, auditing, and AI classification.

The PUBLIC UI, however, exposes a consolidated 8-category taxonomy. This
module is the SINGLE place that mapping is defined - every component that
needs to translate between the two (API filtering, search, category
counts/badges, the API response's `public_categories` field) imports from
here rather than re-deriving the mapping independently. The frontend does
not reimplement this mapping at all: the API computes `public_categories`
per signal server-side (see app/api/routes/signals.py and
app/api/routes/search.py) and the frontend only needs a small, static
label/icon lookup for the 8 known public category slugs (presentation
only, not business logic - see frontend/src/widget/publicTaxonomy.ts,
which must stay in sync with PUBLIC_CATEGORIES/PUBLIC_CATEGORY_LABELS
below).

Internal categories with no explicit entry below are not expected (every
SecurityCategoryType value has a mapping), but internal_categories_to_public
degrades safely (skips unknown values) rather than raising, since this is a
display/filtering concern, not a validation boundary.
"""

from typing import Dict, Iterable, List

from app.db.models import SecurityCategoryType

# Ordered list of public category slugs - this order is also the canonical
# display order (category dropdown, badges, etc).
PUBLIC_CATEGORIES: List[str] = [
    "product_security",
    "cloud_identity_security",
    "supply_chain",
    "data_privacy",
    "ransomware",
    "threat_intel",
    "ai_security",
    "infrastructure",
]

PUBLIC_CATEGORY_LABELS: Dict[str, str] = {
    "product_security": "Product Security",
    "cloud_identity_security": "Cloud & Identity Security",
    "supply_chain": "Supply Chain",
    "data_privacy": "Data & Privacy",
    "ransomware": "Ransomware",
    "threat_intel": "Threat Intelligence",
    "ai_security": "AI Security",
    "infrastructure": "Infrastructure",
}

# Many-to-one: every internal category maps to exactly one public category.
INTERNAL_TO_PUBLIC: Dict[SecurityCategoryType, str] = {
    SecurityCategoryType.INSECURE_DESIGN: "product_security",
    SecurityCategoryType.APP_API: "product_security",
    SecurityCategoryType.CLOUD_SECURITY: "cloud_identity_security",
    SecurityCategoryType.IAM: "cloud_identity_security",
    SecurityCategoryType.SUPPLY_CHAIN: "supply_chain",
    SecurityCategoryType.DATA_PRIVACY: "data_privacy",
    SecurityCategoryType.RANSOMWARE: "ransomware",
    SecurityCategoryType.THREAT_INTEL: "threat_intel",
    SecurityCategoryType.AI_SECURITY: "ai_security",
    SecurityCategoryType.INFRASTRUCTURE: "infrastructure",
}

# One-to-many (the inverse of INTERNAL_TO_PUBLIC, grouped): used to
# translate a public category filter into the OR-list of internal
# categories SignalRepository.get_published()/search already accept via
# their existing `categories: List[SecurityCategoryType]` parameter - no
# repository/query-layer change was needed for this.
PUBLIC_TO_INTERNAL: Dict[str, List[SecurityCategoryType]] = {}
for _internal, _public in INTERNAL_TO_PUBLIC.items():
    PUBLIC_TO_INTERNAL.setdefault(_public, []).append(_internal)


class UnknownPublicCategoryError(ValueError):
    """Raised when a caller passes a public category slug that isn't one
    of the 8 known values - always a client input error (422), never
    silently ignored."""
    pass


def public_category_to_internal(public_category: str) -> List[SecurityCategoryType]:
    """Translate one public category slug into the internal categories it
    aggregates. Raises UnknownPublicCategoryError for anything not in
    PUBLIC_CATEGORIES - callers at the API boundary should catch this and
    return a 422, never guess or silently drop the filter."""
    if public_category not in PUBLIC_TO_INTERNAL:
        raise UnknownPublicCategoryError(
            f"Unknown public category: {public_category!r}. "
            f"Valid values: {PUBLIC_CATEGORIES}"
        )
    return PUBLIC_TO_INTERNAL[public_category]


def internal_categories_to_public(categories: Iterable[str]) -> List[str]:
    """Translate a signal's real internal categories to its distinct public
    categories, preserving first-seen order and removing duplicates - e.g.
    [cloud_security, iam] -> [cloud_identity_security] (one, not two), and
    [cloud_security, supply_chain] -> [cloud_identity_security, supply_chain]
    (two distinct ones, not collapsed). Unknown/unrecognized internal
    values are skipped rather than raising, since this runs over
    already-persisted real data for display purposes."""
    seen: List[str] = []
    for category in categories:
        # Accept either the enum or its raw string value - callers pass
        # SignalCategory.category, which SQLAlchemy may hand back as
        # either depending on the query path.
        key = category.value if hasattr(category, "value") else category
        try:
            internal_enum = SecurityCategoryType(key)
        except ValueError:
            continue
        public = INTERNAL_TO_PUBLIC.get(internal_enum)
        if public and public not in seen:
            seen.append(public)
    return seen
