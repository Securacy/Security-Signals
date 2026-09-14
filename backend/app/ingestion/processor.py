"""Relevance classification and event grouping."""

import logging
import re
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.models import SecurityEvent, EventType, EventSeverity

logger = logging.getLogger(__name__)


class RelevanceClassifier:
    """Classify articles as security-relevant."""
    
    KEYWORDS = {
        'cve', 'vulnerability', 'breach', 'patch', 'security',
        'exploit', 'rce', 'attack', 'threat', 'malware',
        'ransomware', 'zero-day', 'authentication', 'authorization',
        'ssl', 'tls', 'encryption', 'data leak', 'privacy'
    }
    
    @staticmethod
    def is_relevant(title: str, summary: str = '') -> bool:
        """Determine if security-relevant."""
        text = f"{title} {summary}".lower()
        return any(kw in text for kw in RelevanceClassifier.KEYWORDS)


class EventGrouper:
    """Group articles into events."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def find_or_create_event(self, title: str, description: str) -> SecurityEvent:
        """Find existing or create new event.

        security_event.name has a DB-level unique constraint (migration
        001), so any title that already exists as an event - whether from
        this run or a previous one - must be looked up and reused rather
        than re-inserted. The CVE check above only catches title variants
        that share a CVE ID; a plain exact-name match is needed too, since
        that's the actual uniqueness rule the DB enforces.
        """
        # Rule 1: CVE
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', title.upper())
        if cve_match:
            cve = cve_match.group(0)
            existing = (
                self.session.query(SecurityEvent)
                .filter(SecurityEvent.name.ilike(f"%{cve}%"))
                .one_or_none()
            )
            if existing:
                return existing

        # Rule 2: exact name match (the column the unique constraint is on)
        existing = self.session.query(SecurityEvent).filter_by(name=title).one_or_none()
        if existing:
            return existing

        # Create new
        event = SecurityEvent(
            name=title,
            description=description,
            event_type=EventType.VULNERABILITY,
            severity=EventSeverity.MEDIUM,
        )

        self.session.add(event)
        try:
            self.session.flush()
            return event
        except IntegrityError:
            # Lost a race against another insert of the same name (e.g. a
            # concurrent run) - roll back so the session's transaction
            # isn't left aborted, then reuse the row that won.
            self.session.rollback()
            existing = self.session.query(SecurityEvent).filter_by(name=title).one_or_none()
            if existing:
                return existing
            raise
