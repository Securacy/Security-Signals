"""
Shared enums and types.
"""

from enum import Enum


class EnvironmentType(str, Enum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class EventType(str, Enum):
    """Security event classification."""

    VULNERABILITY = "vulnerability"
    BREACH = "breach"
    THREAT = "threat"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    INCIDENT = "incident"
    DISCLOSURE = "disclosure"


class SignalStatus(str, Enum):
    """Lifecycle state of a signal."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"


class UserRole(str, Enum):
    """User authorization level."""

    ADMIN = "admin"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class SecurityCategory(str, Enum):
    """Security domain taxonomy."""

    VULNERABILITY = "vulnerability"
    CLOUD_SECURITY = "cloud_security"
    IAM = "iam"
    APP_API = "app_api"
    SUPPLY_CHAIN = "supply_chain"
    DATA_PRIVACY = "data_privacy"
    RANSOMWARE = "ransomware"
    THREAT_INTEL = "threat_intel"
    AI_SECURITY = "ai_security"
    INFRASTRUCTURE = "infrastructure"
