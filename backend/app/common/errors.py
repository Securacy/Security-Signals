"""
Custom exceptions for application domain.
"""


class SecuritySignalsException(Exception):
    """Base exception for Security Signals."""

    pass


class ConfigurationError(SecuritySignalsException):
    """Configuration is invalid or missing."""

    pass


class DatabaseError(SecuritySignalsException):
    """Database operation failed."""

    pass

class UniqueConstraintError(DatabaseError):
    """Database unique constraint was violated."""

    pass


class ValidationError(SecuritySignalsException):
    """Validation of data failed."""

    pass


class NotFoundError(SecuritySignalsException):
    """Resource not found."""

    pass


class AuthenticationError(SecuritySignalsException):
    """Authentication failed."""

    pass


class AuthorizationError(SecuritySignalsException):
    """User not authorized for action."""

    pass


class ExternalServiceError(SecuritySignalsException):
    """External service (RSS, API) failed."""

    pass


class AIProcessingError(SecuritySignalsException):
    """AI pipeline (Claude API) failed."""

    pass
