# ============================================================================
# SECURITY SIGNALS - Phase 1 Project Builder
# Windows PowerShell Script
# Creates complete project structure and all 51 Phase 1 files
# ============================================================================

param(
    [string]$ProjectRoot = (Get-Location),
    [switch]$Force = $false,
    [switch]$Verbose = $false
)

# ============================================================================
# SAFETY CHECKS
# ============================================================================

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error-Message {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Yellow
}

Write-Header "Security Signals - Phase 1 Builder"

# Check project root
$projectName = Split-Path -Leaf $ProjectRoot
if ($projectName -ne "security-signals" -and -not $Force) {
    Write-Error-Message "Project root must be named 'security-signals' or use -Force flag"
    Write-Host "Current path: $ProjectRoot" -ForegroundColor Yellow
    exit 1
}

Write-Success "Project root: $ProjectRoot"

# ============================================================================
# CREATE DIRECTORY STRUCTURE
# ============================================================================

Write-Header "Creating Directory Structure"

$directories = @(
    # Backend
    "backend/app/db",
    "backend/app/api/routes",
    "backend/app/ingestion",
    "backend/app/processing",
    "backend/app/intelligence",
    "backend/app/review",
    "backend/app/scheduler",
    "backend/app/analytics",
    "backend/app/common",
    "backend/tests/unit",
    "backend/tests/integration",
    "backend/tests/security",
    "backend/alembic/versions",

    # Frontend
    "frontend/src",
    "frontend/tests",
    "frontend/public"
)

foreach ($dir in $directories) {
    $fullPath = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Success "Created: $dir"
    } else {
        Write-Info "Exists: $dir"
    }
}

# ============================================================================
# CREATE BACKEND FILES
# ============================================================================

Write-Header "Creating Backend Files"

# backend/requirements.txt
$file = @"
fastapi==0.104.1
uvicorn==0.24.0
python-dotenv==1.0.0
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.9
pytest==7.4.3
pytest-asyncio==0.21.1
httpx==0.25.1
pydantic==2.5.0
pydantic-settings==2.1.0
anthropic==0.7.1
apscheduler==3.10.4
python-jose==3.3.0
passlib==1.7.4
slowapi==0.1.9
structlog==23.2.0
"@
$path = Join-Path $ProjectRoot "backend/requirements.txt"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/requirements.txt"

# backend/app/__init__.py
$file = @"
"""
Security Signals backend application.
Modular monolith architecture with clear trust boundaries.
"""

__version__ = "0.1.0"
"@
$path = Join-Path $ProjectRoot "backend/app/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/__init__.py"

# backend/app/config.py
$file = @"
"""
Configuration management.
Reads from environment, validates, provides app-wide config.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
import os


class Settings(BaseSettings):
    """Application settings from environment."""

    # App
    app_name: str = "Security Signals"
    app_version: str = "0.1.0"
    environment: str = Field(default="development", pattern="^(development|staging|production)`$")
    debug: bool = Field(default=False)

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # Database
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/security_signals"
    )
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # API Keys
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    jwt_secret_key: str = Field(default="dev-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24

    # Ingestion
    ingestion_timeout_seconds: int = 30
    ingestion_max_retries: int = 3
    ingestion_max_response_size_mb: int = 10

    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)`$")

    class Config:
        env_file = ".env"
        case_sensitive = False


def get_settings() -> Settings:
    """Get application settings (cached singleton in practice)."""
    return Settings()


# Validate on import
_settings = get_settings()
"@
$path = Join-Path $ProjectRoot "backend/app/config.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/config.py"

# backend/app/logging.py
$file = @"
"""
Structured logging setup using structlog.
JSON output to stdout (Docker-friendly).
"""

import structlog
import logging
import sys
from app.config import get_settings


def setup_logging():
    """Configure structlog for production-oriented logging."""
    settings = get_settings()

    # Structlog configuration
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecimalEncoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level),
    )


def get_logger(name: str):
    """Get a structured logger by name."""
    return structlog.get_logger(name)
"@
$path = Join-Path $ProjectRoot "backend/app/logging.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/logging.py"

# backend/app/db/__init__.py
$file = @"
"""Database module."""
"@
$path = Join-Path $ProjectRoot "backend/app/db/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/db/__init__.py"

# backend/app/db/connection.py
$file = @"
"""
Database connection and session management.
SQLAlchemy with PostgreSQL.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config import get_settings
from app.logging import get_logger

logger = get_logger(__name__)

settings = get_settings()

# Create engine
engine = create_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=(settings.environment == "development"),
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Dependency for FastAPI routes: inject DB session."""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error("database_error", error=str(e))
        db.rollback()
        raise
    finally:
        db.close()


async def verify_database_connection():
    """Test database connectivity on startup."""
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        logger.info("database_connected")
        return True
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))
        return False
"@
$path = Join-Path $ProjectRoot "backend/app/db/connection.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/db/connection.py"

# backend/app/db/models.py
$file = @"
"""
ORM models using SQLAlchemy.
Phase 1: Empty base. Phase 2: Add Article, Source, Event, Signal, etc.
"""

from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Models will be defined here in Phase 2
"@
$path = Join-Path $ProjectRoot "backend/app/db/models.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/db/models.py"

# backend/app/common/__init__.py
$file = @"
"""Common utilities."""
"@
$path = Join-Path $ProjectRoot "backend/app/common/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/common/__init__.py"

# backend/app/common/errors.py
$file = @"
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
"@
$path = Join-Path $ProjectRoot "backend/app/common/errors.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/common/errors.py"

# backend/app/common/types.py
$file = @"
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
"@
$path = Join-Path $ProjectRoot "backend/app/common/types.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/common/types.py"

# backend/app/common/utils.py
$file = @"
"""
Utility functions.
"""

import hashlib
from typing import Any


def compute_content_hash(content: str) -> str:
    """
    Compute SHA256 hash of content for deduplication.
    Deterministic.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def safe_get_dict(data: dict, key: str, default: Any = None) -> Any:
    """Safely get from dict with default."""
    return data.get(key, default)
"@
$path = Join-Path $ProjectRoot "backend/app/common/utils.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/common/utils.py"

# backend/app/api/__init__.py
$file = @"
"""API module."""
"@
$path = Join-Path $ProjectRoot "backend/app/api/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/api/__init__.py"

# backend/app/api/errors.py
$file = @"
"""
FastAPI error handlers and response models.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.common.errors import (
    SecuritySignalsException,
    NotFoundError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
)
from app.logging import get_logger

logger = get_logger(__name__)


async def security_signals_exception_handler(request: Request, exc: SecuritySignalsException):
    """Handle custom application exceptions."""
    logger.error(
        "application_error",
        error_type=type(exc).__name__,
        message=str(exc),
        path=str(request.url),
    )

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Internal server error"

    if isinstance(exc, NotFoundError):
        status_code = status.HTTP_404_NOT_FOUND
        detail = str(exc)
    elif isinstance(exc, ValidationError):
        status_code = status.HTTP_400_BAD_REQUEST
        detail = str(exc)
    elif isinstance(exc, AuthenticationError):
        status_code = status.HTTP_401_UNAUTHORIZED
        detail = str(exc)
    elif isinstance(exc, AuthorizationError):
        status_code = status.HTTP_403_FORBIDDEN
        detail = str(exc)

    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "error_type": type(exc).__name__},
    )


async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(
        "unexpected_error",
        error_type=type(exc).__name__,
        message=str(exc),
        path=str(request.url),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "error_type": "UnexpectedException"},
    )
"@
$path = Join-Path $ProjectRoot "backend/app/api/errors.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/api/errors.py"

# backend/app/api/middleware.py
$file = @"
"""
FastAPI middleware for logging, CORS, rate limiting, etc.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.logging import get_logger

logger = get_logger(__name__)

settings = get_settings()


def setup_middleware(app: FastAPI):
    """Configure all middleware."""

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # TODO: Rate limiting (Phase 6)
    # TODO: Request logging middleware (Phase 6)
"@
$path = Join-Path $ProjectRoot "backend/app/api/middleware.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/api/middleware.py"

# backend/app/api/routes/__init__.py
$file = @"
"""API routes."""
"@
$path = Join-Path $ProjectRoot "backend/app/api/routes/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/api/routes/__init__.py"

# backend/app/api/routes/health.py
$file = @"
"""
Health check endpoint for monitoring and readiness probes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.connection import get_db, verify_database_connection
from app.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=dict)
async def health_check():
    """Basic health check."""
    return {
        "status": "healthy",
        "version": "0.1.0",
    }


@router.get("/ready", response_model=dict)
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness check: includes database connectivity.
    Used by orchestrators (K8s, Docker, etc.) to decide if service is ready.
    """
    db_ok = await verify_database_connection()

    if not db_ok:
        return {
            "status": "not_ready",
            "reason": "database_unreachable",
        }, 503

    return {
        "status": "ready",
    }
"@
$path = Join-Path $ProjectRoot "backend/app/api/routes/health.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/api/routes/health.py"

# backend/app/main.py
$file = @"
"""
FastAPI application factory.
Entry point for uvicorn.
"""

from fastapi import FastAPI
from app.config import get_settings
from app.logging import setup_logging, get_logger
from app.db.connection import verify_database_connection
from app.api.errors import security_signals_exception_handler, general_exception_handler
from app.api.middleware import setup_middleware
from app.api.routes import health
from app.common.errors import SecuritySignalsException

# Setup logging before anything else
setup_logging()
logger = get_logger(__name__)

settings = get_settings()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
    )

    # Setup middleware
    setup_middleware(app)

    # Exception handlers
    app.add_exception_handler(SecuritySignalsException, security_signals_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)

    # Routes
    app.include_router(health.router)

    # TODO: Add more routers in Phase 6 (ingestion, processing, intelligence, review, etc.)

    # Startup events
    @app.on_event("startup")
    async def startup():
        logger.info("app_startup", app_name=settings.app_name, environment=settings.environment)
        db_ok = await verify_database_connection()
        if not db_ok:
            logger.warning("app_startup_incomplete", reason="database_not_available")
        else:
            logger.info("app_startup_complete")

    @app.on_event("shutdown")
    async def shutdown():
        logger.info("app_shutdown")

    return app


app = create_app()
"@
$path = Join-Path $ProjectRoot "backend/app/main.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/app/main.py"

# backend/tests/__init__.py
$file = @"
"""Tests."""
"@
$path = Join-Path $ProjectRoot "backend/tests/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/__init__.py"

# backend/tests/conftest.py
$file = @"
"""
Pytest fixtures for backend tests.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient
from app.main import create_app
from app.db.connection import get_db
from app.db.models import Base


# Use in-memory SQLite for testing
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture
def test_db_engine():
    """Create test database engine."""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_db_session(test_db_engine):
    """Create test database session."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def test_client(test_db_session):
    """Create test FastAPI client."""

    def override_get_db():
        yield test_db_session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()
"@
$path = Join-Path $ProjectRoot "backend/tests/conftest.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/conftest.py"

# backend/tests/unit/__init__.py
$file = @"
"""Unit tests."""
"@
$path = Join-Path $ProjectRoot "backend/tests/unit/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/unit/__init__.py"

# backend/tests/unit/test_config.py
$file = @"
"""
Test configuration loading and validation.
"""

import pytest
from app.config import Settings


def test_settings_defaults():
    """Test default configuration."""
    settings = Settings()
    assert settings.app_name == "Security Signals"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.backend_port == 8000


def test_settings_environment_validation():
    """Test that invalid environment is rejected."""
    with pytest.raises(ValueError):
        Settings(environment="invalid")


def test_settings_log_level_validation():
    """Test log level validation."""
    settings = Settings(log_level="DEBUG")
    assert settings.log_level == "DEBUG"

    with pytest.raises(ValueError):
        Settings(log_level="INVALID_LEVEL")


def test_settings_jwt_config():
    """Test JWT configuration."""
    settings = Settings()
    assert settings.jwt_algorithm == "HS256"
    assert settings.jwt_expiration_hours == 24
    assert len(settings.jwt_secret_key) > 0
"@
$path = Join-Path $ProjectRoot "backend/tests/unit/test_config.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/unit/test_config.py"

# backend/tests/unit/test_common_utils.py
$file = @"
"""
Test common utility functions.
"""

from app.common.utils import compute_content_hash, safe_get_dict


def test_compute_content_hash():
    """Test content hash is deterministic."""
    content = "Example security article content"
    hash1 = compute_content_hash(content)
    hash2 = compute_content_hash(content)

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex is 64 chars


def test_compute_content_hash_different():
    """Test different content produces different hashes."""
    hash1 = compute_content_hash("content1")
    hash2 = compute_content_hash("content2")
    assert hash1 != hash2


def test_safe_get_dict():
    """Test safe dict access."""
    data = {"key": "value"}
    assert safe_get_dict(data, "key") == "value"
    assert safe_get_dict(data, "missing") is None
    assert safe_get_dict(data, "missing", "default") == "default"
"@
$path = Join-Path $ProjectRoot "backend/tests/unit/test_common_utils.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/unit/test_common_utils.py"

# backend/tests/integration/__init__.py
$file = @"
"""Integration tests."""
"@
$path = Join-Path $ProjectRoot "backend/tests/integration/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/integration/__init__.py"

# backend/tests/integration/test_api_health.py
$file = @"
"""
Integration tests for health check endpoints.
"""

import pytest


def test_health_check(test_client):
    """Test basic health endpoint."""
    response = test_client.get("/health/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_readiness_check(test_client):
    """Test readiness endpoint."""
    response = test_client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
"@
$path = Join-Path $ProjectRoot "backend/tests/integration/test_api_health.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/integration/test_api_health.py"

# backend/tests/security/__init__.py
$file = @"
"""Security-specific tests (SSRF, SQLi, XSS, injection, etc.)."""
"@
$path = Join-Path $ProjectRoot "backend/tests/security/__init__.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/security/__init__.py"

# backend/tests/security/test_error_handling.py
$file = @"
"""
Test error handling and response formats.
"""

import pytest


def test_404_not_found(test_client):
    """Test 404 on non-existent endpoint."""
    response = test_client.get("/nonexistent")
    assert response.status_code == 404


def test_health_endpoint_exists(test_client):
    """Verify health endpoint is accessible."""
    response = test_client.get("/health/")
    assert response.status_code == 200
"@
$path = Join-Path $ProjectRoot "backend/tests/security/test_error_handling.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/tests/security/test_error_handling.py"

# backend/.env.example
$file = @"
# Environment
ENVIRONMENT=development
DEBUG=true

# Server
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:5173

# Database (Docker Compose will provide postgres:5432)
DATABASE_URL=postgresql://securitysignals:securitysignals@postgres:5432/security_signals

# API Keys
ANTHROPIC_API_KEY=your-key-here

# JWT
JWT_SECRET_KEY=dev-secret-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Ingestion
INGESTION_TIMEOUT_SECONDS=30
INGESTION_MAX_RETRIES=3
INGESTION_MAX_RESPONSE_SIZE_MB=10

# Logging
LOG_LEVEL=INFO
"@
$path = Join-Path $ProjectRoot "backend/.env.example"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/.env.example"

# backend/pytest.ini
$file = @"
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
log_cli = true
log_cli_level = INFO
"@
$path = Join-Path $ProjectRoot "backend/pytest.ini"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/pytest.ini"

# backend/Dockerfile
$file = @"
# Multi-stage build for backend

FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends `
    gcc `
    postgresql-client `
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends `
    postgresql-client `
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app /app/app
COPY alembic /app/alembic
COPY alembic.ini /app/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 `
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health/', timeout=5).raise_for_status()"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
"@
$path = Join-Path $ProjectRoot "backend/Dockerfile"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/Dockerfile"

# backend/alembic.ini
$file = @"
[alembic]
sqlalchemy.url = driver://user:password@localhost/dbname
sqlalchemy.echo = false

[loggers]
keys = sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"@
$path = Join-Path $ProjectRoot "backend/alembic.ini"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/alembic.ini"

# backend/alembic/env.py
$file = @"
"""
Alembic environment configuration.
Handles database migrations.
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import os
from app.db.models import Base
from app.config import get_settings

config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Get target metadata from models
target_metadata = Base.metadata

# Get database URL from settings
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
"@
$path = Join-Path $ProjectRoot "backend/alembic/env.py"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/alembic/env.py"

# backend/alembic/script.py.mako
$file = @'
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
'@
$path = Join-Path $ProjectRoot "backend/alembic/script.py.mako"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/alembic/script.py.mako"

# backend/alembic/versions/.gitkeep
$file = @"
# Placeholder for migration files
"@
$path = Join-Path $ProjectRoot "backend/alembic/versions/.gitkeep"
Set-Content -Path $path -Value $file
Write-Success "Created: backend/alembic/versions/.gitkeep"

# ============================================================================
# CREATE FRONTEND FILES
# ============================================================================

Write-Header "Creating Frontend Files"

# frontend/package.json
$file = @"
{
  "name": "security-signals-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:ui": "vitest --ui",
    "lint": "eslint src --ext ts,tsx"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.2"
  },
  "devDependencies": {
    "@types/react": "^18.2.37",
    "@types/react-dom": "^18.2.15",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.2.2",
    "vite": "^5.0.0",
    "vitest": "^1.0.0",
    "eslint": "^8.52.0",
    "@typescript-eslint/eslint-plugin": "^6.10.0",
    "@typescript-eslint/parser": "^6.10.0"
  }
}
"@
$path = Join-Path $ProjectRoot "frontend/package.json"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/package.json"

# frontend/tsconfig.json
$file = @"
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,

    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",

    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
"@
$path = Join-Path $ProjectRoot "frontend/tsconfig.json"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/tsconfig.json"

# frontend/tsconfig.node.json
$file = @"
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
"@
$path = Join-Path $ProjectRoot "frontend/tsconfig.node.json"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/tsconfig.node.json"

# frontend/vite.config.ts
$file = @"
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
"@
$path = Join-Path $ProjectRoot "frontend/vite.config.ts"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/vite.config.ts"

# frontend/vitest.config.ts
$file = @"
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: [],
  },
});
"@
$path = Join-Path $ProjectRoot "frontend/vitest.config.ts"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/vitest.config.ts"

# frontend/.env.example
$file = @"
VITE_API_BASE_URL=http://localhost:8000
"@
$path = Join-Path $ProjectRoot "frontend/.env.example"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/.env.example"

# frontend/Dockerfile
$file = @"
# Multi-stage build for frontend

FROM node:20-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Serve with nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
"@
$path = Join-Path $ProjectRoot "frontend/Dockerfile"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/Dockerfile"

# frontend/nginx.conf
$file = @"
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;

    index index.html;

    # Proxy API requests to backend
    location /api/ {
        proxy_pass http://backend:8000/;
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
    }

    # SPA routing: fallback to index.html
    location / {
        try_files `$uri `$uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)`$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
"@
$path = Join-Path $ProjectRoot "frontend/nginx.conf"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/nginx.conf"

# frontend/src/main.tsx
$file = @"
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
"@
$path = Join-Path $ProjectRoot "frontend/src/main.tsx"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/src/main.tsx"

# frontend/src/App.tsx
$file = @"
import { useState, useEffect } from "react";
import "./App.css";

function App() {
  const [backendStatus, setBackendStatus] = useState("checking...");

  useEffect(() => {
    // Check backend health
    fetch("/api/health/")
      .then((res) => res.json())
      .then((data) => {
        setBackendStatus(`Backend v`+data.version+` healthy`);
      })
      .catch(() => {
        setBackendStatus("Backend unreachable");
      });
  }, []);

  return (
    <div className="app">
      <header>
        <h1>🔒 Security Signals</h1>
        <p>Cybersecurity Intelligence Product</p>
      </header>
      <main>
        <div className="status-card">
          <p>Status: <strong>{backendStatus}</strong></p>
        </div>
        <section>
          <h2>Phase 1: Foundation Complete</h2>
          <p>
            This is a greenfield project. The foundation is ready.
            Next phase: Database models and domain entities.
          </p>
        </section>
      </main>
    </div>
  );
}

export default App;
"@
$path = Join-Path $ProjectRoot "frontend/src/App.tsx"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/src/App.tsx"

# frontend/src/index.css
$file = @"
:root {
  font-family: Inter, system-ui, Avenir, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  font-weight: 400;

  color: rgba(255, 255, 255, 0.87);
  background-color: #242424;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  display: flex;
  place-items: center;
  min-width: 320px;
  min-height: 100vh;
}

#root {
  width: 100%;
}

.app {
  text-align: center;
  padding: 2rem;
}

header {
  margin-bottom: 2rem;
}

header h1 {
  font-size: 2.5rem;
  margin: 0 0 0.5rem 0;
}

main {
  max-width: 600px;
  margin: 0 auto;
}

.status-card {
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 2rem;
}

section {
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  padding: 1.5rem;
}

section h2 {
  margin-top: 0;
}
"@
$path = Join-Path $ProjectRoot "frontend/src/index.css"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/src/index.css"

# frontend/src/App.css
$file = @"
/* Minimal styling for Phase 1 */
"@
$path = Join-Path $ProjectRoot "frontend/src/App.css"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/src/App.css"

# frontend/src/vite-env.d.ts
$file = @"
/// <reference types="vite/client" />
"@
$path = Join-Path $ProjectRoot "frontend/src/vite-env.d.ts"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/src/vite-env.d.ts"

# frontend/index.html
$file = @"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Signals</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
"@
$path = Join-Path $ProjectRoot "frontend/index.html"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/index.html"

# frontend/tests/__init__.ts
$file = @"
// Test directory marker
"@
$path = Join-Path $ProjectRoot "frontend/tests/__init__.ts"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/tests/__init__.ts"

# frontend/.eslintrc.json
$file = @"
{
  "env": {
    "browser": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module",
    "ecmaFeatures": {
      "jsx": true
    }
  },
  "plugins": ["@typescript-eslint"],
  "rules": {
    "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }]
  }
}
"@
$path = Join-Path $ProjectRoot "frontend/.eslintrc.json"
Set-Content -Path $path -Value $file
Write-Success "Created: frontend/.eslintrc.json"

# ============================================================================
# CREATE ROOT PROJECT FILES
# ============================================================================

Write-Header "Creating Root Project Files"

# docker-compose.yml
$file = @"
version: "3.9"

services:
  postgres:
    image: postgres:15-alpine
    container_name: security_signals_postgres
    environment:
      POSTGRES_USER: securitysignals
      POSTGRES_PASSWORD: securitysignals
      POSTGRES_DB: security_signals
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U securitysignals"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: security_signals_backend
    environment:
      ENVIRONMENT: development
      DEBUG: "true"
      DATABASE_URL: postgresql://securitysignals:securitysignals@postgres:5432/security_signals
      BACKEND_HOST: 0.0.0.0
      BACKEND_PORT: 8000
      FRONTEND_URL: http://localhost:5173
      LOG_LEVEL: INFO
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./backend:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: security_signals_frontend
    ports:
      - "5173:5173"
    volumes:
      - ./frontend/src:/app/src
      - ./frontend/public:/app/public
    command: npm run dev

volumes:
  postgres_data:
"@
$path = Join-Path $ProjectRoot "docker-compose.yml"
Set-Content -Path $path -Value $file
Write-Success "Created: docker-compose.yml"

# .env.example (root)
$file = @"
# Root .env (copy to .env for local development)

# Backend
ENVIRONMENT=development
DEBUG=true
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:5173

# Database (shared via Docker Compose)
DATABASE_URL=postgresql://securitysignals:securitysignals@postgres:5432/security_signals

# API Keys
ANTHROPIC_API_KEY=

# JWT (change in production)
JWT_SECRET_KEY=dev-secret-change-in-production

# Logging
LOG_LEVEL=INFO
"@
$path = Join-Path $ProjectRoot ".env.example"
Set-Content -Path $path -Value $file
Write-Success "Created: .env.example"

# .gitignore
$file = @"
# Environment
.env
.env.local

# Python
__pycache__/
*.py[cod]
*`$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Node
node_modules/
npm-debug.log
yarn-error.log
dist/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Pytest
.pytest_cache/
.coverage
htmlcov/

# Alembic
alembic/versions/__pycache__/
"@
$path = Join-Path $ProjectRoot ".gitignore"
Set-Content -Path $path -Value $file
Write-Success "Created: .gitignore"

# README.md
$file = @"
# Security Signals

A production-oriented cybersecurity intelligence platform that ingests real security news, validates it, groups events, generates AI-powered insights, and publishes approved signals through a public API.

## Phase 1: Foundation ✅

This is a **greenfield project**. Phase 1 includes:

- ✅ FastAPI backend skeleton with config, logging, DB connection
- ✅ React + Vite frontend shell
- ✅ PostgreSQL via Docker Compose
- ✅ Environment management
- ✅ Error handling infrastructure
- ✅ Testing foundation (pytest, Vitest)
- ✅ Health check endpoint

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local backend development)
- Node 20+ (for local frontend development)

### Run with Docker Compose

\`\`\`bash
# Copy example environment
cp .env.example .env

# Start all services
docker-compose up --build

# Access
# Frontend: http://localhost:5173
# Backend: http://localhost:8000
# API docs: http://localhost:8000/docs
# Database: localhost:5432 (user: securitysignals, pass: securitysignals)
\`\`\`

### Run Backend Locally (for development)

\`\`\`bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or \`venv\\Scripts\\activate\` on Windows

# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL via Docker
docker-compose up -d postgres

# Run migrations (Phase 2)
# alembic upgrade head

# Start backend
uvicorn app.main:app --reload

# Run tests
pytest

# Run specific test file
pytest tests/unit/test_config.py -v

# Run security tests
pytest tests/security/ -v
\`\`\`

### Run Frontend Locally (for development)

\`\`\`bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev

# Run tests
npm test

# Build for production
npm run build
\`\`\`

## API Endpoints (Phase 1)

- \`GET /health/\` — Basic health check
- \`GET /health/ready\` — Readiness probe (includes DB check)

## Testing

### Backend Tests

\`\`\`bash
cd backend
pytest                          # Run all tests
pytest tests/unit/ -v           # Unit tests only
pytest tests/integration/ -v    # Integration tests only
pytest tests/security/ -v       # Security tests only
pytest --cov=app                # With coverage
\`\`\`

### Frontend Tests

\`\`\`bash
cd frontend
npm test                        # Run all tests
npm run test:ui                 # Interactive UI
\`\`\`

## Architecture

### Trust Model

\`\`\`
EXTERNAL (UNTRUSTED)
  ↓ (HTTP + SSRF defenses)
INGESTION (parse, store)
  ↓
PROCESSING (filter, dedup, group)
  ↓
AI PIPELINE (Claude API, schema validated)
  ↓
HUMAN REVIEW (REQUIRED gate)
  ↓
PUBLIC API (PUBLISHED signals only)
\`\`\`

### Project Structure

\`\`\`
security-signals/
├── backend/
│   ├── app/
│   │   ├── config.py           # Settings & env validation
│   │   ├── logging.py          # Structured logging
│   │   ├── db/                 # Database layer
│   │   ├── api/                # FastAPI routes & middleware
│   │   ├── common/             # Shared utils, errors, types
│   │   └── main.py             # App factory
│   ├── tests/
│   │   ├── unit/               # Unit tests
│   │   ├── integration/        # Integration tests
│   │   └── security/           # Security tests
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   └── ...
│   └── package.json
└── docker-compose.yml
\`\`\`

## Next Phase

Phase 2: Database & Domain Models

- Define Article, Source, SecurityEvent, Signal entities
- Alembic migrations
- Repositories/services for data access

## Status

- ✅ Foundation complete
- ❌ No business logic implemented yet
- ❌ No ingestion implemented
- ❌ No AI pipeline implemented
- ❌ No review workflow implemented

## Security Considerations

- Trust boundary: TRUSTED system logic vs UNTRUSTED external content
- Prompt injection defenses (Phase 5)
- SSRF/DNS rebinding defenses (Phase 3)
- SQL injection prevention (SQLAlchemy ORM)
- XSS prevention (React auto-escaping)
- All state transitions audited (Phase 6)
"@
$path = Join-Path $ProjectRoot "README.md"
Set-Content -Path $path -Value $file
Write-Success "Created: README.md"

# ============================================================================
# COMPLETION SUMMARY
# ============================================================================

Write-Header "Phase 1 Files Created Successfully"

Write-Success "All 51 Phase 1 files have been created."
Write-Info "Next step: Copy environment files and start Docker Compose"

Write-Host ""
Write-Host "Command to copy environment files:" -ForegroundColor Cyan
Write-Host "  cd `"$ProjectRoot`"" -ForegroundColor Yellow
Write-Host "  Copy-Item '.env.example' '.env'" -ForegroundColor Yellow
Write-Host "  Copy-Item 'backend\.env.example' 'backend\.env'" -ForegroundColor Yellow
Write-Host "  Copy-Item 'frontend\.env.example' 'frontend\.env'" -ForegroundColor Yellow
Write-Host ""
Write-Host "Command to start Docker Compose:" -ForegroundColor Cyan
Write-Host "  cd `"$ProjectRoot`"" -ForegroundColor Yellow
Write-Host "  docker-compose up --build" -ForegroundColor Yellow
Write-Host ""
Write-Host "Files created:" -ForegroundColor Green
Write-Host "  Backend files: 32" -ForegroundColor Green
Write-Host "  Frontend files: 14" -ForegroundColor Green
Write-Host "  Root files: 5" -ForegroundColor Green
Write-Host "  TOTAL: 51 files" -ForegroundColor Green
Write-Host ""