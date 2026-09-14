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

\\\ash
# Copy example environment
cp .env.example .env

# Start all services
docker-compose up --build

# Access
# Frontend: http://localhost:5173
# Backend: http://localhost:8000
# API docs: http://localhost:8000/docs
# Database: localhost:5432 (user: securitysignals, pass: securitysignals)
\\\

### Run Backend Locally (for development)

\\\ash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or \env\\Scripts\\activate\ on Windows

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
\\\

### Run Frontend Locally (for development)

\\\ash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev

# Run tests
npm test

# Build for production
npm run build
\\\

## API Endpoints (Phase 1)

- \GET /health/\ — Basic health check
- \GET /health/ready\ — Readiness probe (includes DB check)

## Testing

### Backend Tests

\\\ash
cd backend
pytest                          # Run all tests
pytest tests/unit/ -v           # Unit tests only
pytest tests/integration/ -v    # Integration tests only
pytest tests/security/ -v       # Security tests only
pytest --cov=app                # With coverage
\\\

### Frontend Tests

\\\ash
cd frontend
npm test                        # Run all tests
npm run test:ui                 # Interactive UI
\\\

## Architecture

### Trust Model

\\\
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
\\\

### Project Structure

\\\
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
\\\

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
