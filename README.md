# Security Signals

A production-oriented cybersecurity intelligence platform that ingests real security information from trusted sources, validates and groups related events, generates AI-powered security insights using Claude on AWS Bedrock, and publishes human-approved signals through a public API and embeddable frontend widget.

## Overview

Security Signals transforms important cybersecurity developments into concise, actionable security-design insights.

The platform follows this pipeline:

```text
REAL SECURITY NEWS
        ↓
SECURITY EVENT
        ↓
SECURITY SIGNAL
        ↓
SECURE-DESIGN INSIGHT
```

The goal is simple:

> Help an engineer understand the relevant threat and the security principle behind it within two minutes.

The system is designed with a security-first trust model. External security content is treated as untrusted input, AI output is schema-validated, and human review is mandatory before anything becomes publicly visible.

## Key Features

- Real cybersecurity news ingestion from trusted sources
- RSS, Atom and machine-readable source adapters
- SSRF and DNS rebinding protection
- Article normalization and relevance filtering
- Multi-level deduplication and security event grouping
- Major-event detection
- AI-powered security signal generation using Claude on AWS Bedrock
- Structured and schema-validated AI output
- AI security taxonomy and subcategory classification
- Evidence and source provenance tracking
- Human review workflow
- Role-based access control
- JWT authentication and bcrypt password hashing
- Audit logging
- Public API exposing published signals only
- Internal review and administration APIs
- Monthly security analytics
- Weekly automated ingestion scheduler
- Embeddable React-based Security Signals widget
- Security headers, CORS protection and rate limiting
- Comprehensive unit, integration and security testing
- Docker-based deployment support

## Security Signal Categories

Security Signals covers:

- Vulnerabilities
- Cloud Security
- Identity & Access Management
- Application & API Security
- Supply Chain Security
- Data Breaches & Privacy
- Ransomware & Malware
- Threat Intelligence
- AI Security
- Infrastructure & DevOps

### AI Security Coverage

- LLM vulnerabilities
- Agent and tool abuse
- AI data leakage
- Model poisoning
- AI supply chain security
- AI infrastructure security
- AI-enabled attacks
- Misaligned AI permissions

## Architecture

Security Signals is implemented as a modular monolith.

```text
┌──────────────────────────────┐
│        Trusted Sources       │
│  RSS / Atom / JSON / APIs    │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│          Ingestion           │
│ Fetch → Validate → Normalize │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│         Processing           │
│ Relevance → Dedup → Grouping │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│        AI Intelligence       │
│ Claude / AWS Bedrock         │
│ Schema + Evidence Validation │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│        Human Review          │
│ Draft → Review → Approval    │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│         Public API           │
│      Published Signals       │
└──────────────────────────────┘
```

### Trust Model

External article content is **UNTRUSTED**.

```text
EXTERNAL / UNTRUSTED CONTENT
            ↓
      HTTP SECURITY LAYER
      SSRF / DNS Protection
            ↓
         INGESTION
            ↓
        PROCESSING
            ↓
       AI PIPELINE
   Schema + Evidence Validation
            ↓
      HUMAN REVIEW
        REQUIRED
            ↓
      PUBLIC API
   Published Signals Only
```

AI-generated content never directly controls application behavior or bypasses the review workflow.

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL
- Pydantic
- APScheduler
- boto3
- AWS Bedrock
- Claude
- JWT
- bcrypt

### Frontend

- React
- TypeScript
- Vite
- Vitest

### Infrastructure

- Docker
- Docker Compose
- PostgreSQL
- Nginx

### Testing & Quality

- pytest
- Vitest
- Ruff
- mypy
- ESLint

## Project Structure

```text
security-signals/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/
│   │   │   ├── dependencies.py
│   │   │   ├── middleware.py
│   │   │   └── rate_limit.py
│   │   ├── auth/
│   │   ├── common/
│   │   ├── db/
│   │   ├── ingestion/
│   │   ├── intelligence/
│   │   ├── scheduler/
│   │   ├── services/
│   │   ├── repositories.py
│   │   ├── schemas.py
│   │   └── main.py
│   ├── alembic/
│   │   └── versions/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── security/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   └── widget/
│   ├── tests/
│   ├── loader/
│   ├── docs/
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## Signal Lifecycle

```text
DRAFT
  ↓
IN_REVIEW
  ↓
APPROVED
  ↓
PUBLISHED
```

A signal may also be rejected during review:

```text
IN_REVIEW
    ↓
 REJECTED
```

AI-generated signals are **not automatically published**. Human review is mandatory before publication.

## Data Sources

The ingestion system is based on real cybersecurity information rather than synthetic or crowd-sourced threats.

The ingestion layer supports:

- Security advisories
- Vendor security feeds
- Vulnerability information
- Cloud security sources
- Application security sources
- Threat intelligence sources
- AI security sources
- Security news sources

Source processing includes:

- Request timeouts
- Retry handling
- Response size limits
- User-Agent handling
- Redirect controls
- SSRF protection
- DNS rebinding protection
- Feed validation
- Malformed feed handling
- Source failure tracking
- Source recovery

## Deduplication & Event Grouping

```text
Exact URL
   ↓
Content Hash
   ↓
Title Similarity
   ↓
Security Event Grouping
```

When multiple trusted sources report the same underlying security event, the system can group them into a single event while preserving individual source evidence.

## AI Intelligence

The AI pipeline uses **Claude through AWS Bedrock** to transform validated security events into structured security insights.

AI output includes:

- Security signal title
- Summary
- Security impact
- Security design principles
- Recommended actions
- Evidence
- Category
- Subcategory

AI output is validated against strict schemas before persistence.

### AI Security Controls

- External article content is treated as data, not instructions.
- AI output cannot control application behavior.
- Structured output validation is mandatory.
- Evidence must correspond to known source material.
- Invalid AI output is rejected.
- Secrets are never included in prompts.
- AI-generated content requires human review before publication.

## Authentication & Authorization

Supported roles:

- `ADMIN`
- `REVIEWER`
- `VIEWER`

Capabilities include:

- JWT authentication
- Explicit JWT algorithm validation
- Token expiry validation
- Required JWT claims
- bcrypt password hashing
- Login rate limiting
- Role-based authorization
- User administration
- Audit logging

## Public API

Public endpoints expose **published signals only**.

### Published Signals

```http
GET /api/v1/signals/published
```

### Published Signal Detail

```http
GET /api/v1/signals/published/{id}
```

### Public Analytics

```http
GET /api/v1/analytics/public
```

### API Documentation

```text
http://localhost:8000/docs
```

## Analytics

The platform provides:

- Monthly signal trends
- Category distribution
- Security principle counts
- Dominant security themes

Public analytics are based on published signals. Internal analytics are restricted to authorized users.

## Automated Ingestion

The ingestion pipeline is scheduled using APScheduler.

Default schedule:

```text
Every Sunday at 20:00 UTC
```

The scheduler includes:

- Single-instance job protection
- Job coalescing
- Failure isolation
- Startup/shutdown handling
- Scheduler logging
- Migration path toward Celery for distributed deployments

## Frontend Widget

Security Signals includes an embeddable frontend widget with:

- Security signal feed
- Category filtering
- Signal details
- Evidence/source links
- Responsive layout
- Loading, empty and error states

Example integration:

```html
<script
  type="module"
  src="/loader/embed.js"
  data-widget-url="https://your-widget-host/"
  data-api-base="https://your-api-host"
  data-position="bottom-right">
</script>
```

See `frontend/docs/embedding.md` for integration details.

## Local Development

### Prerequisites

- Docker
- Docker Compose
- Python 3.11+
- Node.js 20+
- PostgreSQL (if running outside Docker)

### Environment Configuration

```bash
cp .env.example .env
```

Security requirements:

- Never commit `.env`
- Never place production secrets in `.env.example`
- Never hard-code credentials
- Never expose AWS credentials to the frontend

### Run with Docker Compose

```bash
docker-compose up --build
```

Services:

```text
Frontend:
http://localhost:5173

Backend:
http://localhost:8000

API documentation:
http://localhost:8000/docs
```

## Backend Development

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Run all tests:

```bash
python -m pytest
```

Run unit tests:

```bash
python -m pytest tests/unit/ -v
```

Run integration tests:

```bash
python -m pytest tests/integration/ -v
```

Run security tests:

```bash
python -m pytest tests/security/ -v
```

## Frontend Development

```bash
cd frontend
npm install
npm run dev
```

Run tests:

```bash
npm test
```

Build for production:

```bash
npm run build
```

## Testing

Latest verified results:

```text
Backend:
508 passed
0 failed

Frontend:
77 passed
0 failed
```

The frontend production build, type checking, and linting were also verified successfully.

## Security

Security is a core architectural requirement.

### Application Security

The implementation includes controls for:

- SQL injection prevention
- XSS prevention
- SSRF prevention
- DNS rebinding protection
- Authentication hardening
- Authorization / RBAC
- JWT validation
- Rate limiting
- Security headers
- CORS restrictions
- Query-string leakage prevention
- Audit logging
- Database immutability controls

### AI Security

The system addresses:

- Prompt injection
- Malicious external content
- AI output validation
- Evidence validation
- AI permission boundaries
- AI supply-chain considerations
- Sensitive information exposure

External content is always considered untrusted.

## Security Testing

Security-focused testing includes:

- Authentication tests
- RBAC tests
- JWT hardening tests
- Rate-limit tests
- Error-handling tests
- Security-header tests
- Prompt-injection tests
- AI output validation tests
- Evidence validation tests
- Ingestion security tests

## Current Status

### Completed

- [x] Project foundation
- [x] PostgreSQL database
- [x] SQLAlchemy models
- [x] Alembic migrations
- [x] Real security-source ingestion
- [x] Source adapters
- [x] Article normalization
- [x] Relevance filtering
- [x] Deduplication
- [x] Security event grouping
- [x] AI intelligence pipeline
- [x] AWS Bedrock / Claude integration
- [x] Structured AI output validation
- [x] Evidence validation
- [x] Signal service
- [x] Authentication
- [x] RBAC
- [x] Audit logging
- [x] Human review workflow
- [x] Public signals API
- [x] Internal administration APIs
- [x] Analytics backend
- [x] Automated ingestion scheduler
- [x] Security hardening
- [x] Embeddable frontend widget
- [x] Backend test suite
- [x] Frontend test suite
- [x] End-to-end verification

### Production Considerations

- Upgrade FastAPI/Starlette to current secure versions
- Add public API rate limiting at the reverse-proxy/CDN layer
- Use distributed scheduler/locking for multiple backend replicas
- Finalize production monitoring and alerting
- Finalize analytics UI requirements
- Define production data-retention policy
- Complete final GDPR/privacy review
- Complete production deployment configuration

## Design Principles

### 1. Real Data Over Fabrication

Security insights originate from real cybersecurity sources.

### 2. Source Truth Over AI

AI transforms and summarizes evidence; it does not replace source evidence.

### 3. Human Review Is Mandatory

No AI-generated signal is automatically published.

### 4. External Content Is Hostile

Security articles and feeds are treated as untrusted input.

### 5. AI Cannot Control the Application

AI output is constrained by schemas and application-level validation.

### 6. Security-Sensitive Actions Are Audited

Important lifecycle and administrative operations produce audit records.

### 7. Secrets Never Belong in Source Code

Credentials and environment-specific secrets remain outside version control.

## Limitations

- Ingestion is scheduled rather than real-time
- Semantic ML-based deduplication is not implemented
- Threat actor attribution is not performed
- Predictive severity scoring is not implemented
- Crowd-sourced threats are outside the scope of the platform
- Direct Securacy threat-model integration is not currently implemented
- Distributed scheduler coordination requires additional infrastructure for multi-replica deployments

## License

Add the project's applicable license here.
