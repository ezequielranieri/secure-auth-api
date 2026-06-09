# 🔐 Secure Auth API

A production-ready authentication backend built with FastAPI, designed to
go beyond basic JWT tutorials and tackle real identity security problems:
token hijacking, brute force attacks, and session integrity at scale.

## 👤 About the Developer

I'm **Ezequiel Ranieri**, a self-taught Backend & Security Engineer
specializing in distributed systems and authentication. Everything I know —
from architecture patterns to async database design — I built through
documentation, hands-on projects, and real client work.

Being self-taught isn't a gap in my background. It's how I learned to
think independently, make architectural decisions under uncertainty, and
ship software that actually works.

- 📧 ez.ranieri@gmail.com
- 🐙 [GitHub](https://github.com/ezequielranieri)
- 💼 [LinkedIn](https://www.linkedin.com/in/ezequielranieri/)

---

## 🎯 Why this project?

Most authentication tutorials stop at "here's how JWT works." This project
starts where they end.

The goal was to implement a security-first architecture that addresses
the threats a production identity system actually faces: token reuse after
rotation, brute force at scale, and session revocation without performance
tradeoffs.

---

## 🏗 Architecture

The system follows a strict layered architecture with clear separation of
concerns:
Client
│
▼
Rate Limiter (SlowAPI + Redis)     ← distributed, multi-worker safe
│
▼
Middleware Stack                   ← Request ID, Audit Log, Error Handling
│
▼
Router Layer                       ← HTTP validation via Pydantic schemas
│
▼
AuthService                        ← business logic, no HTTP concerns
│
├── Security Core (JWT + Bcrypt)
└── Persistence (SQLAlchemy 2.0 async)

---

## 🛡 Security Features

### Brute Force Protection
Failed login attempts are tracked per user. Exceeding the configured
threshold triggers a temporary account lockout with structured audit logging.

### Token Rotation & Revocation
Refresh tokens are stored in the database as Bcrypt hashes — never in
plaintext — protecting against database leaks. Each use rotates the token:
the old one is revoked, a new one is issued.

### Distributed Rate Limiting
Critical endpoints (register, login) are rate-limited per IP using SlowAPI
with a Redis backend, ensuring limits hold correctly across multiple workers.

### Audit Logging
A dedicated middleware captures every security-relevant request: method,
path, status code, client IP, processing time, and a unique `X-Request-ID`
for correlation across logs.

### Password Validation
Passwords are validated before hashing: minimum length, complexity rules,
and a hard 72-byte ceiling enforced at the schema level to respect bcrypt's
internal limit.

---

## 🛠 Tech Stack

| Technology | Purpose |
|---|---|
| **FastAPI** | Async web framework |
| **SQLAlchemy 2.0** | Async ORM |
| **Pydantic v2** | Data validation & settings |
| **Alembic** | Database migrations |
| **bcrypt** | Password hashing |
| **PyJWT** | JWT token creation and validation |
| **SlowAPI + Redis** | Distributed rate limiting |
| **Structlog** | Structured JSON logging |
| **asyncpg** | Async PostgreSQL driver (production) |
| **aiosqlite** | Async SQLite driver (testing only) |
| **prometheus-client** | Metrics endpoint for observability |

---

## 🚀 Quick Start

**Prerequisites:** Python 3.12+, Docker

```bash
# Clone and configure
git clone https://github.com/ezequielranieri/secure-auth-api.git
cd secure-auth-api
cp .env.example .env  # set your SECRET_KEY

# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Install dependencies
pip install -e .

# Run migrations
alembic upgrade head

# Start the server
uvicorn src.auth.main:app --reload
```

API docs available at `http://localhost:8000/api/v1/docs`

---

## 📡 Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register new account (rate limited) |
| POST | `/api/v1/auth/login` | Authenticate, receive token pair or 2FA prompt |
| POST | `/api/v1/auth/login/2fa` | Complete login with TOTP code |
| POST | `/api/v1/auth/refresh` | Rotate tokens |
| POST | `/api/v1/auth/logout` | Revoke session |
| GET | `/api/v1/users/me` | Authenticated user profile |
| POST | `/api/v1/users/me/2fa/setup` | Initiate 2FA setup, get QR URI |
| POST | `/api/v1/users/me/2fa/verify` | Verify first TOTP code, enable 2FA |
| POST | `/api/v1/users/me/2fa/disable` | Disable 2FA with TOTP confirmation |

---

## 🔬 Technical Retrospective

Honest assessment of current design decisions and how I'd evolve them.

### ✅ Resolved

**Distributed Rate Limiting**
Initial implementation used SlowAPI with an in-memory backend — correct
behavior with a single worker, silent failure with multiple. Migrated to
Redis backend via `storage_uri`, making limits consistent across any number
of workers.

**Password Length Validation**
Bcrypt silently truncates passwords over 72 bytes, which can create a
false sense of security. Added explicit byte-length validation at the
Pydantic schema level, returning a clear 422 before the hash operation.

**Token Lookup: O(1) via JTI Index**
Refresh token verification previously iterated all active tokens for a user running bcrypt.verify() in a loop — O(n × bcrypt_cost). Added a jti (JWT ID) column with a unique index to refresh_tokens, stored at token creation. Lookup is now a direct indexed query, eliminating the loop entirely. expires_at is also validated at the DB level on every lookup.

**AuthService → Dependency Injection**
Refactored AuthService from @staticmethod methods to an injectable class instantiated via FastAPI's Depends() system. get_auth_service() binds the DB session at request time, decoupling the router from the implementation and making the service independently testable.

**Test Suite (34 tests)**
The project had existing tests that were broken after the DI refactor and the create_refresh_token tuple change. Fixed all unit and integration tests, then expanded coverage to include: token rotation reuse rejection, brute force lockout, access token used as refresh token rejection, and duplicate email registration. 34 tests passing across unit and integration layers.

**Two-Factor Authentication via TOTP**
Implemented a full 2FA flow using pyotp. Setup generates a provisioning URI for any authenticator app. Login is a two-step process when 2FA is active: first step returns a short-lived temp_token (5 min, type 2fa_pending), second step at /auth/login/2fa validates the TOTP code and issues full tokens. Disable requires TOTP confirmation. All operations are audit logged.

**PostgreSQL Migration + Docker Compose**
Migrated from aiosqlite/SQLite to asyncpg/PostgreSQL for production. SQLite is retained exclusively for the test suite via conftest.py override, keeping tests fast and isolated. Docker Compose now orchestrates three services: PostgreSQL 16, Redis 7, and the app itself — any developer can run the full stack with a single `docker compose up`.

**Prometheus Metrics**
Exposed a /metrics endpoint via prometheus-client compatible with any Prometheus scraper. Counters instrument five critical security events: login attempts (labeled success/failure), account lockouts, token refreshes, 2FA attempts, and registrations. Metrics are incremented directly in the service layer, not middleware, keeping instrumentation close to the business logic.

**Security Library Modernization + Type Safety**
Replaced passlib (abandoned since 2020) and python-jose with bcrypt and PyJWT directly. This eliminates the bcrypt version incompatibility that forced a downgrade to 3.2.2. Removed the redundant `token` column from `refresh_tokens` — it stored a hash of the JTI which was already in plaintext in the same row, adding no security value. Fixed all 14 mypy errors across routers and security core. Result: 0 mypy errors, 34 tests passing, modern dependency stack.

### 🗺 Roadmap

- [x] Distributed rate limiting with Redis backend
- [x] O(1) token lookup via JTI index
- [x] Dependency injection for AuthService
- [x] Test suite (34 tests, unit + integration)
- [x] Two-Factor Authentication via TOTP
- [x] PostgreSQL migration + Docker Compose
- [x] Prometheus metrics
- [x] Security library modernization (bcrypt + PyJWT, mypy clean)
- [ ] Token Family Tracking (detect and block token reuse attacks)
- [ ] Secrets Manager (documented decision: abstraction deferred — current env-var approach is sufficient for the threat model; a SecretsProvider interface would add Vault/AWS SM as backends when deploying to managed infrastructure)

---

## 📄 License

MIT
