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
| **Passlib (Bcrypt)** | Password hashing |
| **SlowAPI + Redis** | Distributed rate limiting |
| **Structlog** | Structured JSON logging |
| **aiosqlite** | Async SQLite driver (dev) |

---

## 🚀 Quick Start

**Prerequisites:** Python 3.12+, Docker

```bash
# Clone and configure
git clone https://github.com/ezequielranieri/secure-auth-api.git
cd secure-auth-api
cp .env.example .env  # set your SECRET_KEY

# Start Redis
docker compose up -d

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
| POST | `/api/v1/auth/login` | Authenticate, receive token pair |
| POST | `/api/v1/auth/refresh` | Rotate tokens |
| POST | `/api/v1/auth/logout` | Revoke session |
| GET | `/api/v1/users/me` | Authenticated user profile |

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

### 🗺 Roadmap

- [x] Distributed rate limiting with Redis backend
- [x] O(1) token lookup via JTI index
- [x] Dependency injection for AuthService
- [ ] PostgreSQL migration (replace aiosqlite for production concurrency)
- [ ] Token Family Tracking (detect and block token reuse attacks)
- [ ] Two-Factor Authentication via TOTP
- [ ] Prometheus metrics (`login_attempts_total`, `lockouts_total`)
- [ ] Secrets Manager integration

---

## 📄 License

MIT
