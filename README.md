# Secure Auth API 🔐

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy_2.0-D71F00?style=for-the-badge&logo=sqlalchemy)](https://www.sqlalchemy.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic_v2-E92063?style=for-the-badge&logo=pydantic)](https://docs.pydantic.dev/latest/)
[![Python](https://img.shields.io/badge/Python_3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

A production-ready, security-first REST API implementing industry-standard authentication and authorization patterns. Built with high-performance asynchronous Python.

---

## 🚀 Why This Project?

Most authentication tutorials stop at basic JWT. This project goes further, treating **Security as a First-Class Citizen**. It demonstrates how to build a resilient backend that actively defends against common attacks (Brute Force, Credential Stuffing) while maintaining high performance and clear observability.

It’s designed to show a **Senior Mindset**: clean code, strict validation, layered architecture, and comprehensive testing.

---

## 🛡️ Security Features Explained

### 1. Robust Password Hashing
Uses **Bcrypt** with a work factor of **12**. Unlike simple hashes, it's computationally expensive, making it resilient to hardware-accelerated cracking attempts.

### 2. Modern Token Strategy (Access + Refresh)
- **Access Tokens**: Short-lived (15 min) for minimal exposure.
- **Refresh Tokens**: Stored in a secure database to allow for **instant revocation** (Logout) and **Token Rotation** (new refresh token on every use), preventing replay attacks.

### 3. Brute Force Protection
Integrated monitoring of failed login attempts. Automatically **locks accounts** for 15 minutes after 5 consecutive failures, effectively stopping automated password-guessing bots.

### 4. Advanced Rate Limiting
Granular protection using **SlowAPI**. Sensitive endpoints like `/register` and `/login` are strictly limited per IP address to prevent service abuse and DDoS at the application layer.

### 5. Audit Logging & Observability
Every security-relevant event (logins, lockouts, registrations) is recorded in a **structured format** using `structlog`. Includes **Request ID tracking** across all logs for seamless troubleshooting in production.

### 6. 2FA Ready (TOTP)
Architecture prepared for Two-Factor Authentication using Time-based One-Time Passwords (TOTP), emphasizing a multi-layered security approach.

---

## 🏗️ Architecture

The project follows a **Layered Architecture** to ensure separation of concerns and maintainability:

- **Routers**: FastAPI endpoints, handle HTTP logic and rate limiting.
- **Services**: Business logic layer. Orchestrates security operations, DB interactions, and audit logging.
- **Models**: SQLAlchemy 2.0 (Async) models with UUID primary keys.
- **Schemas**: Strict Pydantic v2 validation (e.g., strong password requirements).
- **Middleware**: Global handlers for Request IDs, Audit Logs, and Safe Error Handling.

---

## 🛠️ Technologies

- **FastAPI**: Modern, high-performance web framework.
- **SQLAlchemy 2.0**: The industry-standard ORM, used here with full `asyncio` support.
- **Alembic**: Database migration management.
- **Pydantic v2**: High-speed data validation and settings management.
- **Passlib & Python-Jose**: Cryptographic primitives for hashing and JWT.
- **SlowAPI**: Rate limiting for FastAPI.
- **Structlog**: High-performance structured logging.
- **Pytest & HTTPX**: Comprehensive unit and integration testing.

---

## 📥 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ezequielranieri/secure-auth-api.git

   cd secure-auth-api
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your secrets
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**
   ```bash
   alembic upgrade head
   ```

---

## 🚀 Usage

Start the development server:
```bash
uvicorn src.auth.main:app --reload
```

The API documentation will be available at:
- Swagger UI: `http://localhost:8000/api/v1/docs`
- Redoc: `http://localhost:8000/api/v1/redoc`

---

## 🧪 Testing

Run the full test suite (19+ tests including unit and integration):
```bash
pytest
```

---

## 🔑 API Endpoints

### Auth
- `POST /api/v1/auth/register` — New user enrollment (Rate limited)
- `POST /api/v1/auth/login` — Token issuance & Brute force check (Rate limited)
- `POST /api/v1/auth/refresh` — Token rotation
- `POST /api/v1/auth/logout` — Instant token revocation

### Users
- `GET /api/v1/users/me` — Secure profile access (Requires JWT)

---

## 👨‍💻 About the Author

**Self-Taught & Driven Developer**

I am a passionate software engineer who chose the path of self-directed learning. This project is a testament to my ability to master complex technical domains—like backend security and asynchronous systems—through disciplined study and hands-on implementation.

I believe that **Clean Code** and **Security** are not "extras" but fundamental requirements. My goal is to build software that is not just functional, but resilient, auditable, and elegant.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
