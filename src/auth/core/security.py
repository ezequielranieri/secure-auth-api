import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from src.auth.config import settings


# Password hashing configuration
# Using bcrypt with cost factor 12 as per proyecto_auth_api.md
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt.

    Args:
        password: The plain-text password to hash.

    Returns:
        The hashed password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a hashed password.

    Args:
        plain_password: The plain-text password.
        hashed_password: The hashed password to check against.

    Returns:
        True if the passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_token(
    subject: str | Any,
    expires_delta: timedelta,
    token_type: str = "access"
) -> str:
    """Creates a JWT token.

    Args:
        subject: The subject of the token (usually user ID).
        expires_delta: How long the token should be valid.
        token_type: The type of token ('access' or 'refresh').

    Returns:
        The encoded JWT token.
    """
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "type": token_type,
        "iat": now,
        "jti": str(uuid.uuid4())  # Ensure token uniqueness
    }
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    return encoded_jwt


def create_access_token(subject: str | Any) -> str:
    """Helper to create an access token."""
    expires = timedelta(minutes=settings.access_token_expire_minutes)
    return create_token(subject, expires, token_type="access")


def create_refresh_token(subject: str | Any) -> str:
    """Helper to create a refresh token."""
    expires = timedelta(days=settings.refresh_token_expire_days)
    return create_token(subject, expires, token_type="refresh")


def decode_token(token: str) -> dict[str, Any]:
    """Decodes and validates a JWT token.

    Args:
        token: The JWT token to decode.

    Returns:
        The decoded payload.

    Raises:
        jwt.JWTError: If the token is invalid or expired.
    """
    return jwt.decode(
        token, settings.secret_key, algorithms=[settings.algorithm]
    )
