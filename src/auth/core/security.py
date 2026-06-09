import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from src.auth.config import settings


def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt.

    Args:
        password: The plain-text password to hash.

    Returns:
        The hashed password as a string.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a hashed password.

    Args:
        plain_password: The plain-text password.
        hashed_password: The hashed password to check against.

    Returns:
        True if the passwords match, False otherwise.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


def create_token(
    subject: str | Any,
    expires_delta: timedelta,
    token_type: str = "access"
) -> tuple[str, str]:
    """Creates a JWT token.

    Args:
        subject: The subject of the token (usually user ID).
        expires_delta: How long the token should be valid.
        token_type: The type of token ('access' or 'refresh').

    Returns:
        A tuple of (encoded_jwt, jti).
    """
    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    jti = str(uuid.uuid4())
    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "type": token_type,
        "iat": now,
        "jti": jti,
    }
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    return encoded_jwt, jti


def create_access_token(subject: str | Any) -> str:
    """Helper to create an access token."""
    expires = timedelta(minutes=settings.access_token_expire_minutes)
    token, _ = create_token(subject, expires, token_type="access")
    return token


def create_refresh_token(subject: str | Any) -> tuple[str, str]:
    """Helper to create a refresh token. Returns (token, jti)."""
    expires = timedelta(days=settings.refresh_token_expire_days)
    return create_token(subject, expires, token_type="refresh")


def decode_token(token: str) -> dict[str, Any]:
    """Decodes and validates a JWT token.

    Args:
        token: The JWT token to decode.

    Returns:
        The decoded payload.

    Raises:
        jwt.InvalidTokenError: If the token is invalid or expired.
    """
    payload: dict[str, Any] = jwt.decode(
        token, settings.secret_key, algorithms=[settings.algorithm]
    )
    return payload


def create_temp_token(subject: str) -> str:
    """Creates a short-lived temporary token for 2FA pending state.

    Args:
        subject: The user ID.

    Returns:
        A JWT token string valid for 5 minutes with type '2fa_pending'.
    """
    expires = timedelta(minutes=5)
    token, _ = create_token(subject, expires, token_type="2fa_pending")
    return token


def decode_temp_token(token: str) -> dict[str, Any]:
    """Decodes and validates a 2FA pending token.

    Args:
        token: The temporary JWT token.

    Returns:
        The decoded payload.

    Raises:
        HTTPException: If token is invalid or not of type '2fa_pending'.
    """
    from fastapi import HTTPException, status
    try:
        payload = decode_token(token)
        if payload.get("type") != "2fa_pending":
            raise ValueError("Invalid token type")
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired temporary token"
        )
