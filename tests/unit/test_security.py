import pytest
from datetime import timedelta
from jose import jwt
from src.auth.core import security
from src.auth.config import settings


class TestSecurity:
    """Unit tests for security core functions."""

    def test_hash_password(self):
        """Password should be hashed correctly and verifiable."""
        password = "secret_password"
        hashed = security.hash_password(password)
        assert hashed != password
        assert security.verify_password(password, hashed) is True
        assert security.verify_password("wrong_password", hashed) is False

    def test_create_access_token_returns_string(self):
        """Access token should return a string."""
        subject = "test-user-id"
        token = security.create_access_token(subject)
        assert isinstance(token, str)

    def test_create_access_token_payload(self):
        """Access token payload should have correct subject and type."""
        subject = "test-user-id"
        token = security.create_access_token(subject)
        payload = security.decode_token(token)
        assert payload["sub"] == subject
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "jti" in payload

    def test_create_refresh_token_returns_tuple(self):
        """create_refresh_token should return a (token, jti) tuple."""
        subject = "test-user-id"
        result = security.create_refresh_token(subject)
        assert isinstance(result, tuple)
        assert len(result) == 2
        token, jti = result
        assert isinstance(token, str)
        assert isinstance(jti, str)

    def test_create_refresh_token_payload(self):
        """Refresh token payload should have correct subject, type and jti."""
        subject = "test-user-id"
        token, jti = security.create_refresh_token(subject)
        payload = security.decode_token(token)
        assert payload["sub"] == subject
        assert payload["type"] == "refresh"
        assert payload["jti"] == jti
        assert "exp" in payload

    def test_create_token_returns_tuple(self):
        """create_token should return a (token, jti) tuple."""
        subject = "test-user-id"
        expires = timedelta(minutes=15)
        result = security.create_token(subject, expires)
        assert isinstance(result, tuple)
        token, jti = result
        assert isinstance(token, str)
        assert isinstance(jti, str)

    def test_decode_invalid_token(self):
        """Decoding an invalid token should raise JWTError."""
        with pytest.raises(jwt.JWTError):
            security.decode_token("invalid-token")

    def test_token_expiration(self):
        """Expired token should raise JWTError."""
        subject = "test-user-id"
        expires_delta = timedelta(minutes=-1)
        token, _ = security.create_token(subject, expires_delta)
        with pytest.raises(jwt.JWTError):
            security.decode_token(token)
