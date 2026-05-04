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

    def test_create_access_token(self):
        """Access token should be created with correct subject and type."""
        subject = "test-user-id"
        token = security.create_access_token(subject)
        payload = security.decode_token(token)
        
        assert payload["sub"] == subject
        assert payload["type"] == "access"
        assert "exp" in payload

    def test_create_refresh_token(self):
        """Refresh token should be created with correct subject and type."""
        subject = "test-user-id"
        token = security.create_refresh_token(subject)
        payload = security.decode_token(token)
        
        assert payload["sub"] == subject
        assert payload["type"] == "refresh"
        assert "exp" in payload

    def test_decode_invalid_token(self):
        """Decoding an invalid token should raise JWTError."""
        with pytest.raises(jwt.JWTError):
            security.decode_token("invalid-token")

    def test_token_expiration(self):
        """Expired token should raise JWTError."""
        subject = "test-user-id"
        # Create a token that expired 1 minute ago
        expires_delta = timedelta(minutes=-1)
        token = security.create_token(subject, expires_delta)
        
        with pytest.raises(jwt.JWTError):
            security.decode_token(token)
