import pytest
from pydantic import ValidationError
from src.auth.schemas.user import UserRegister


class TestUserSchemas:
    """Unit tests for User-related Pydantic schemas."""

    def test_user_register_valid(self):
        """Valid user registration data should pass validation."""
        data = {
            "email": "test@example.com",
            "password": "Password123"
        }
        user = UserRegister(**data)
        assert user.email == data["email"]
        assert user.password == data["password"]

    def test_user_register_invalid_email(self):
        """Invalid email should raise ValidationError."""
        data = {
            "email": "not-an-email",
            "password": "Password123"
        }
        with pytest.raises(ValidationError) as excinfo:
            UserRegister(**data)
        assert "value is not a valid email address" in str(excinfo.value)

    def test_user_register_short_password(self):
        """Short password should raise ValueError from validator."""
        data = {
            "email": "test@example.com",
            "password": "Pass1"
        }
        with pytest.raises(ValidationError) as excinfo:
            UserRegister(**data)
        assert "Password must be at least 8 characters" in str(excinfo.value)

    def test_user_register_no_uppercase(self):
        """Password without uppercase should raise ValueError."""
        data = {
            "email": "test@example.com",
            "password": "password123"
        }
        with pytest.raises(ValidationError) as excinfo:
            UserRegister(**data)
        assert "Password must contain at least one uppercase letter" in str(excinfo.value)

    def test_user_register_no_digit(self):
        """Password without digit should raise ValueError."""
        data = {
            "email": "test@example.com",
            "password": "Password"
        }
        with pytest.raises(ValidationError) as excinfo:
            UserRegister(**data)
        assert "Password must contain at least one digit" in str(excinfo.value)
