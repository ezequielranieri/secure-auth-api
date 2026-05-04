import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


class UserBase(BaseModel):
    """Base schema for User data."""

    email: EmailStr


class UserRegister(UserBase):
    """Schema for user registration."""

    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validates that the password meets security requirements.

        Rules:
            - At least 8 characters long.
            - Contains at least one uppercase letter.
            - Contains at least one digit.
        """
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(UserBase):
    """Schema for user login."""

    password: str


class UserResponse(UserBase):
    """Schema for user data in responses.

    Excludes sensitive fields like hashed_password or totp_secret.
    """

    id: uuid.UUID
    is_active: bool
    is_verified: bool
    totp_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
