from pydantic import BaseModel


class Token(BaseModel):
    """Schema for JWT tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Schema for JWT payload content."""

    sub: str | None = None
    exp: int | None = None
    type: str | None = None
