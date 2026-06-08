from pydantic import BaseModel


class TOTPSetupResponse(BaseModel):
    """Schema for TOTP setup response."""

    uri: str
    secret: str


class TOTPVerifyRequest(BaseModel):
    """Schema for TOTP verification request."""

    code: str


class TOTPDisableRequest(BaseModel):
    """Schema for TOTP disable request."""

    code: str


class LoginStep2Request(BaseModel):
    """Schema for the second step of 2FA login."""

    temp_token: str
    code: str


class LoginResponse(BaseModel):
    """Schema for login response, supporting both full and 2FA-pending states."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    two_fa_required: bool = False
    temp_token: str | None = None
