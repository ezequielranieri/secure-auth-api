from fastapi import APIRouter, Depends

from src.auth.schemas.user import UserResponse
from src.auth.schemas.totp import TOTPSetupResponse, TOTPVerifyRequest, TOTPDisableRequest
from src.auth.models.user import User
from src.auth.core.dependencies import require_active_user
from src.auth.services.totp_service import TOTPService, get_totp_service


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(require_active_user)
) -> UserResponse:
    """Returns the current authenticated user's profile."""
    return UserResponse.model_validate(current_user)


@router.post("/me/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    current_user: User = Depends(require_active_user),
    totp_service: TOTPService = Depends(get_totp_service)
) -> TOTPSetupResponse:
    """Initiates 2FA setup. Returns a URI to generate a QR code."""
    result = await totp_service.setup_totp(current_user)
    return TOTPSetupResponse.model_validate(result)


@router.post("/me/2fa/verify")
async def verify_2fa(
    request: TOTPVerifyRequest,
    current_user: User = Depends(require_active_user),
    totp_service: TOTPService = Depends(get_totp_service)
) -> dict[str, str]:
    """Verifies the first TOTP code and enables 2FA."""
    return await totp_service.verify_and_enable_totp(current_user, request.code)


@router.post("/me/2fa/disable")
async def disable_2fa(
    request: TOTPDisableRequest,
    current_user: User = Depends(require_active_user),
    totp_service: TOTPService = Depends(get_totp_service)
) -> dict[str, str]:
    """Disables 2FA after verifying a TOTP code."""
    return await totp_service.disable_totp(current_user, request.code)
