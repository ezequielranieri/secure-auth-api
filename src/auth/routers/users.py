from fastapi import APIRouter, Depends
from src.auth.schemas.user import UserResponse
from src.auth.models.user import User
from src.auth.core.dependencies import require_active_user


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(require_active_user)
):
    """Returns the current authenticated user's profile."""
    return current_user


# 2FA endpoints placeholder for Phase 5 (Logic to be added in Phase 5 refinement or later)
@router.post("/me/2fa/enable")
async def enable_2fa(
    current_user: User = Depends(require_active_user)
):
    """Enables 2FA for the user."""
    return {"message": "2FA enrollment initiated (Phase 5 Refinement)"}
