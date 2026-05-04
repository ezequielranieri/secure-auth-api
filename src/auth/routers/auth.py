from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.database import get_db
from src.auth.schemas.user import UserRegister, UserLogin, UserResponse
from src.auth.schemas.token import Token
from src.auth.services.auth_service import AuthService
from src.auth.core.rate_limit import limiter


router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
@limiter.limit("3/hour")
async def register(
    request: Request,
    user_in: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """Registers a new user. 
    
    Rate limited to 3 registrations per hour per IP.
    """
    return await AuthService.register_user(db, user_in)


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """Authenticates a user and returns JWT tokens.
    
    Rate limited to 5 attempts per minute per IP.
    """
    return await AuthService.login_user(db, login_data)


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Refreshes access and refresh tokens."""
    return await AuthService.refresh_tokens(db, refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Invalidates a refresh token."""
    await AuthService.logout(db, refresh_token)
    return None
