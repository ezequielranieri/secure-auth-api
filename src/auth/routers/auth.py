from fastapi import APIRouter, Depends, Request, status, Body

from src.auth.schemas.user import UserRegister, UserLogin, UserResponse
from src.auth.schemas.token import Token
from src.auth.services.auth_service import AuthService, get_auth_service
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
    service: AuthService = Depends(get_auth_service)
):
    """Registers a new user. 
    
    Rate limited to 3 registrations per hour per IP.
    """
    return await service.register_user(user_in)


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_data: UserLogin,
    service: AuthService = Depends(get_auth_service)
):
    """Authenticates a user and returns JWT tokens.
    
    Rate limited to 5 attempts per minute per IP.
    """
    return await service.login_user(login_data)


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str = Body(..., embed=True),
    service: AuthService = Depends(get_auth_service)
):
    """Refreshes access and refresh tokens.
    
    Receives refresh_token in the request body.
    """
    return await service.refresh_tokens(refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    refresh_token: str = Body(..., embed=True),
    service: AuthService = Depends(get_auth_service)
):
    """Invalidates a refresh token.
    
    Receives refresh_token in the request body.
    """
    await service.logout(refresh_token)
    return None
