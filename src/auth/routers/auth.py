from fastapi import APIRouter, Depends, Request, status, Body

from src.auth.schemas.user import UserRegister, UserLogin, UserResponse
from src.auth.schemas.token import Token
from src.auth.schemas.totp import LoginStep2Request, LoginResponse
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
) -> UserResponse:
    """Registers a new user. 
    
    Rate limited to 3 registrations per hour per IP.
    """
    user = await service.register_user(user_in)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_data: UserLogin,
    service: AuthService = Depends(get_auth_service)
) -> LoginResponse:
    """Authenticates a user and returns JWT tokens.
    
    Rate limited to 5 attempts per minute per IP.
    """
    return await service.login_user(login_data)


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str = Body(..., embed=True),
    service: AuthService = Depends(get_auth_service)
) -> Token:
    """Refreshes access and refresh tokens.
    
    Receives refresh_token in the request body.
    """
    return await service.refresh_tokens(refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    refresh_token: str = Body(..., embed=True),
    service: AuthService = Depends(get_auth_service)
) -> None:
    """Invalidates a refresh token.
    
    Receives refresh_token in the request body.
    """
    await service.logout(refresh_token)
    return None


@router.post("/login/2fa", response_model=LoginResponse)
async def login_2fa(
    request: LoginStep2Request,
    service: AuthService = Depends(get_auth_service)
) -> LoginResponse:
    """Completes login for users with 2FA enabled.

    Receives temp_token from /login and a TOTP code.
    """
    return await service.complete_2fa_login(request.temp_token, request.code)
