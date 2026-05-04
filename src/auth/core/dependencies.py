import uuid
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.auth.config import settings
from src.auth.database import get_db
from src.auth.models.user import User
from src.auth.schemas.token import TokenPayload
from src.auth.core import security


# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.app_name}/api/v1/auth/login"
)


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Dependency to get the current authenticated user.

    Validates the JWT token and fetches the user from the database.

    Args:
        db: Database session.
        token: JWT access token.

    Returns:
        The User object if found and valid.

    Raises:
        HTTPException: If token is invalid or user doesn't exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = security.decode_token(token)
        token_data = TokenPayload(**payload)
        
        if token_data.sub is None or token_data.type != "access":
            raise credentials_exception
            
        user_id = uuid.UUID(token_data.sub)
            
    except (jwt.JWTError, ValidationError, ValueError):
        raise credentials_exception

    # Fetch user from DB
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception
        
    return user


async def require_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Dependency to ensure the current user is active.

    Args:
        current_user: The user retrieved from get_current_user.

    Returns:
        The active User object.

    Raises:
        HTTPException: If the user is inactive.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def require_verified_user(
    current_user: User = Depends(require_active_user)
) -> User:
    """Dependency to ensure the current user is verified."""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User email not verified"
        )
    return current_user
