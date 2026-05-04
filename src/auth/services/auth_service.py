import uuid
import structlog
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from src.auth.config import settings
from src.auth.models.user import User
from src.auth.models.token import RefreshToken
from src.auth.schemas.user import UserRegister, UserLogin
from src.auth.schemas.token import Token
from src.auth.core import security


logger = structlog.get_logger(__name__)


def log_audit(event: str, detail: dict[str, Any]) -> None:
    """Logs a security audit event in a structured format.

    Args:
        event: The name of the audit event.
        detail: A dictionary with event details.
    """
    detail_str = " | ".join(f"{k}={v}" for k, v in detail.items())
    logger.info(f"AUDITORIA | evento={event} | {detail_str}")


class AuthService:
    """Business logic for authentication operations."""

    @staticmethod
    async def register_user(db: AsyncSession, user_in: UserRegister) -> User:
        """Registers a new user in the system.

        Args:
            db: Database session.
            user_in: Registration data.

        Returns:
            The created User.

        Raises:
            HTTPException: If the email is already registered.
        """
        # Check if user exists
        result = await db.execute(select(User).where(User.email == user_in.email))
        if result.scalar_one_or_none():
            log_audit("registration_failed", {"email": user_in.email, "reason": "email_exists"})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Create user
        new_user = User(
            email=user_in.email,
            hashed_password=security.hash_password(user_in.password),
            is_active=True,  # Default to active for this project
            is_verified=False
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        log_audit("user_registered", {"user_id": str(new_user.id), "email": new_user.email})
        return new_user

    @staticmethod
    async def login_user(db: AsyncSession, login_data: UserLogin) -> Token:
        """Authenticates a user and generates tokens.

        Implements brute force protection and audit logging.

        Args:
            db: Database session.
            login_data: Login credentials.

        Returns:
            A Token schema containing access and refresh tokens.

        Raises:
            HTTPException: For invalid credentials, locked accounts, or inactive users.
        """
        result = await db.execute(select(User).where(User.email == login_data.email))
        user = result.scalar_one_or_none()

        if not user:
            log_audit("login_failed", {"email": login_data.email, "reason": "user_not_found"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            log_audit("login_failed", {"user_id": str(user.id), "reason": "account_locked"})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is locked until {user.locked_until}"
            )

        if not user.is_active:
            log_audit("login_failed", {"user_id": str(user.id), "reason": "user_inactive"})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive"
            )

        # Verify password
        if not security.verify_password(login_data.password, user.hashed_password):
            # Increment failed attempts
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= settings.max_failed_login_attempts:
                lock_duration = timedelta(minutes=settings.lockout_duration_minutes)
                user.locked_until = datetime.now(timezone.utc) + lock_duration
                log_audit("account_locked", {"user_id": str(user.id), "email": user.email})
            
            await db.commit()
            log_audit("login_failed", {"user_id": str(user.id), "reason": "invalid_password"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        
        user_id = user.id  # Capture ID before commit
        
        await db.commit()
        
        access_token = security.create_access_token(user_id)
        refresh_token_str = security.create_refresh_token(user_id)

        # Store hashed refresh token for revocation
        # We store only the hash to protect against DB leaks
        new_refresh_token = RefreshToken(
            token=security.hash_password(refresh_token_str),
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        db.add(new_refresh_token)
        await db.commit()

        log_audit("login_success", {"user_id": str(user_id)})
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token_str
        )

    @staticmethod
    async def refresh_tokens(db: AsyncSession, refresh_token: str) -> Token:
        """Generates new access and refresh tokens using a valid refresh token.

        Implements token rotation and revocation with hashed token validation.
        """
        try:
            payload = security.decode_token(refresh_token)
            if payload.get("type") != "refresh":
                raise ValueError("Invalid token type")
            user_id = payload.get("sub")
        except Exception:
            log_audit("token_refresh_failed", {"reason": "invalid_token"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        # We must fetch active tokens for this user and verify the hash
        # Since we can't query by hash (due to bcrypt salt), we query by user_id
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == uuid.UUID(user_id),
                RefreshToken.revoked == False
            )
        )
        db_tokens = result.scalars().all()

        target_token = None
        for db_t in db_tokens:
            if security.verify_password(refresh_token, db_t.token):
                target_token = db_t
                break

        if not target_token:
            log_audit("token_refresh_failed", {"user_id": user_id, "reason": "token_not_found_or_revoked"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token revoked or invalid"
            )

        # Revoke old token (Token Rotation)
        target_token.revoked = True
        
        # Create new tokens
        access_token = security.create_access_token(user_id)
        new_refresh_token_str = security.create_refresh_token(user_id)

        # Store new hashed refresh token
        new_db_token = RefreshToken(
            token=security.hash_password(new_refresh_token_str),
            user_id=uuid.UUID(user_id),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        db.add(new_db_token)
        await db.commit()

        log_audit("token_refreshed", {"user_id": user_id})

        return Token(
            access_token=access_token,
            refresh_token=new_refresh_token_str
        )

    @staticmethod
    async def logout(db: AsyncSession, refresh_token: str) -> None:
        """Revokes a refresh token to logout the user."""
        try:
            payload = security.decode_token(refresh_token)
            user_id = payload.get("sub")
        except Exception:
            log_audit("logout_attempt_invalid_token", {})
            return

        # Fetch active tokens for this user and verify hash
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == uuid.UUID(user_id),
                RefreshToken.revoked == False
            )
        )
        db_tokens = result.scalars().all()

        for db_t in db_tokens:
            if security.verify_password(refresh_token, db_t.token):
                db_t.revoked = True
                await db.commit()
                log_audit("logout", {"user_id": str(user_id)})
                return
        
        log_audit("logout_attempt_token_not_found", {"user_id": user_id})
