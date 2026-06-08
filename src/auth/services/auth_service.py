import uuid
import structlog
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends, HTTPException, status

from src.auth.config import settings
from src.auth.database import get_db
from src.auth.models.user import User
from src.auth.models.token import RefreshToken
from src.auth.schemas.user import UserRegister, UserLogin
from src.auth.schemas.token import Token
from src.auth.schemas.totp import LoginResponse
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

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def register_user(self, user_in: UserRegister) -> User:
        """Registers a new user in the system.

        Args:
            user_in: Registration data.

        Returns:
            The created User.

        Raises:
            HTTPException: If the email is already registered.
        """
        # Check if user exists
        result = await self.db.execute(select(User).where(User.email == user_in.email))
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
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)

        log_audit("user_registered", {"user_id": str(new_user.id), "email": new_user.email})
        return new_user

    async def login_user(self, login_data: UserLogin) -> LoginResponse:
        """Authenticates a user and generates tokens.

        Implements brute force protection and audit logging.

        Args:
            login_data: Login credentials.

        Returns:
            A Token schema containing access and refresh tokens.

        Raises:
            HTTPException: For invalid credentials, locked accounts, or inactive users.
        """
        result = await self.db.execute(select(User).where(User.email == login_data.email))
        user = result.scalar_one_or_none()

        if not user:
            log_audit("login_failed", {"email": login_data.email, "reason": "user_not_found"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if account is locked
        if user.locked_until:
            # Handle potential naive datetime from some DBs like SQLite
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            
            if locked_until > datetime.now(timezone.utc):
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
            
            await self.db.commit()
            log_audit("login_failed", {"user_id": str(user.id), "reason": "invalid_password"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Successful login
        user.failed_login_attempts = 0
        user.locked_until = None

        user_id = user.id  # Capture ID before commit
        # Capture 2FA status before commit to avoid MissingGreenlet after session expires
        is_2fa_enabled = user.totp_enabled and user.totp_secret

        await self.db.commit()

        # If 2FA is enabled, return a temporary token instead of full tokens
        if is_2fa_enabled:
            temp_token = security.create_temp_token(str(user_id))
            log_audit("login_2fa_required", {"user_id": str(user_id)})
            return LoginResponse(two_fa_required=True, temp_token=temp_token)

        access_token = security.create_access_token(user_id)
        refresh_token_str, refresh_jti = security.create_refresh_token(user_id)

        new_refresh_token = RefreshToken(
            jti=refresh_jti,
            token=security.hash_password(refresh_token_str),
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        self.db.add(new_refresh_token)
        await self.db.commit()

        log_audit("login_success", {"user_id": str(user_id)})

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token_str
        )

    async def complete_2fa_login(self, temp_token: str, code: str) -> LoginResponse:
        """Completes login for users with 2FA enabled.

        Args:
            temp_token: The temporary token from the first login step.
            code: The TOTP code from the authenticator app.

        Returns:
            A LoginResponse with full access and refresh tokens.

        Raises:
            HTTPException: If temp token is invalid or TOTP code is wrong.
        """
        import uuid as uuid_module
        from src.auth.services.totp_service import TOTPService
        from src.auth.core.security import decode_temp_token

        payload = decode_temp_token(temp_token)
        user_id = payload.get("sub")

        result = await self.db.execute(
            select(User).where(User.id == uuid_module.UUID(user_id))
        )
        user = result.scalar_one_or_none()

        if not user or not user.totp_enabled or not user.totp_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid request"
            )

        if not TOTPService.verify_code(user.totp_secret, code):
            log_audit("2fa_login_failed", {"user_id": user_id, "reason": "invalid_totp"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )

        access_token = security.create_access_token(user_id)
        refresh_token_str, refresh_jti = security.create_refresh_token(user_id)

        new_refresh_token = RefreshToken(
            jti=refresh_jti,
            token=security.hash_password(refresh_token_str),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        self.db.add(new_refresh_token)
        await self.db.commit()

        log_audit("2fa_login_success", {"user_id": user_id})

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token_str
        )

    async def refresh_tokens(self, refresh_token: str) -> Token:
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

        jti = payload.get("jti")
        if not jti:
            log_audit("token_refresh_failed", {"reason": "missing_jti"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.jti == jti,
                RefreshToken.revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc)
            )
        )
        target_token = result.scalar_one_or_none()

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
        new_refresh_token_str, new_jti = security.create_refresh_token(user_id)

        # Store new hashed refresh token
        new_db_token = RefreshToken(
            jti=new_jti,
            token=security.hash_password(new_refresh_token_str),
            user_id=uuid.UUID(user_id),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        self.db.add(new_db_token)
        await self.db.commit()

        log_audit("token_refreshed", {"user_id": user_id})

        return Token(
            access_token=access_token,
            refresh_token=new_refresh_token_str
        )

    async def logout(self, refresh_token: str) -> None:
        """Revokes a refresh token to logout the user."""
        try:
            payload = security.decode_token(refresh_token)
            user_id = payload.get("sub")
        except Exception:
            log_audit("logout_attempt_invalid_token", {})
            return

        jti = payload.get("jti")
        if not jti:
            log_audit("logout_attempt_invalid_token", {})
            return

        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.jti == jti,
                RefreshToken.revoked == False
            )
        )
        db_token = result.scalar_one_or_none()

        if db_token:
            db_token.revoked = True
            await self.db.commit()
            log_audit("logout", {"user_id": str(user_id)})
            return
        
        log_audit("logout_attempt_token_not_found", {"user_id": user_id})


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    """FastAPI dependency that provides an AuthService instance.

    Args:
        db: Database session injected by FastAPI.

    Returns:
        An AuthService instance bound to the current session.
    """
    return AuthService(db)
