import pyotp
import structlog
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import Depends

from src.auth.database import get_db
from src.auth.models.user import User
from src.auth.core import security


logger = structlog.get_logger(__name__)


def log_audit(event: str, detail: dict[str, Any]) -> None:
    """Logs a security audit event in a structured format."""
    detail_str = " | ".join(f"{k}={v}" for k, v in detail.items())
    logger.info(f"AUDITORIA | evento={event} | {detail_str}")


class TOTPService:
    """Business logic for TOTP 2FA operations."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def setup_totp(self, user: User) -> dict[str, str]:
        """Generates a new TOTP secret for the user.

        Args:
            user: The current authenticated user.

        Returns:
            A dict with 'uri' and 'secret' for QR code generation.

        Raises:
            HTTPException: If 2FA is already enabled.
        """
        if user.totp_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is already enabled"
            )

        secret = pyotp.random_base32()
        user.totp_secret = secret
        await self.db.commit()

        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="SecureAuthAPI"
        )

        log_audit("totp_setup_initiated", {"user_id": str(user.id)})
        return {"uri": uri, "secret": secret}

    async def verify_and_enable_totp(self, user: User, code: str) -> dict[str, str]:
        """Verifies a TOTP code and enables 2FA for the user.

        Args:
            user: The current authenticated user.
            code: The TOTP code from the authenticator app.

        Returns:
            A success message dict.

        Raises:
            HTTPException: If setup was not initiated or code is invalid.
        """
        if not user.totp_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA setup not initiated. Call /setup first."
            )

        if user.totp_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is already enabled"
            )

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code):
            log_audit("totp_verify_failed", {"user_id": str(user.id)})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid TOTP code"
            )

        user.totp_enabled = True
        await self.db.commit()

        log_audit("totp_enabled", {"user_id": str(user.id)})
        return {"message": "2FA enabled successfully"}

    async def disable_totp(self, user: User, code: str) -> dict[str, str]:
        """Disables 2FA for the user after verifying the TOTP code.

        Args:
            user: The current authenticated user.
            code: The TOTP code for confirmation.

        Returns:
            A success message dict.

        Raises:
            HTTPException: If 2FA is not enabled or code is invalid.
        """
        if not user.totp_enabled or not user.totp_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is not enabled"
            )

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code):
            log_audit("totp_disable_failed", {"user_id": str(user.id)})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid TOTP code"
            )

        user.totp_secret = None
        user.totp_enabled = False
        await self.db.commit()

        log_audit("totp_disabled", {"user_id": str(user.id)})
        return {"message": "2FA disabled successfully"}

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        """Verifies a TOTP code against a secret without DB access.

        Args:
            secret: The TOTP secret.
            code: The TOTP code to verify.

        Returns:
            True if valid, False otherwise.
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code)


def get_totp_service(db: AsyncSession = Depends(get_db)) -> TOTPService:
    """FastAPI dependency that provides a TOTPService instance."""
    return TOTPService(db)
