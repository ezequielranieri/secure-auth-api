import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.auth.database import Base


class RefreshToken(Base):
    """SQLAlchemy model for storing refresh tokens to allow revocation.

    Attributes:
        id: Unique identifier.
        jti: JWT ID for O(1) token lookup.
        user_id: Reference to the user who owns the token.
        expires_at: Expiration timestamp.
        revoked: Whether the token has been revoked.
        created_at: Creation timestamp.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    jti: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="refresh_tokens")
