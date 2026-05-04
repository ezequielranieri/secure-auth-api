import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.auth.database import Base


class RefreshToken(Base):
    """SQLAlchemy model for storing refresh tokens to allow revocation.

    Attributes:
        id: Unique identifier.
        token: The refresh token string.
        user_id: Reference to the user who owns the token.
        expires_at: Expiration timestamp.
        revoked: Whether the token has been revoked.
        created_at: Creation timestamp.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    token: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="refresh_tokens")


# Update User model to include relationship (I'll do this in a separate replace call if needed, 
# but I'll add it here for completeness if I were writing the file)
