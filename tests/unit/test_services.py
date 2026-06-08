import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from src.auth.services.auth_service import AuthService
from src.auth.schemas.user import UserRegister, UserLogin
from src.auth.models.user import User
from src.auth.models.token import RefreshToken


@pytest.mark.asyncio
class TestAuthService:
    """Unit tests for AuthService."""

    def _make_service(self, db):
        """Helper to instantiate AuthService with a mock db."""
        return AuthService(db)

    async def test_register_user_success(self):
        """Should successfully register a new user."""
        db = AsyncMock()
        db.add = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        service = self._make_service(db)
        user_in = UserRegister(email="new@example.com", password="Password123")

        with patch("src.auth.core.security.hash_password", return_value="hashed"):
            user = await service.register_user(user_in)

        assert user.email == "new@example.com"
        db.add.assert_called_once()
        db.commit.assert_called_once()

    async def test_register_user_already_exists(self):
        """Should raise HTTPException if email already exists."""
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = MagicMock()
        db.execute.return_value = mock_result

        service = self._make_service(db)
        user_in = UserRegister(email="exists@example.com", password="Password123")

        with pytest.raises(HTTPException) as exc:
            await service.register_user(user_in)
        assert exc.value.status_code == 400

    async def test_login_user_success(self):
        """Should successfully login and return tokens."""
        db = AsyncMock()
        db.add = MagicMock()
        user_id = uuid.uuid4()
        user = User(
            id=user_id,
            email="test@example.com",
            hashed_password="hashed",
            is_active=True,
            failed_login_attempts=0
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db.execute.return_value = mock_result

        service = self._make_service(db)
        login_data = UserLogin(email="test@example.com", password="Password123")

        with patch("src.auth.core.security.verify_password", return_value=True), \
             patch("src.auth.core.security.create_access_token", return_value="access_token"), \
             patch("src.auth.core.security.create_refresh_token", return_value=("refresh_token", "test-jti")), \
             patch("src.auth.core.security.hash_password", return_value="hashed_refresh"):
            token = await service.login_user(login_data)

        assert token.access_token == "access_token"
        assert token.refresh_token == "refresh_token"
        assert user.failed_login_attempts == 0
        db.add.assert_called_once()

    async def test_login_user_not_found(self):
        """Should raise 401 if user does not exist."""
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute.return_value = mock_result

        service = self._make_service(db)
        login_data = UserLogin(email="ghost@example.com", password="Password123")

        with pytest.raises(HTTPException) as exc:
            await service.login_user(login_data)
        assert exc.value.status_code == 401

    async def test_login_user_locked(self):
        """Should raise 403 if account is locked."""
        db = AsyncMock()
        future_lock = datetime.now(timezone.utc) + timedelta(minutes=10)
        user = User(
            email="locked@example.com",
            hashed_password="hashed",
            is_active=True,
            locked_until=future_lock
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db.execute.return_value = mock_result

        service = self._make_service(db)
        login_data = UserLogin(email="locked@example.com", password="Password123")

        with pytest.raises(HTTPException) as exc:
            await service.login_user(login_data)
        assert exc.value.status_code == 403
        assert "locked" in exc.value.detail

    async def test_login_user_inactive(self):
        """Should raise 403 if account is inactive."""
        db = AsyncMock()
        user = User(
            email="inactive@example.com",
            hashed_password="hashed",
            is_active=False
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db.execute.return_value = mock_result

        service = self._make_service(db)
        login_data = UserLogin(email="inactive@example.com", password="Password123")

        with pytest.raises(HTTPException) as exc:
            await service.login_user(login_data)
        assert exc.value.status_code == 403

    async def test_login_user_brute_force_lock(self):
        """Should lock account after max failed attempts."""
        db = AsyncMock()
        db.add = MagicMock()
        user = User(
            id=uuid.uuid4(),
            email="brute@example.com",
            hashed_password="hashed",
            is_active=True,
            failed_login_attempts=4
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db.execute.return_value = mock_result

        service = self._make_service(db)
        login_data = UserLogin(email="brute@example.com", password="WrongPassword")

        with patch("src.auth.core.security.verify_password", return_value=False):
            with pytest.raises(HTTPException):
                await service.login_user(login_data)

        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
