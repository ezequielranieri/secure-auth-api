import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestAuthRoutes:
    """Integration tests for authentication routes."""

    async def test_register_and_login_success(self, client: AsyncClient):
        """Should successfully register and then login."""
        # 1. Register
        reg_data = {"email": "integration@example.com", "password": "Password123"}
        response = await client.post("/api/v1/auth/register", json=reg_data)
        assert response.status_code == 201
        assert response.json()["email"] == reg_data["email"]

        # 2. Login
        login_data = {"email": "integration@example.com", "password": "Password123"}
        response = await client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        tokens = response.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens

    async def test_login_invalid_credentials(self, client: AsyncClient):
        """Should return 401 for wrong credentials."""
        login_data = {"email": "wrong@example.com", "password": "WrongPassword123"}
        response = await client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401

    async def test_protected_me_route(self, client: AsyncClient):
        """Should allow access to /me with valid token."""
        # Setup: Register and Login
        reg_data = {"email": "me@example.com", "password": "Password123"}
        await client.post("/api/v1/auth/register", json=reg_data)
        
        login_response = await client.post("/api/v1/auth/login", json=reg_data)
        access_token = login_response.json()["access_token"]

        # Access /me
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await client.get("/api/v1/users/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["email"] == reg_data["email"]

    async def test_me_route_no_token(self, client: AsyncClient):
        """Should return 401 if no token is provided."""
        response = await client.get("/api/v1/users/me")
        assert response.status_code == 401
