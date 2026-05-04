from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration settings for the application.

    Attributes:
        app_name: The name of the application.
        debug: Flag to enable/disable debug mode.
        secret_key: Secret key for JWT signing.
        algorithm: Algorithm used for JWT signing.
        access_token_expire_minutes: Expiration time for access tokens.
        refresh_token_expire_days: Expiration time for refresh tokens.
        database_url: Connection string for the database.
        max_failed_login_attempts: Maximum number of failed login attempts before lockout.
        lockout_duration_minutes: Duration of account lockout in minutes.
    """

    app_name: str = "secure-auth-api"
    debug: bool = False

    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = "sqlite+aiosqlite:///./auth.db"

    # Brute force protection
    max_failed_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)


settings = Settings()
