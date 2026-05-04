from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from src.auth.config import settings
from src.auth.core.rate_limit import limiter


from src.auth.routers import auth, users
from src.auth.middleware.audit import AuditLogMiddleware, RequestIDMiddleware
from src.auth.middleware import ErrorHandlingMiddleware


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Secure Authentication REST API",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

# Set up rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register Middleware (Bottom to top execution for 'dispatch' style)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(RequestIDMiddleware)

# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        A dictionary with the status.
    """
    return {"status": "ok", "app_name": settings.app_name}


@app.get("/api/v1/")
async def root() -> dict[str, str]:
    """Root endpoint for API v1.

    Returns:
        A welcome message.
    """
    return {"message": "Welcome to Secure Auth API v1"}
