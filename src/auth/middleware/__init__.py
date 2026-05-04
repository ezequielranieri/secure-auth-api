import structlog
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


logger = structlog.get_logger("middleware.error")


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware to catch unhandled exceptions and return a consistent error format.
    
    Prevents leaking internal database errors or tracebacks to the client.
    """
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            request_id = getattr(request.state, "request_id", "unknown")
            
            # Log the full exception internally
            logger.exception(
                "unhandled_exception",
                path=request.url.path,
                request_id=request_id,
                error=str(exc)
            )
            
            # Return a generic safe response to the client
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "Internal server error",
                    "code": "INTERNAL_ERROR",
                    "request_id": request_id
                }
            )
