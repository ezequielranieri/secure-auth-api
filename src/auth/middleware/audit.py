import time
import uuid
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


logger = structlog.get_logger("middleware.audit")


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Middleware to log every security-relevant or state-changing request.
    
    Logs method, path, status code, client IP, and processing time.
    """
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # We generally want to audit POST, PUT, DELETE, and sensitive GETs
        # For simplicity in this secure-auth-api, we'll log all requests to /api/v1/
        
        start_time = time.perf_counter()
        
        response = await call_next(request)
        
        process_time = time.perf_counter() - start_time
        
        # Only log API requests to avoid noise from health checks or docs
        if request.url.path.startswith("/api/v1/"):
            client_ip = request.client.host if request.client else "unknown"
            request_id = request.headers.get("X-Request-ID", "none")
            
            logger.info(
                "request_audit",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                client_ip=client_ip,
                duration=f"{process_time:.4f}s",
                request_id=request_id
            )
            
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to ensure every request has a unique ID for log correlation."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # Set request_id in request state for downstream use
        request.state.request_id = request_id
        
        response = await call_next(request)
        
        # Ensure the response also carries the request ID
        response.headers["X-Request-ID"] = request_id
        
        return response
