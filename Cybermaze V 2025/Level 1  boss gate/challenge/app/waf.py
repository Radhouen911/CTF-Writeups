from fastapi import Request
from fastapi.responses import JSONResponse
import unicodedata

BLOCKED_PATHS = [
    "/boss/flag", 
    "/admin",
    "/secret",
    "/../",
    "/./",
]

async def waf_middleware(request: Request, call_next):
    path = request.url.path
    
    normalized_path = unicodedata.normalize("NFC", path)
    
    for blocked in BLOCKED_PATHS:
        if blocked in normalized_path:
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied by WAF"}
            )
    
    response = await call_next(request)
    return response
