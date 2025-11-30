from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import time
from routes import router
from waf import waf_middleware

app = FastAPI()

rate_limit_store = {}

@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else request.client.host
    
    current_time = time.time()
    
    if client_ip in rate_limit_store:
        last_request, count = rate_limit_store[client_ip]
        if current_time - last_request < 60:
            if count >= 10:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )
            rate_limit_store[client_ip] = (last_request, count + 1)
        else:
            rate_limit_store[client_ip] = (current_time, 1)
    else:
        rate_limit_store[client_ip] = (current_time, 1)
    
    response = await call_next(request)
    return response

@app.middleware("http")
async def waf_check(request: Request, call_next):
    return await waf_middleware(request, call_next)

app.include_router(router)

@app.get("/health")
async def health():
    return {"status": "ok"}
