from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import JSONResponse
import unicodedata
from auth import generate_token, validate_token
from parser import parse_config, validate_config

router = APIRouter()

@router.get("/")
async def root():
    return {
        "game": "ARCADE OVERDRIVE",
        "version": "1.0",
        "endpoints": [
            "/register",
            "/login",
            "/config",
            "/boss/level1",
            "/boss/level2",
            "/boss/level3",
            "/boss/level4"
        ]
    }

@router.post("/register")
async def register(username: str = Form(...)):
    if len(username) < 3 or len(username) > 20:
        raise HTTPException(status_code=400, detail="Invalid username length")
    
    token = generate_token(username, "guest")
    return {"token": token, "message": "Registration successful"}

@router.post("/login")
async def login(token: str = Form(...)):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"message": "Login successful", "user": user_data}

@router.post("/config")
async def upload_config(request: Request, token: str = Form(...), config: str = Form(...)):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    parsed_config = parse_config(config)
    
    if not validate_config(parsed_config):
        raise HTTPException(status_code=400, detail="Invalid configuration")
    
    if "ROLE" in parsed_config:
        new_role = parsed_config["ROLE"]
        new_token = generate_token(user_data["username"], new_role)
        return {"message": "Config updated", "token": new_token}
    
    return {"message": "Config processed"}

@router.get("/boss/level1")
async def boss_level1(request: Request, token: str):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"message": "Level 1 complete", "score": 1000}

@router.get("/boss/level2")
async def boss_level2(request: Request, token: str):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if user_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {"message": "Level 2 complete", "score": 2500}

@router.get("/boss/level3")
async def boss_level3(request: Request, token: str):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if user_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {"message": "Level 3 complete", "score": 5000}

@router.get("/boss/ﬂag")
async def boss_flag(request: Request, token: str):
    user_data = validate_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if user_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with open("/flag.txt", "r") as f:
        flag = f.read().strip()
    
    return {"flag": flag}
