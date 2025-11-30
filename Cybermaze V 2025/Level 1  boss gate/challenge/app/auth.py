import hmac
import hashlib
import time

SECRET_KEY = b"arcade_secret_key_2024"

def generate_token(username: str, role: str) -> str:
    timestamp = str(int(time.time()))
    message = f"{username}:{role}:{timestamp}".encode()
    
    full_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    truncated_hmac = full_hmac[:2]
    
    token = message.hex() + truncated_hmac.hex()
    return token

def validate_token(token: str) -> dict:
    try:
        message_hex = token[:-4]
        provided_hmac = bytes.fromhex(token[-4:])
        
        message = bytes.fromhex(message_hex)
        
        full_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
        expected_hmac = full_hmac[:2]
        
        if not hmac.compare_digest(provided_hmac, expected_hmac):
            return None
        
        parts = message.decode().split(":")
        if len(parts) != 3:
            return None
        
        username, role, timestamp = parts
        
        if int(time.time()) - int(timestamp) > 3600:
            return None
        
        return {"username": username, "role": role}
    except:
        return None
