def parse_config(config_text: str) -> dict:
    config = {}
    lines = config_text.strip().split("\n")
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            
            config[key] = value
    
    return config

def validate_config(config: dict) -> bool:
    allowed_keys = ["USERNAME", "ROLE", "THEME", "DIFFICULTY"]
    allowed_roles = ["guest", "user", "admin"]
    
    for key in config:
        if key not in allowed_keys:
            return False
    
    if "ROLE" in config:
        if config["ROLE"] not in allowed_roles:
            return False
    
    return True
