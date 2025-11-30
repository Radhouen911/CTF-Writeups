require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "arcade1";
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb://admin:R0b0M4st3rS3cur3Passw0rd2024xYz@localhost:27017/robobook?authSource=admin";

// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(express.static("public"));

// Rate limiting (per-session/browser implementation)
const rateLimitStore = new Map();
const crypto = require("crypto");

const rateLimit = (maxRequests, windowMs) => {
  return (req, res, next) => {
    // Use session ID from cookie, or create one if it doesn't exist
    let sessionId = req.cookies.session_id;

    if (!sessionId) {
      // Generate unique session ID for this browser
      sessionId = crypto.randomBytes(16).toString("hex");
      res.cookie("session_id", sessionId, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: "lax",
      });
    }

    // Combine session ID with IP for extra security
    const identifier = `${sessionId}_${req.ip || req.connection.remoteAddress}`;

    const now = Date.now();
    const windowStart = now - windowMs;

    if (!rateLimitStore.has(identifier)) {
      rateLimitStore.set(identifier, []);
    }

    const requests = rateLimitStore
      .get(identifier)
      .filter((time) => time > windowStart);

    if (requests.length >= maxRequests) {
      return res.status(429).json({
        error: "Too many requests. Please try again later.",
        retry_after: Math.ceil((requests[0] + windowMs - now) / 1000),
      });
    }

    requests.push(now);
    rateLimitStore.set(identifier, requests);
    next();
  };
};

// MongoDB connection
let db;
MongoClient.connect(MONGODB_URI)
  .then((client) => {
    db = client.db("robobook");
    console.log("✅ Connected to MongoDB");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Middleware to verify JWT (but intentionally weak)
const authenticateToken = (req, res, next) => {
  // Check for token in cookie first, then fall back to Authorization header
  let token = req.cookies.token;

  if (!token) {
    const authHeader = req.headers["authorization"];
    token = authHeader && authHeader.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    // Intentionally weak: doesn't properly validate signature
    const decoded = jwt.decode(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
};

// Middleware to check role (intentionally bypassable for engineer, but not admin)
const requireRole = (role) => {
  return async (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      if (role === "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }
      if (role === "engineer") {
        return res.status(403).json({
          error:
            "Engineer access required. Only engineers can access this feature.",
        });
      }
      return res.status(403).json({ error: `${role} access required` });
    }

    // For admin role, verify against database (prevent JWT forgery bypass)
    if (role === "admin") {
      try {
        const user = await db
          .collection("users")
          .findOne({ _id: req.user.user_id });
        if (!user || user.role !== "admin") {
          return res.status(403).json({
            error:
              "Admin access denied. Your role has been verified against the database.",
            hint: "Admin access requires proper authentication through 2FA.",
          });
        }
      } catch (err) {
        return res.status(500).json({ error: "Role verification failed" });
      }
    }

    next();
  };
};

// ============================================
// STAGE 1: NoSQL Injection - Login Endpoint
// ============================================
app.post("/api/auth/login", rateLimit(10, 60000), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate username is a string (prevent NoSQL injection on username)
    if (
      typeof username !== "string" ||
      username.length === 0 ||
      username.length > 50
    ) {
      return res.status(400).json({ error: "Invalid username format" });
    }

    // Block objects in username field
    if (typeof username === "object") {
      return res.status(400).json({ error: "Invalid username format" });
    }

    // VULNERABILITY: NoSQL Injection on password field only
    // Username is validated, but password field is vulnerable
    const user = await db.collection("users").findOne({
      username: username,
      password_hash: password,
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if 2FA is enabled
    if (user.totp_enabled) {
      // Generate temporary session ID for 2FA
      const sessionId = Math.random().toString(36).substring(7);
      return res.json({
        requires_2fa: true,
        session_id: sessionId,
        user_id: user._id,
        message: "2FA required. Use /api/auth/verify-2fa",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: user._id,
        username: user.username,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set token as HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: "lax",
    });

    res.json({
      success: true,
      token: token, // Also send in response for compatibility
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        badge: user.badge,
      },
      message: "Login successful!",
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Register endpoint
app.post("/api/auth/register", rateLimit(5, 60000), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields required" });
    }

    // Validate all fields are strings (prevent NoSQL injection)
    if (
      typeof username !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "Invalid input format" });
    }

    // Validate username format
    if (username.length < 3 || username.length > 20) {
      return res
        .status(400)
        .json({ error: "Username must be 3-20 characters" });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });
    }

    // Check if user exists - safe query with validated strings
    const existing = await db.collection("users").findOne({
      $or: [{ username: username }, { email: email }],
    });

    if (existing) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    // Hash password properly for new users (unlike Wily's MD5)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Get next user ID
    const lastUser = await db
      .collection("users")
      .find()
      .sort({ _id: -1 })
      .limit(1)
      .toArray();
    const nextId = lastUser.length > 0 ? lastUser[0]._id + 1 : 10;

    const newUser = {
      _id: nextId,
      username,
      email,
      bio: "New RoboBook user 🤖",
      password_hash: hashedPassword,
      role: "technician",
      badge: "🔨 Technician",
      totp_enabled: false,
      created_at: new Date(),
    };

    await db.collection("users").insertOne(newUser);

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: newUser._id,
        username: newUser.username,
        role: newUser.role,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set token as HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "lax",
    });

    res.json({
      success: true,
      token: token,
      user: {
        id: newUser._id,
        username: newUser.username,
        role: newUser.role,
        badge: newUser.badge,
      },
      message: "Registration successful!",
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// STAGE 5: 2FA Bypass with Backup Codes
// ============================================
app.post("/api/auth/verify-2fa", rateLimit(5, 60000), async (req, res) => {
  try {
    const { user_id, code, backup_code } = req.body;

    // Validate user_id is provided and is a number
    if (!user_id || isNaN(parseInt(user_id))) {
      return res.status(400).json({ error: "Valid user_id required" });
    }

    const user = await db
      .collection("users")
      .findOne({ _id: parseInt(user_id) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure user actually has 2FA enabled (prevent bypassing login flow)
    if (!user.totp_enabled) {
      return res.status(400).json({
        error: "2FA is not enabled for this account",
        hint: "You must login through the normal flow first",
      });
    }

    // Validate code and backup_code are strings if provided
    if (code && typeof code !== "string") {
      return res.status(400).json({ error: "Invalid code format" });
    }
    if (backup_code && typeof backup_code !== "string") {
      return res.status(400).json({ error: "Invalid backup code format" });
    }

    let isValid = false;

    // Check backup code first (VULNERABILITY: Backup codes bypass 2FA)
    if (
      backup_code &&
      typeof backup_code === "string" &&
      user.backup_codes &&
      user.backup_codes.includes(backup_code)
    ) {
      isValid = true;
      // VULNERABILITY: Backup codes are NOT removed after use (reusable)
      // In a real system, you would remove the used code:
      // await db.collection("users").updateOne(
      //   { _id: user._id },
      //   { $pull: { backup_codes: backup_code } }
      // );
    }
    // Check TOTP code
    else if (code && typeof code === "string" && user.totp_secret) {
      isValid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: "base32",
        token: code,
        window: 2,
      });
    }

    if (!isValid) {
      return res.status(401).json({ error: "Invalid 2FA code" });
    }

    // Generate JWT token with admin access
    const token = jwt.sign(
      {
        user_id: user._id,
        username: user.username,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set token as HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "lax",
    });

    // Return second flag fragment for admin users
    const response = {
      success: true,
      token: token,
      role: user.role,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        badge: user.badge,
      },
      message: `Welcome, ${user.username}. Admin access granted.`,
    };

    if (user.role === "admin") {
      response.flag_fragment_2 = "wily_defeated_20XX_f3a8c5d9}";
      response.arcade_message = "🎮 LEVEL COMPLETE! 🎮";
      response.achievement = "⭐ ADMIN ACCESS UNLOCKED ⭐";
      response.hint = "Navigate to /admin.html to complete your mission!";
      response.next_stage =
        "Head to the Admin Panel to submit the Master Override Code";
    }

    res.json(response);
  } catch (err) {
    console.error("2FA verification error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// STAGE 2: IDOR - User Profile Endpoint
// ============================================
app.get("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // VULNERABILITY: No authorization check - IDOR
    const user = await db.collection("users").findOne({ _id: userId });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return user data including sensitive info
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      bio: user.bio,
      role: user.role,
      badge: user.badge,
      password_hash: user.password_hash, // VULNERABILITY: Exposing password hash
      totp_enabled: user.totp_enabled,
      created_at: user.created_at,
    });
  } catch (err) {
    console.error("User fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// STAGE 2: IDOR - User Messages Endpoint
// ============================================
app.get("/api/users/:id/messages", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // VULNERABILITY: No authorization check - IDOR
    const messages = await db
      .collection("messages")
      .find({
        $or: [{ to_user_id: userId }, { from_user_id: userId }],
      })
      .toArray();

    res.json({ messages });
  } catch (err) {
    console.error("Messages fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get user posts - Mock data only
app.get("/api/users/:id/posts", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // Only return pre-seeded posts (IDs 1-10)
    const posts = await db
      .collection("posts")
      .find({ user_id: userId, _id: { $lte: 10 } })
      .sort({ timestamp: -1 })
      .toArray();

    res.json({ posts });
  } catch (err) {
    console.error("Posts fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all posts (feed) - Mock data only
app.get("/api/posts", async (req, res) => {
  try {
    // Only return the pre-seeded posts (IDs 1-10)
    const posts = await db
      .collection("posts")
      .find({ _id: { $lte: 10 }, visibility: "public" })
      .sort({ timestamp: -1 })
      .toArray();

    res.json({ posts });
  } catch (err) {
    console.error("Feed fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create new post - DISABLED (Mock data only)
app.post(
  "/api/posts",
  authenticateToken,
  rateLimit(20, 60000),
  async (req, res) => {
    // Posting is disabled - this is a read-only feed for CTF purposes
    return res.status(403).json({
      error: "Posting is temporarily disabled",
      message: "The feed is in read-only mode. Focus on the investigation! 🔍",
      hint: "Check out the existing posts for clues about the system...",
    });
  }
);

// Get single post
app.get("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);

    const post = await db.collection("posts").findOne({ _id: postId });

    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    res.json(post);
  } catch (err) {
    console.error("Post fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================
// STAGE 4: RCE - Diagnostics Endpoint
// ============================================
app.post(
  "/api/diagnostics/ping",
  authenticateToken,
  requireRole("engineer"),
  rateLimit(10, 60000), // Reduced from 50 to 10 requests per minute
  async (req, res) => {
    try {
      const { target } = req.body;

      if (!target) {
        return res.status(400).json({ error: "Target IP required" });
      }

      // Security: Whitelist approach - only allow specific commands
      // Allowed: ping, ls, base64, tac, diff, rev
      const allowedCommands = ["ping", "ls", "base64", "tac", "diff", "rev"];
      const targetLower = target.toLowerCase();

      // Extract the command being used (first word after semicolon if present)
      let commandUsed = target.trim().split(/[\s;]+/)[0];
      if (target.includes(";")) {
        const afterSemicolon = target.split(";")[1];
        if (afterSemicolon) {
          commandUsed = afterSemicolon.trim().split(/\s+/)[0];
        }
      }

      // Check if any allowed command is present
      const hasAllowedCommand = allowedCommands.some((cmd) =>
        targetLower.includes(cmd)
      );

      // Block dangerous commands - check for word boundaries
      const dangerousCommands = [
        "rm",
        "del",
        "erase",
        "dd",
        "mkfs",
        "wget",
        "curl",
        "nc",
        "netcat",
        "bash",
        "sh",
        "cmd",
        "powershell",
        "pwsh",
        "python",
        "node",
        "perl",
        "ruby",
        "chmod",
        "chown",
        "sudo",
        "su",
        "cat",
        "more",
        "less",
        "head",
        "tail",
        "grep",
        "find",
        "awk",
        "sed",
        "cp",
        "mv",
        "ln",
        "cut",
        "paste",
        "sort",
        "uniq",
        "nl",
        "pr",
        "wc",
      ];

      // Extract commands from the target (after semicolon if present)
      const commandParts = target.split(";");
      for (const part of commandParts) {
        const cmd = part.trim().split(/\s+/)[0].toLowerCase();
        if (dangerousCommands.includes(cmd)) {
          return res.status(400).json({
            error: `${cmd} is not allowed`,
          });
        }
      }

      // Limit command length
      if (target.length > 500) {
        return res.status(400).json({ error: "Command too long" });
      }

      // Block certain operators (but allow semicolon for command chaining)
      if (
        target.includes("|") ||
        target.includes("&") ||
        target.includes(">") ||
        target.includes("<") ||
        target.includes("`") ||
        target.includes("$(")
      ) {
        return res
          .status(400)
          .json({ error: "Dangerous operators detected and blocked" });
      }

      // VULNERABILITY: Command injection via semicolon
      // Players can chain commands like: 8.8.8.8; ls secrets
      exec(
        `ping -c 2 ${target}`,
        { timeout: 5000, cwd: __dirname },
        (error, stdout, stderr) => {
          if (error) {
            // Check if it's a "command not found" error
            const errorOutput = stderr || error.message || "";
            const fullOutput =
              (stdout || "") +
              " " +
              (stderr || "") +
              " " +
              (error.message || "");

            // Check for command not found errors
            if (
              fullOutput.includes("not found") ||
              fullOutput.includes("No such file") ||
              fullOutput.includes("executable") ||
              fullOutput.includes("command not found") ||
              errorOutput.includes("sh:")
            ) {
              return res.json({
                success: false,
                output:
                  "❌ cat is not allowed\n\n💡 Hint: Try thinking of alternative ways to read files...\n\nAllowed commands: ping, ls, base64, tac, diff, rev",
                message: "Command not allowed",
              });
            }

            // Return the actual error for debugging
            return res.json({
              success: false,
              output: errorOutput || fullOutput || "Command execution failed",
              message: "Command execution failed",
            });
          }

          // Success - return output
          res.json({
            success: true,
            output: stdout || "Command completed successfully",
            message: "Diagnostics completed",
          });
        }
      );
    } catch (err) {
      console.error("Diagnostics error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ============================================
// FINAL STAGE: Master Override
// ============================================
app.post(
  "/api/admin/override",
  authenticateToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { override_code } = req.body;

      const correctCode = "CM{master_override_wily_defeated_20XX_f3a8c5d9}";

      if (override_code === correctCode) {
        res.json({
          success: true,
          message:
            "🎉 MASTER OVERRIDE ACCEPTED! All Robot Masters have been shut down.",
          flag: correctCode,
          congratulations:
            "You saved the city! Dr. Light thanks you, hero of 20XX!",
          stats: {
            stages_completed: 5,
            fragments_collected: 2,
            exploit_chain: [
              "NoSQL Injection",
              "IDOR",
              "JWT Manipulation",
              "RCE",
              "2FA Bypass",
            ],
          },
        });
      } else {
        res.status(400).json({
          error: "Invalid override code",
          hint: "Did you collect both flag fragments?",
        });
      }
    } catch (err) {
      console.error("Override error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Logout endpoint
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true, message: "Logged out successfully" });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "RoboBook is running!" });
});

// Start server
app.listen(PORT, () => {
  console.log(`🤖 RoboBook server running on port ${PORT}`);
  console.log(`🌐 Access at: http://localhost:${PORT}`);
});
