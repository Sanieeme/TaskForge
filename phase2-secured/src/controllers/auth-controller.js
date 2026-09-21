// src/controllers/auth-controller.js
// Owns exactly the auth-related HTTP endpoints. Delegates every concern it
// doesn't own: hashing to password-utils, validation to validators,
// sessions to session-store, lockout logic to rate-limiter, and audit
// recording to audit-service.
"use strict";

const db = require("../db");
const { sendJSON } = require("../http/response");
const { readBody } = require("../http/request-body");
const { hashPassword, verifyPassword } = require("../auth/password-utils");
const { isValidUsername, isValidPassword, isValidRole } = require("../validation/validators");
const { createSession, destroySession } = require("../auth/session-store");
const { requireAuth } = require("../middleware/require-auth");
const rateLimiter = require("../rate-limiter");
const { logAudit } = require("../services/audit-service");

async function register(req, res) {
  const { username, password, role } = await readBody(req);

  // FIX (#10 no validation) + (#4 client-controlled role)
  if (!isValidUsername(username)) {
    return sendJSON(res, 400, { error: "username must be 3-32 chars, letters/numbers/underscore only" });
  }
  if (!isValidPassword(password)) {
    return sendJSON(res, 400, { error: "password must be at least 8 characters" });
  }
  // FIX (#4 privilege escalation on register): self-registration can ONLY
  // ever create an 'employee'. Promotion requires a separate admin action.
  if (role !== undefined && !isValidRole(role)) {
    return sendJSON(res, 400, { error: "self-registration is only permitted as 'employee'" });
  }

  const { hash, salt } = hashPassword(password);
  try {
    db.prepare(
      "INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, 'employee')"
    ).run(username, hash, salt);
    sendJSON(res, 201, { message: "registered" });
  } catch (e) {
    sendJSON(res, 409, { error: "username already exists" });
  }
}

async function login(req, res) {
  const { username, password } = await readBody(req);
  if (!username || !password) {
    return sendJSON(res, 400, { error: "username and password required" });
  }

  // FIX (F10 rate limiting): reject before ever touching the database if
  // this account is currently locked out from repeated recent failures.
  const sourceIp = req.socket.remoteAddress;
  const lockout = rateLimiter.checkLockout(username);
  if (!lockout.allowed) {
    res.setHeader("Retry-After", Math.ceil(lockout.retryAfterMs / 1000));
    return sendJSON(res, 429, {
      error: `too many failed login attempts - try again in ${Math.ceil(lockout.retryAfterMs / 1000)}s`,
    });
  }

  // FIX (#2 SQL Injection): parameterised query, never string concatenation.
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // FIX: generic error + always-run verifyPassword (even against a dummy
  // hash for a nonexistent user) to reduce username-enumeration via timing.
  const dummySalt = "0".repeat(32);
  const dummyHash = "0".repeat(128);
  const ok = user
    ? verifyPassword(password, user.password_hash, user.password_salt)
    : verifyPassword(password, dummyHash, dummySalt);

  if (!user || !ok) {
    rateLimiter.recordFailure(username, sourceIp);
    return sendJSON(res, 401, { error: "invalid username or password" });
  }

  rateLimiter.recordSuccess(username);
  logAudit({
    actorId: user.id,
    actorUsername: user.username,
    action: "login",
    targetType: "session",
    targetId: null,
    detail: `login from ${sourceIp}`,
  });

  const sid = createSession(user);

  // FIX (#8 cookie missing security flags): HttpOnly + SameSite=Lax.
  res.setHeader("Set-Cookie", `tf_session=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800`);
  sendJSON(res, 200, { message: "logged in", role: user.role, username: user.username });
}

function logout(req, res) {
  destroySession(req);
  res.setHeader("Set-Cookie", "tf_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  sendJSON(res, 200, { message: "logged out" });
}

function me(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  sendJSON(res, 200, { userId: session.userId, username: session.username, role: session.role });
}

module.exports = { register, login, logout, me };
