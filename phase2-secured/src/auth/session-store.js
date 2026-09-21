// src/auth/session-store.js
// Single concern: creating, looking up, and destroying sessions. Nothing
// here knows about HTTP routing or what a request is "allowed" to do -
// that authorization decision belongs to middleware/require-auth.js.
"use strict";

const crypto = require("node:crypto");
const config = require("../config");

const sessions = new Map();
const SESSION_TTL_MS = config.sessionTtlMs;

function createSession(user) {
  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, {
    userId: user.id,
    username: user.username,
    role: user.role,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return sid;
}

function getSessionIdFromRequest(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tf_session=([a-f0-9]+)/);
  return match ? match[1] : null;
}

function getSession(req) {
  const sid = getSessionIdFromRequest(req);
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sid);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS; // sliding expiry
  return session;
}

function destroySession(req) {
  const sid = getSessionIdFromRequest(req);
  if (sid) sessions.delete(sid);
}

module.exports = { createSession, getSession, destroySession };
