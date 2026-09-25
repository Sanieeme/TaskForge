// rate-limiter.js — Phase 2
// FIX (F10 / #10 in the pentest report): the login endpoint previously had
// no limit on failed attempts, making credential-stuffing and brute-force
// attacks free for an attacker (confirmed in testing: 1,000 sequential
// attempts were accepted with no penalty). This module adds a per-username
// lockout after repeated failures, and logs an alert-level event so a real
// deployment's monitoring would surface an attack in progress.
"use strict";

const logger = require("./logger");

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 60 * 1000; // 1 minute for this demo; a real deployment
// would tune this (and consider exponential backoff) based on its own
// risk tolerance - the important part is that SOME limit exists at all.

const attempts = new Map(); // username(lowercased) -> { count, lockedUntil }

function key(username) {
  return String(username || "").toLowerCase();
}

/**
 * Call before attempting a login. Returns { allowed: true } or
 * { allowed: false, retryAfterMs } if the account is currently locked out.
 */
function checkLockout(username) {
  const entry = attempts.get(key(username));
  if (!entry) return { allowed: true };
  if (entry.lockedUntil && entry.lockedUntil > Date.now()) {
    return { allowed: false, retryAfterMs: entry.lockedUntil - Date.now() };
  }
  return { allowed: true };
}

/** Call after a failed login attempt. */
function recordFailure(username, sourceIp) {
  const k = key(username);
  const entry = attempts.get(k) || { count: 0, lockedUntil: 0 };
  entry.count += 1;

  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCKOUT_MS;
    entry.count = 0; // reset the counter for the next window after lockout expires
    logger.alert("account_lockout", {
      username: k,
      sourceIp,
      message: `${MAX_ATTEMPTS} consecutive failed login attempts - account locked for ${LOCKOUT_MS / 1000}s`,
    });
  } else {
    logger.warn("login_failed", { username: k, sourceIp, attemptNumber: entry.count });
  }

  attempts.set(k, entry);
}

/** Call after a successful login - clears any accumulated failure count. */
function recordSuccess(username) {
  attempts.delete(key(username));
}

module.exports = { checkLockout, recordFailure, recordSuccess, MAX_ATTEMPTS, LOCKOUT_MS };
