// auth-utils.js — Phase 2 (secured)
// Password hashing helpers. Uses Node's built-in scrypt (no external deps).
"use strict";

const crypto = require("node:crypto");

const SCRYPT_KEYLEN = 64;

function hashPassword(plainPassword) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(plainPassword, salt, SCRYPT_KEYLEN).toString("hex");
  return { hash, salt };
}

function verifyPassword(plainPassword, storedHash, storedSalt) {
  const candidateHash = crypto.scryptSync(plainPassword, storedSalt, SCRYPT_KEYLEN);
  const storedBuf = Buffer.from(storedHash, "hex");
  // Constant-time comparison to avoid timing attacks.
  if (candidateHash.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(candidateHash, storedBuf);
}

// Basic reusable input validators (FIX for Phase 1's "no validation" issues).
function isValidUsername(u) {
  return typeof u === "string" && /^[a-zA-Z0-9_]{3,32}$/.test(u);
}

function isValidPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 200;
}

function isValidRole(r) {
  return r === "employee"; // self-registration can only ever create employees
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = {
  hashPassword,
  verifyPassword,
  isValidUsername,
  isValidPassword,
  isValidRole,
  escapeHtml,
};
