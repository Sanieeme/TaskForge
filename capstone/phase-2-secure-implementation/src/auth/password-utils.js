// src/auth/password-utils.js
// Single concern: turning a plaintext password into a stored credential and
// verifying one against it. No validation rules, no HTML escaping, no
// session logic - those each live in their own module now.
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
  if (candidateHash.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(candidateHash, storedBuf);
}

module.exports = { hashPassword, verifyPassword };
