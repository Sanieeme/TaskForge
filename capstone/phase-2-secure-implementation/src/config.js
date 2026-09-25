// src/config.js
// Single source of truth for environment-derived configuration. Nothing
// else in the codebase reads process.env directly - see .env.example for
// what each variable means and .gitignore for why real values never get
// committed.
"use strict";

const path = require("node:path");

// This file lives at <project root>/src/config.js, so one level up is the
// project root - every other module resolves paths through config.rootDir
// rather than its own __dirname, so moving a file between folders never
// silently changes where it reads/writes on disk.
const rootDir = path.join(__dirname, "..");

function requireEnvInProd(name, devDefault) {
  const value = process.env[name];
  if (value !== undefined && value !== "") return value;
  if (process.env.NODE_ENV === "production") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return devDefault;
}

module.exports = {
  rootDir,
  port: Number(process.env.PORT) || 3001,
  nodeEnv: process.env.NODE_ENV || "development",
  sessionTtlMs: Number(process.env.SESSION_TTL_MS) || 30 * 60 * 1000,
  dbPath: process.env.DB_PATH || "./taskforge.db",
  cookieSigningKey: requireEnvInProd("COOKIE_SIGNING_KEY", "dev-only-insecure-key"),
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
};
