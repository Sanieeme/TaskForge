// src/http/cors.js
// Single concern: deciding which CORS headers, if any, a response gets.
// FIX (#9 CORS misconfiguration): only reflects an allowlisted origin -
// never "whatever the request sent" - and only sets Allow-Credentials
// when the origin is actually in that allowlist.
"use strict";

const config = require("../config");

const ALLOWED_ORIGINS = new Set(
  config.allowedOrigins.length > 0
    ? config.allowedOrigins
    : [`http://localhost:${config.port}`, `http://127.0.0.1:${config.port}`]
);

/** Returns true if the request was a handled OPTIONS preflight (caller should stop). */
function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return true;
  }
  return false;
}

module.exports = { applyCors, ALLOWED_ORIGINS };
