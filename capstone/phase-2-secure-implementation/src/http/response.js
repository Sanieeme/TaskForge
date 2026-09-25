// src/http/response.js
// Single concern: writing a JSON response. Every security header applied
// to every API response is set in exactly this one place.
"use strict";

function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
  });
  res.end(body);
}

module.exports = { sendJSON };
