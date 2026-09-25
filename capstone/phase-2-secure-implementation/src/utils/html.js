// src/utils/html.js
// Single concern: safely encoding untrusted text for HTML output. This is
// deliberately NOT in the auth/ folder - escaping is a general output-safety
// concern (used for comment bodies, usernames in responses, etc.), not
// something specific to authentication.
"use strict";

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = { escapeHtml };
