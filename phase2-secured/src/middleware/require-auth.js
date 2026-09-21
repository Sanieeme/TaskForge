// src/middleware/require-auth.js
// FIX (#5, #6 Broken Access Control / IDOR): this is the ONE place "is this
// request allowed?" gets decided. Every controller that needs auth calls
// these two functions rather than re-implementing the check - so a missing
// role check (the root cause of several Phase 1 findings) can no longer
// happen by a controller simply forgetting to add one inline.
"use strict";

const { getSession } = require("../auth/session-store");
const { sendJSON } = require("../http/response");

function requireAuth(req, res) {
  const session = getSession(req);
  if (!session) {
    sendJSON(res, 401, { error: "not logged in" });
    return null;
  }
  return session;
}

function requireRole(session, res, allowedRoles) {
  if (!allowedRoles.includes(session.role)) {
    sendJSON(res, 403, { error: "forbidden: insufficient role" });
    return false;
  }
  return true;
}

module.exports = { requireAuth, requireRole };
