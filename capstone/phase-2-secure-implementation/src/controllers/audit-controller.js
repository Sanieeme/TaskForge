// src/controllers/audit-controller.js
// Addresses the STRIDE Repudiation gap: admins can see who did what, when.
"use strict";

const db = require("../db");
const { sendJSON } = require("../http/response");
const { requireAuth, requireRole } = require("../middleware/require-auth");

function list(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (!requireRole(session, res, ["admin"])) return;

  const rows = db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").all();
  sendJSON(res, 200, rows);
}

module.exports = { list };
