// src/controllers/users-controller.js
"use strict";

const db = require("../db");
const { sendJSON } = require("../http/response");
const { readBody } = require("../http/request-body");
const { requireAuth, requireRole } = require("../middleware/require-auth");

function list(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): admin-only.
  if (!requireRole(session, res, ["admin"])) return;

  // FIX (#1 plaintext passwords): password hash/salt never serialised.
  const rows = db.prepare("SELECT id, username, role FROM users").all();
  sendJSON(res, 200, rows);
}

async function updateAvatar(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { avatar } = await readBody(req);
  // FIX (#10 no validation): length-limit + plausible http(s) URL shape.
  if (avatar && (typeof avatar !== "string" || avatar.length > 500 || !/^https?:\/\//.test(avatar))) {
    return sendJSON(res, 400, { error: "avatar must be a valid http(s) URL under 500 chars" });
  }
  db.prepare("UPDATE users SET avatar = ? WHERE id = ?").run(avatar || "", session.userId);
  sendJSON(res, 200, { message: "avatar updated" });
}

module.exports = { list, updateAvatar };
