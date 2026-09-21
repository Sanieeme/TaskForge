// src/controllers/comments-controller.js
"use strict";

const db = require("../db");
const { sendJSON } = require("../http/response");
const { readBody } = require("../http/request-body");
const { requireAuth } = require("../middleware/require-auth");
const { escapeHtml } = require("../utils/html");
const { logAudit } = require("../services/audit-service");

async function add(req, res, taskId) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { body } = await readBody(req);
  if (!body || typeof body !== "string" || body.length > 1000) {
    return sendJSON(res, 400, { error: "comment must be 1-1000 characters" });
  }

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
  if (!task) return sendJSON(res, 404, { error: "task not found" });

  // FIX (#6): employees can only comment on tasks they're involved with.
  if (session.role === "employee" && task.assignee_id !== session.userId && task.created_by !== session.userId) {
    return sendJSON(res, 403, { error: "forbidden" });
  }

  db.prepare("INSERT INTO comments (task_id, user_id, body) VALUES (?, ?, ?)").run(taskId, session.userId, body);
  logAudit({
    actorId: session.userId,
    actorUsername: session.username,
    action: "comment_add",
    targetType: "task",
    targetId: Number(taskId),
    detail: null,
  });
  sendJSON(res, 201, { message: "comment added" });
}

function list(req, res, taskId) {
  const session = requireAuth(req, res);
  if (!session) return;

  const rows = db
    .prepare(
      `SELECT comments.id, comments.task_id, comments.user_id, comments.body,
              comments.created_at, users.username
       FROM comments JOIN users ON comments.user_id = users.id
       WHERE task_id = ? ORDER BY comments.id ASC`
    )
    .all(taskId);

  // FIX (#7 Stored XSS): escape on the way out as defense in depth.
  const safeRows = rows.map((r) => ({ ...r, body: escapeHtml(r.body), username: escapeHtml(r.username) }));
  sendJSON(res, 200, safeRows);
}

module.exports = { add, list };
