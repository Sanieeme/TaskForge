// src/controllers/tasks-controller.js
// Owns exactly the task-related HTTP endpoints. Authorization decisions
// delegate to middleware/require-auth.js; nothing here re-implements a
// role check inline.
"use strict";

const db = require("../db");
const { sendJSON } = require("../http/response");
const { readBody } = require("../http/request-body");
const { requireAuth, requireRole } = require("../middleware/require-auth");
const { checkUrlIsSafe } = require("../ssrf-guard");
const { logAudit } = require("../services/audit-service");

function list(req, res, query) {
  const session = requireAuth(req, res);
  if (!session) return;

  const search = (query.get("search") || "").slice(0, 200);

  // FIX (#3 SQL Injection): parameterised LIKE query.
  const likeTerm = `%${search}%`;
  let rows = db
    .prepare("SELECT * FROM tasks WHERE title LIKE ? OR description LIKE ?")
    .all(likeTerm, likeTerm);

  // FIX (#6 Broken Access Control): employees only see their own tasks.
  if (session.role === "employee") {
    rows = rows.filter((t) => t.assignee_id === session.userId || t.created_by === session.userId);
  }

  sendJSON(res, 200, rows);
}

async function create(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): server-side role check.
  if (!requireRole(session, res, ["manager", "admin"])) return;

  const { title, description, priority, assignee_id } = await readBody(req);
  if (!title || typeof title !== "string" || title.length > 200) {
    return sendJSON(res, 400, { error: "valid title required (max 200 chars)" });
  }
  const validPriorities = ["low", "medium", "high"];
  const safePriority = validPriorities.includes(priority) ? priority : "medium";

  const info = db
    .prepare(
      "INSERT INTO tasks (title, description, status, priority, assignee_id, created_by) VALUES (?, ?, 'todo', ?, ?, ?)"
    )
    .run(title, (description || "").slice(0, 2000), safePriority, assignee_id ? Number(assignee_id) : null, session.userId);

  logAudit({
    actorId: session.userId,
    actorUsername: session.username,
    action: "task_create",
    targetType: "task",
    targetId: Number(info.lastInsertRowid),
    detail: title,
  });
  sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
}

async function update(req, res, id) {
  const session = requireAuth(req, res);
  if (!session) return;

  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  if (!existing) return sendJSON(res, 404, { error: "not found" });

  const { status, title, description, priority, assignee_id } = await readBody(req);

  // FIX (#6 IDOR): employees may only update status on tasks assigned to them.
  if (session.role === "employee") {
    if (existing.assignee_id !== session.userId) {
      return sendJSON(res, 403, { error: "forbidden: not your task" });
    }
    const validStatuses = ["todo", "in_progress", "done"];
    if (!validStatuses.includes(status)) {
      return sendJSON(res, 400, { error: "invalid status" });
    }
    db.prepare("UPDATE tasks SET status = ? WHERE id = ?").run(status, id);
    logAudit({
      actorId: session.userId,
      actorUsername: session.username,
      action: "task_status_update",
      targetType: "task",
      targetId: Number(id),
      detail: `status -> ${status}`,
    });
    return sendJSON(res, 200, { message: "updated" });
  }

  // manager/admin: full edit allowed
  db.prepare(
    "UPDATE tasks SET status = ?, title = ?, description = ?, priority = ?, assignee_id = ? WHERE id = ?"
  ).run(
    status ?? existing.status,
    title ?? existing.title,
    description ?? existing.description,
    priority ?? existing.priority,
    assignee_id ?? existing.assignee_id,
    id
  );
  logAudit({
    actorId: session.userId,
    actorUsername: session.username,
    action: "task_update",
    targetType: "task",
    targetId: Number(id),
    detail: null,
  });
  sendJSON(res, 200, { message: "updated" });
}

function remove(req, res, id) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): admin-only, enforced server-side.
  if (!requireRole(session, res, ["admin"])) return;

  db.prepare("DELETE FROM tasks WHERE id = ?").run(id);
  logAudit({
    actorId: session.userId,
    actorUsername: session.username,
    action: "task_delete",
    targetType: "task",
    targetId: Number(id),
    detail: null,
  });
  sendJSON(res, 200, { message: "deleted" });
}

// FIX (#11 SSRF): validated via checkUrlIsSafe() BEFORE any fetch happens.
// Redirects are disabled and treated as failures.
async function preview(req, res, taskId) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { url } = await readBody(req);
  if (!url || typeof url !== "string" || url.length > 2000) {
    return sendJSON(res, 400, { error: "a valid url is required" });
  }

  const safety = await checkUrlIsSafe(url);
  if (!safety.safe) {
    return sendJSON(res, 400, { error: `blocked: ${safety.reason}` });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(url, { signal: controller.signal, redirect: "manual" });
    clearTimeout(timeout);

    if (response.status >= 300 && response.status < 400) {
      return sendJSON(res, 400, { error: "blocked: redirects are not followed" });
    }

    const text = await response.text();
    sendJSON(res, 200, { requestedUrl: url, status: response.status, snippet: text.slice(0, 500) });
  } catch (e) {
    sendJSON(res, 502, { error: "could not fetch url" });
  }
}

module.exports = { list, create, update, remove, preview };
