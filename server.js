// server.js — TaskForge Phase 2 (secured)
// Every fix below is commented with "FIX (Phase 2)" and references the
// vulnerability number from the Phase 1 README so the two are easy to diff.
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const db = require("./db");
const {
  hashPassword,
  verifyPassword,
  isValidUsername,
  isValidPassword,
  isValidRole,
  escapeHtml,
} = require("./auth-utils");

const PORT = process.env.PORT || 3001;
const PUBLIC_DIR = path.join(__dirname, "public");

// FIX (#9 CORS misconfiguration): explicit allowlist instead of reflecting
// any Origin header. Add your real frontend origin(s) here.
const ALLOWED_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  "http://127.0.0.1:" + PORT,
]);

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
const sessions = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes idle timeout

function createSession(user) {
  const sid = crypto.randomBytes(32).toString("hex"); // FIX: longer, unguessable id
  sessions.set(sid, {
    userId: user.id,
    username: user.username,
    role: user.role,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return sid;
}

function getSession(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tf_session=([a-f0-9]+)/);
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(match[1]);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS; // sliding expiry
  return session;
}

function destroySession(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tf_session=([a-f0-9]+)/);
  if (match) sessions.delete(match[1]);
}

// FIX (#5, #6 Broken Access Control / IDOR): small authorization helpers used
// by every handler below, instead of relying on the frontend to hide buttons.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    // FIX: a couple of cheap, broadly-recommended security headers.
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let tooLarge = false;
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 100_000) {
        // FIX (#10 no size limits): reject oversized payloads early
        // (e.g. an avatar field can no longer be an arbitrarily large blob).
        tooLarge = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooLarge) return reject(new Error("payload too large"));
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

const MIME = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === "/" ? "/login.html" : pathname;
  filePath = path.join(PUBLIC_DIR, filePath);
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }
  fs.readFile(resolved, (err, content) => {
    if (err) {
      res.writeHead(404);
      return res.end("Not found");
    }
    const ext = path.extname(resolved);
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(content);
  });
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async function handleRegister(req, res) {
  const { username, password, role } = await readBody(req);

  // FIX (#10 no validation) + (#4 client-controlled role)
  if (!isValidUsername(username)) {
    return sendJSON(res, 400, { error: "username must be 3-32 chars, letters/numbers/underscore only" });
  }
  if (!isValidPassword(password)) {
    return sendJSON(res, 400, { error: "password must be at least 8 characters" });
  }
  // FIX (#4 Broken Access Control - privilege escalation on register):
  // self-registration can ONLY ever create an 'employee'. Managers/admins
  // must be promoted by an existing admin via a separate, protected endpoint.
  if (role !== undefined && !isValidRole(role)) {
    return sendJSON(res, 400, { error: "self-registration is only permitted as 'employee'" });
  }

  const { hash, salt } = hashPassword(password);
  try {
    db.prepare(
      "INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, 'employee')"
    ).run(username, hash, salt);
    sendJSON(res, 201, { message: "registered" });
  } catch (e) {
    sendJSON(res, 409, { error: "username already exists" });
  }
}

async function handleLogin(req, res) {
  const { username, password } = await readBody(req);
  if (!username || !password) {
    return sendJSON(res, 400, { error: "username and password required" });
  }

  // FIX (#2 SQL Injection): parameterised query, never string concatenation.
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // FIX: generic error message + always run verifyPassword (even on a
  // nonexistent user, against a dummy hash) to reduce username-enumeration
  // via timing differences.
  const dummySalt = "0".repeat(32);
  const dummyHash = "0".repeat(128);
  const ok = user
    ? verifyPassword(password, user.password_hash, user.password_salt)
    : verifyPassword(password, dummyHash, dummySalt);

  if (!user || !ok) {
    return sendJSON(res, 401, { error: "invalid username or password" });
  }

  const sid = createSession(user);

  // FIX (#8 cookie missing security flags): HttpOnly stops JS/XSS from
  // reading the cookie; SameSite=Lax mitigates CSRF; Secure would also be
  // set in production behind HTTPS (omitted here only because this demo
  // runs over plain HTTP on localhost).
  res.setHeader(
    "Set-Cookie",
    `tf_session=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800`
  );
  sendJSON(res, 200, { message: "logged in", role: user.role, username: user.username });
}

function handleLogout(req, res) {
  destroySession(req);
  res.setHeader("Set-Cookie", "tf_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  sendJSON(res, 200, { message: "logged out" });
}

function handleMe(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  sendJSON(res, 200, { userId: session.userId, username: session.username, role: session.role });
}

function handleGetTasks(req, res, query) {
  const session = requireAuth(req, res);
  if (!session) return;

  const search = (query.get("search") || "").slice(0, 200);

  // FIX (#3 SQL Injection): parameterised LIKE query.
  const likeTerm = `%${search}%`;
  let rows = db
    .prepare("SELECT * FROM tasks WHERE title LIKE ? OR description LIKE ?")
    .all(likeTerm, likeTerm);

  // FIX (#6 Broken Access Control / excessive data exposure): employees only
  // see tasks they created or are assigned to. Managers/Admins see everything.
  if (session.role === "employee") {
    rows = rows.filter(
      (t) => t.assignee_id === session.userId || t.created_by === session.userId
    );
  }

  sendJSON(res, 200, rows);
}

async function handleCreateTask(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): server-side role check, not just a
  // hidden button in the UI.
  if (!requireRole(session, res, ["manager", "admin"])) return;

  const { title, description, priority, assignee_id } = await readBody(req);
  if (!title || typeof title !== "string" || title.length > 200) {
    return sendJSON(res, 400, { error: "valid title required (max 200 chars)" });
  }
  const validPriorities = ["low", "medium", "high"];
  const safePriority = validPriorities.includes(priority) ? priority : "medium";

  const stmt = db.prepare(
    "INSERT INTO tasks (title, description, status, priority, assignee_id, created_by) VALUES (?, ?, 'todo', ?, ?, ?)"
  );
  const info = stmt.run(
    title,
    (description || "").slice(0, 2000),
    safePriority,
    assignee_id ? Number(assignee_id) : null,
    session.userId
  );
  sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
}

async function handleUpdateTask(req, res, id) {
  const session = requireAuth(req, res);
  if (!session) return;

  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  if (!existing) return sendJSON(res, 404, { error: "not found" });

  // FIX (#6 IDOR): employees may only update status on tasks assigned to
  // them; only manager/admin may edit title/description/priority/assignee.
  const { status, title, description, priority, assignee_id } = await readBody(req);

  if (session.role === "employee") {
    if (existing.assignee_id !== session.userId) {
      return sendJSON(res, 403, { error: "forbidden: not your task" });
    }
    const validStatuses = ["todo", "in_progress", "done"];
    if (!validStatuses.includes(status)) {
      return sendJSON(res, 400, { error: "invalid status" });
    }
    db.prepare("UPDATE tasks SET status = ? WHERE id = ?").run(status, id);
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
  sendJSON(res, 200, { message: "updated" });
}

function handleDeleteTask(req, res, id) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): admin-only, enforced server-side.
  if (!requireRole(session, res, ["admin"])) return;

  db.prepare("DELETE FROM tasks WHERE id = ?").run(id);
  sendJSON(res, 200, { message: "deleted" });
}

async function handleAddComment(req, res, taskId) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { body } = await readBody(req);
  if (!body || typeof body !== "string" || body.length > 1000) {
    return sendJSON(res, 400, { error: "comment must be 1-1000 characters" });
  }

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
  if (!task) return sendJSON(res, 404, { error: "task not found" });

  // FIX (#6): employees can only comment on tasks they're involved with.
  if (
    session.role === "employee" &&
    task.assignee_id !== session.userId &&
    task.created_by !== session.userId
  ) {
    return sendJSON(res, 403, { error: "forbidden" });
  }

  db.prepare("INSERT INTO comments (task_id, user_id, body) VALUES (?, ?, ?)").run(
    taskId,
    session.userId,
    body
  );
  sendJSON(res, 201, { message: "comment added" });
}

function handleGetComments(req, res, taskId) {
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

  // FIX (#7 Stored XSS): escape on the way out as defense in depth (the
  // frontend is also fixed to avoid innerHTML - see app.js).
  const safeRows = rows.map((r) => ({ ...r, body: escapeHtml(r.body), username: escapeHtml(r.username) }));
  sendJSON(res, 200, safeRows);
}

function handleGetUsers(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  // FIX (#5 Broken Access Control): admin-only.
  if (!requireRole(session, res, ["admin"])) return;

  // FIX (#1 plaintext passwords): password hash/salt are NEVER returned to
  // any client, not even the admin UI.
  const rows = db.prepare("SELECT id, username, role FROM users").all();
  sendJSON(res, 200, rows);
}

async function handleAvatar(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { avatar } = await readBody(req);
  // FIX (#10 no validation): length-limit and reject anything that isn't a
  // plausible http(s) URL. (A production app would also verify content-type
  // and use a real upload pipeline rather than accepting arbitrary strings.)
  if (avatar && (typeof avatar !== "string" || avatar.length > 500 || !/^https?:\/\//.test(avatar))) {
    return sendJSON(res, 400, { error: "avatar must be a valid http(s) URL under 500 chars" });
  }
  db.prepare("UPDATE users SET avatar = ? WHERE id = ?").run(avatar || "", session.userId);
  sendJSON(res, 200, { message: "avatar updated" });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const { pathname, searchParams } = url;

  try {
    // FIX (#9 CORS misconfiguration): only reflect an allowlisted origin,
    // and only send credentialed-CORS headers when the origin matches.
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      return res.end();
    }

    if (pathname === "/api/register" && req.method === "POST") return await handleRegister(req, res);
    if (pathname === "/api/login" && req.method === "POST") return await handleLogin(req, res);
    if (pathname === "/api/logout" && req.method === "POST") return handleLogout(req, res);
    if (pathname === "/api/me" && req.method === "GET") return handleMe(req, res);
    if (pathname === "/api/tasks" && req.method === "GET") return handleGetTasks(req, res, searchParams);
    if (pathname === "/api/tasks" && req.method === "POST") return await handleCreateTask(req, res);
    if (pathname === "/api/users" && req.method === "GET") return handleGetUsers(req, res);
    if (pathname === "/api/profile/avatar" && req.method === "POST") return await handleAvatar(req, res);

    let m = pathname.match(/^\/api\/tasks\/(\d+)$/);
    if (m && req.method === "PUT") return await handleUpdateTask(req, res, m[1]);
    if (m && req.method === "DELETE") return handleDeleteTask(req, res, m[1]);

    m = pathname.match(/^\/api\/tasks\/(\d+)\/comments$/);
    if (m && req.method === "GET") return handleGetComments(req, res, m[1]);
    if (m && req.method === "POST") return await handleAddComment(req, res, m[1]);

    if (pathname.startsWith("/api/")) return sendJSON(res, 404, { error: "not found" });
    return serveStatic(req, res, pathname);
  } catch (err) {
    // FIX: don't leak stack traces / internals to the client.
    console.error(err);
    sendJSON(res, 500, { error: "internal server error" });
  }
});

server.listen(PORT, () => {
  console.log(`TaskForge (Phase 2 secured) running at http://localhost:${PORT}`);
  console.log(`Seed accounts: admin/admin123, manager1/manager123, employee1/employee123, employee2/employee123`);
});
