// tests/security.test.js
// Automated regression tests for the Phase 1 -> Phase 2 security fixes.
// Run with: node --test tests/
//
// These exist so that a future code change which accidentally reintroduces
// one of the original 10 vulnerabilities (e.g. someone "simplifies" the
// login query back into string concatenation) gets caught automatically in
// CI, rather than relying on a human remembering to check by hand.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

// Use an isolated, throwaway database for the test run so tests never touch
// (or are affected by) a developer's real local taskforge.db.
const tmpDbPath = path.join(os.tmpdir(), `taskforge-test-${Date.now()}.db`);
process.env.DB_PATH = tmpDbPath;
process.env.PORT = "0"; // ephemeral port, avoids clashing with a running dev server
process.env.NODE_ENV = "test";

const server = require("../server");

let baseUrl;

test.before(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tmpDbPath, { force: true });
});

async function login(username, password) {
  const res = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const cookie = res.headers.get("set-cookie");
  const data = await res.json();
  return { res, data, cookie };
}

// --- Vulnerability #2: SQL Injection on login ------------------------------
test("login rejects a SQL injection auth-bypass payload", async () => {
  const { res, data } = await login("admin' -- ", "anything");
  assert.equal(res.status, 401);
  assert.equal(data.error, "invalid username or password");
});

// --- Vulnerability #1: plaintext passwords ---------------------------------
test("valid credentials still log in successfully (hashing didn't break auth)", async () => {
  const { res, data } = await login("admin", "admin123");
  assert.equal(res.status, 200);
  assert.equal(data.role, "admin");
});

// --- Vulnerability #8: session cookie missing security flags ---------------
test("session cookie is HttpOnly and SameSite", async () => {
  const { cookie } = await login("admin", "admin123");
  assert.ok(cookie.includes("HttpOnly"), "cookie should be HttpOnly");
  assert.ok(cookie.includes("SameSite"), "cookie should set SameSite");
});

// --- Vulnerability #4: client-controlled role on registration --------------
test("registration rejects a self-assigned admin role", async () => {
  const res = await fetch(`${baseUrl}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "attacker1", password: "password123", role: "admin" }),
  });
  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /employee/);
});

// --- Vulnerability #5: missing server-side role checks ---------------------
test("an employee cannot create a task (manager/admin only)", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/tasks`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ title: "Sneaky task" }),
  });
  assert.equal(res.status, 403);
});

test("an employee cannot list all users (admin only)", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/users`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 403);
});

// --- Vulnerability #6: IDOR on task read/update -----------------------------
test("an employee cannot update a task assigned to someone else", async () => {
  const { cookie } = await login("employee1", "employee123");
  // Task 2 in seed data is assigned to employee2, not employee1.
  const res = await fetch(`${baseUrl}/api/tasks/2`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ status: "done" }),
  });
  assert.equal(res.status, 403);
});

test("an employee only sees their own tasks in the task list", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/tasks`, { headers: { Cookie: cookie } });
  const tasks = await res.json();
  for (const t of tasks) {
    assert.ok(
      t.assignee_id === 3 || t.created_by === 3, // employee1's user id in seed data
      `task ${t.id} should not be visible to employee1`
    );
  }
});

// --- Vulnerability #7: stored XSS in comments -------------------------------
test("comment bodies are HTML-escaped in API responses", async () => {
  const { cookie } = await login("employee1", "employee123");
  const payload = "<script>alert(1)</script>";
  await fetch(`${baseUrl}/api/tasks/1/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ body: payload }),
  });
  const res = await fetch(`${baseUrl}/api/tasks/1/comments`, { headers: { Cookie: cookie } });
  const comments = await res.json();
  const last = comments[comments.length - 1];
  assert.ok(!last.body.includes("<script>"), "raw <script> tag must not appear in output");
  assert.ok(last.body.includes("&lt;script&gt;"), "tag should be HTML-escaped");
});

// --- Unauthenticated access ---------------------------------------------
test("unauthenticated requests to protected endpoints are rejected", async () => {
  const res = await fetch(`${baseUrl}/api/tasks`);
  assert.equal(res.status, 401);
});

// --- Vulnerability #11: SSRF via link preview -------------------------------
test("link preview blocks a loopback/internal destination", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/tasks/1/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ url: "http://127.0.0.1:9/" }),
  });
  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /blocked/);
});

test("link preview blocks a non-http(s) scheme", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/tasks/1/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ url: "file:///etc/passwd" }),
  });
  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /http/);
});

test("link preview blocks the literal hostname 'localhost'", async () => {
  const { cookie } = await login("employee1", "employee123");
  const res = await fetch(`${baseUrl}/api/tasks/1/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ url: "http://localhost/" }),
  });
  assert.equal(res.status, 400);
});

// --- F10: rate limiting / account lockout -----------------------------------
test("account is locked out after repeated failed login attempts", async () => {
  const username = "lockout_test_user";
  // Register a throwaway account so this test doesn't interfere with the
  // shared seed accounts used by every other test.
  await fetch(`${baseUrl}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: "correct-horse-battery" }),
  });

  let lastStatus;
  for (let i = 0; i < 5; i++) {
    const res = await login(username, "wrong-password");
    lastStatus = res.res.status;
  }
  assert.equal(lastStatus, 401, "the 5th failed attempt should still just be a normal 401");

  // The 6th attempt (even with the CORRECT password) should now be locked out.
  const { res } = await login(username, "correct-horse-battery");
  assert.equal(res.status, 429);
  assert.ok(res.headers.get("retry-after"), "should advertise a Retry-After header");
});

test("a successful login clears any prior failed-attempt count", async () => {
  const username = "lockout_reset_test_user";
  await fetch(`${baseUrl}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: "correct-horse-battery" }),
  });

  // 3 failures (below the lockout threshold), then a success.
  for (let i = 0; i < 3; i++) await login(username, "wrong-password");
  const success = await login(username, "correct-horse-battery");
  assert.equal(success.res.status, 200);

  // Should be able to fail a few more times afterward without being
  // immediately locked out, proving the counter reset on success.
  const { res } = await login(username, "wrong-password");
  assert.equal(res.status, 401);
});

// --- STRIDE Repudiation fix: audit log --------------------------------------
test("audit log records a login event and is admin-only", async () => {
  const { cookie: adminCookie } = await login("admin", "admin123");
  const res = await fetch(`${baseUrl}/api/audit-log`, { headers: { Cookie: adminCookie } });
  assert.equal(res.status, 200);
  const entries = await res.json();
  assert.ok(Array.isArray(entries) && entries.length > 0);
  assert.ok(entries.some((e) => e.action === "login"));

  const { cookie: empCookie } = await login("employee1", "employee123");
  const forbidden = await fetch(`${baseUrl}/api/audit-log`, { headers: { Cookie: empCookie } });
  assert.equal(forbidden.status, 403);
});

test("audit log records a task creation event", async () => {
  const { cookie } = await login("manager1", "manager123");
  const createRes = await fetch(`${baseUrl}/api/tasks`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ title: "Audit log test task" }),
  });
  assert.equal(createRes.status, 201);

  const { cookie: adminCookie } = await login("admin", "admin123");
  const res = await fetch(`${baseUrl}/api/audit-log`, { headers: { Cookie: adminCookie } });
  const entries = await res.json();
  assert.ok(entries.some((e) => e.action === "task_create" && e.detail === "Audit log test task"));
});

