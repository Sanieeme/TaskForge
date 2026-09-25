// src/http/router.js
// The single place that knows "this URL + method maps to this controller
// function". Controllers know nothing about routing; this file knows
// nothing about business logic - it only dispatches.
"use strict";

const { URL } = require("node:url");
const { sendJSON } = require("./response");
const { serveStatic } = require("./static-server");
const { applyCors } = require("./cors");

const authController = require("../controllers/auth-controller");
const tasksController = require("../controllers/tasks-controller");
const commentsController = require("../controllers/comments-controller");
const usersController = require("../controllers/users-controller");
const auditController = require("../controllers/audit-controller");

async function router(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const { pathname, searchParams } = url;

  try {
    if (applyCors(req, res)) return; // true = OPTIONS preflight already handled

    if (pathname === "/api/register" && req.method === "POST") return await authController.register(req, res);
    if (pathname === "/api/login" && req.method === "POST") return await authController.login(req, res);
    if (pathname === "/api/logout" && req.method === "POST") return authController.logout(req, res);
    if (pathname === "/api/me" && req.method === "GET") return authController.me(req, res);

    if (pathname === "/api/tasks" && req.method === "GET") return tasksController.list(req, res, searchParams);
    if (pathname === "/api/tasks" && req.method === "POST") return await tasksController.create(req, res);

    if (pathname === "/api/users" && req.method === "GET") return usersController.list(req, res);
    if (pathname === "/api/audit-log" && req.method === "GET") return auditController.list(req, res);
    if (pathname === "/api/profile/avatar" && req.method === "POST") return await usersController.updateAvatar(req, res);

    let m = pathname.match(/^\/api\/tasks\/(\d+)$/);
    if (m && req.method === "PUT") return await tasksController.update(req, res, m[1]);
    if (m && req.method === "DELETE") return tasksController.remove(req, res, m[1]);

    m = pathname.match(/^\/api\/tasks\/(\d+)\/comments$/);
    if (m && req.method === "GET") return commentsController.list(req, res, m[1]);
    if (m && req.method === "POST") return await commentsController.add(req, res, m[1]);

    m = pathname.match(/^\/api\/tasks\/(\d+)\/preview$/);
    if (m && req.method === "POST") return await tasksController.preview(req, res, m[1]);

    if (pathname.startsWith("/api/")) return sendJSON(res, 404, { error: "not found" });
    return serveStatic(req, res, pathname);
  } catch (err) {
    // FIX: don't leak stack traces / internals to the client.
    console.error(err);
    sendJSON(res, 500, { error: "internal server error" });
  }
}

module.exports = router;
