// src/http/static-server.js
// Single concern: serving files out of public/. Knows nothing about
// sessions, JSON, or the API - if it isn't a file on disk, it's a 404 as
// far as this module is concerned.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const config = require("../config");

const PUBLIC_DIR = path.join(config.rootDir, "public");

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

module.exports = { serveStatic };
