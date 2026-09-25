// server.js — TaskForge Phase 2 (secured)
//
// This file is deliberately thin: it creates the HTTP server and starts it.
// Every actual concern - configuration, data access, auth, validation,
// output encoding, CORS, static files, and each resource's endpoints -
// lives in its own module under src/, organized by what it's responsible
// for rather than everything sharing one file. See ARCHITECTURE.md for the
// full map and the reasoning behind each boundary.
"use strict";

const http = require("node:http");
const config = require("./src/config");
const router = require("./src/http/router");

const server = http.createServer(router);

// Only auto-start the listener when this file is run directly. When
// required as a module (e.g. by tests/security.test.js), the server object
// is exported instead, so tests can bind it to an ephemeral port.
if (require.main === module) {
  server.listen(config.port, () => {
    console.log(`TaskForge (Phase 2 secured) running at http://localhost:${config.port}`);
    console.log(`Seed accounts: admin/admin123, manager1/manager123, employee1/employee123, employee2/employee123`);
  });
}

module.exports = server;
