// src/db.js
// Owns exactly one concern: the SQLite connection, schema, and seed data.
// No route/controller logic lives here.
"use strict";

const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");
const config = require("./config");
const { hashPassword } = require("./auth/password-utils");

const dbPath = path.isAbsolute(config.dbPath)
  ? config.dbPath
  : path.join(config.rootDir, config.dbPath);
const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'employee',
    avatar TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'todo',
    priority TEXT DEFAULT 'medium',
    assignee_id INTEGER,
    created_by INTEGER
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor_username TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    detail TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
if (count === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, ?)"
  );
  for (const [username, password, role] of [
    ["admin", "admin123", "admin"],
    ["manager1", "manager123", "manager"],
    ["employee1", "employee123", "employee"],
    ["employee2", "employee123", "employee"],
  ]) {
    const { hash, salt } = hashPassword(password);
    insertUser.run(username, hash, salt, role);
  }

  const insertTask = db.prepare(
    "INSERT INTO tasks (title, description, status, priority, assignee_id, created_by) VALUES (?, ?, ?, ?, ?, ?)"
  );
  insertTask.run("Set up CI pipeline", "Configure GitHub Actions build", "in_progress", "high", 3, 2);
  insertTask.run("Fix login bug", "Users report session expiring too fast", "todo", "medium", 4, 2);
  insertTask.run("Confidential salary review", "Internal only - do not share", "todo", "high", 2, 1);
}

module.exports = db;
