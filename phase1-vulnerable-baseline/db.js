// db.js
// Sets up the SQLite database and seeds demo accounts.
"use strict";

const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");

const dbPath = path.join(__dirname, "taskforge.db");
const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
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
`);

// Seed demo accounts if empty
const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
if (count === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
  );
  // NOTE (intentional Phase 1 vulnerability):
  // Passwords are stored in PLAINTEXT. This is a deliberate flaw to be
  // fixed in Phase 2 with proper salted hashing (e.g. scrypt/bcrypt).
  insertUser.run("admin", "admin123", "admin");
  insertUser.run("manager1", "manager123", "manager");
  insertUser.run("employee1", "employee123", "employee");
  insertUser.run("employee2", "employee123", "employee");

  const insertTask = db.prepare(
    "INSERT INTO tasks (title, description, status, priority, assignee_id, created_by) VALUES (?, ?, ?, ?, ?, ?)"
  );
  insertTask.run("Set up CI pipeline", "Configure GitHub Actions build", "in_progress", "high", 3, 2);
  insertTask.run("Fix login bug", "Users report session expiring too fast", "todo", "medium", 4, 2);
  insertTask.run("Confidential salary review", "Internal only - do not share", "todo", "high", 2, 1);
}

module.exports = db;
