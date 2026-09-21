# TaskForge (Phase 2) — Architecture

This codebase was refactored from a single 470-line `server.js` into
layers, each with one clear responsibility. This document explains the
boundaries and why each one exists.

## Directory structure

```
server.js                      Thin entry point — creates the HTTP server, starts listening
src/
├── config.js                  Reads environment variables. Nothing else touches process.env.
├── db.js                      SQLite connection, schema, seed data. No business logic.
├── logger.js                  Structured JSON logging.
├── rate-limiter.js            Login lockout after repeated failures.
├── ssrf-guard.js               URL safety checks for the link-preview feature.
│
├── auth/
│   ├── password-utils.js      Hashing + verifying passwords. Nothing else.
│   └── session-store.js       Creating/reading/destroying sessions. Nothing else.
│
├── validation/
│   └── validators.js          "Is this input shaped correctly?" — no side effects.
│
├── utils/
│   └── html.js                HTML-escaping untrusted output.
│
├── middleware/
│   └── require-auth.js        The ONE place "is this request allowed?" is decided.
│
├── services/
│   └── audit-service.js       Cross-cutting: records who-did-what-when.
│
├── controllers/
│   ├── auth-controller.js     register, login, logout, me
│   ├── tasks-controller.js    task CRUD + link preview
│   ├── comments-controller.js comment add/list
│   ├── users-controller.js    user list, avatar
│   └── audit-controller.js    audit log viewing
│
└── http/
    ├── router.js               Maps URL + method → controller function. Nothing else.
    ├── response.js             sendJSON() — the only place response headers are set.
    ├── request-body.js         readBody() — parsing + size limits.
    ├── static-server.js        Serving files from public/.
    └── cors.js                 CORS header logic.
```

## The rule each layer follows

**A file should have exactly one reason to change.** If you're fixing a bug
in how passwords are hashed, you touch `auth/password-utils.js` — nothing
else. If you're changing which roles can delete a task, you touch
`middleware/require-auth.js`'s caller in `tasks-controller.js` — not the
router, not the database layer, not the response formatting.

Concretely, this means:

- **Controllers never talk to `process.env`, never format HTTP headers directly, never construct SQL by hand outside `db.prepare()` calls.** They call `requireAuth`/`requireRole` for authorization, `readBody`/`sendJSON` for HTTP mechanics, and the database directly only for the specific query that endpoint needs.
- **`db.js` has no idea what a "task" or a "comment" means as a concept** — it only owns the schema and connection. The *meaning* of that data lives in the controllers that query it.
- **`middleware/require-auth.js` is the single enforcement point for "is this allowed?"** — this is deliberate, and directly traces back to the root cause of several Phase 1 vulnerabilities (F2, F4, F5): those bugs existed because each handler was responsible for remembering to add its own role check, and several simply didn't. Centralizing that check doesn't make forgetting impossible, but it means there's exactly one function to audit, not eleven.
- **`router.js` contains zero business logic** — it is purely a lookup table from `(method, path)` to a controller function. You can read the entire API surface of the application by reading this one file top to bottom.

## Why this matters for the security story specifically

Every fix documented in `SECURITY_ANALYSIS.md` and the pentest report still
lives in the codebase — nothing about *what* the code does changed in this
refactor, only *where* each piece lives. That was verified directly: the
full 17-test automated security suite and the custom SAST check both pass
against this structure with **zero changes to their assertions**, and the
same live attacks (SQL injection, SSRF, CORS) were manually replayed
against the running refactored server and confirmed still blocked.

The practical benefit of the separation: a future contributor fixing an
authentication bug has one file to look at (`auth-controller.js` +
`auth/`), not 470 lines of everything. A code reviewer checking "does every
privileged endpoint have a role check" can grep for `requireRole` calls
across `controllers/` in seconds. That reviewability is itself a secure
coding practice (Iteration 2 §1) — code that's hard to read is code where
a missing check is hard to notice.

## What did NOT change

- The database schema, all API endpoints, request/response shapes, and every security behavior are identical to before the refactor.
- `public/` (the frontend) is untouched — it talks to the same API.
- `tests/security.test.js` required zero modifications and all 17 tests still pass unchanged.
- `.env.example`, `.gitignore`, `package.json`, `.github/workflows/ci.yml`, and `.github/dependabot.yml` are unchanged (the CI pipeline's `npm test`, `npm run lint:sast`, and `npm audit` steps all still work against the new layout as-is).
