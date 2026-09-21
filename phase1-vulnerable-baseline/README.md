# TaskForge — Phase 1 Baseline

📄 See **[SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md)** for the CIA triad,
STRIDE threat model, OWASP Top 10/SAMM, NIST SSDF, ISO/IEC 27034, DevSecOps/
shift-left/SSDLC discussion, and case studies (Iteration 1).

📄 See **[pentest/ITERATION3_PENTEST_GUIDE.md](./pentest/ITERATION3_PENTEST_GUIDE.md)**
for real, executed enumeration and exploitation of every vulnerability below,
plus Burp Suite/ffuf/sqlmap/Postman/DevTools usage (Iteration 3).

A small full-stack task/ticket manager with authentication and role-based
access control (Admin / Manager / Employee). This is the **Phase 1** build
for the capstone: functional, but built quickly and **deliberately left
insecure in several well-documented ways**, so there are real vulnerabilities
to fix in Phase 2 and real vulnerabilities to find in Phase 3.

## Stack
Plain Node.js only — no `npm install` required:
- `node:http` for the server
- `node:sqlite` (built into Node 22+) for storage
- Vanilla HTML/CSS/JS on the frontend

## Running it
```bash
node server.js
```
Then open `http://localhost:3000`. The database file `taskforge.db` is
created and seeded automatically on first run.

**Seed accounts:**
| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| manager1 | manager123 | manager |
| employee1 | employee123 | employee |
| employee2 | employee123 | employee |

## What it does
- Register / log in / log out
- Create tasks, assign them, update status (To do / In progress / Done)
- Comment on tasks
- Search/filter tasks by keyword
- View/edit a profile "avatar" field
- Admin-intended user list page

## Intentional vulnerabilities (Phase 1 — fix these in Phase 2)
Every one of these is marked in the code with a `VULNERABLE (Phase 1)` comment.

| # | Vulnerability | Where | OWASP Top 10 category |
|---|---|---|---|
| 1 | Passwords stored in **plaintext** | `db.js`, `server.js` (`handleRegister`) | A02: Cryptographic Failures |
| 2 | **SQL Injection** on login — string-concatenated query lets you log in as any user via `username = admin' -- ` | `server.js` (`handleLogin`) | A03: Injection |
| 3 | **SQL Injection** on the task search endpoint | `server.js` (`handleGetTasks`) | A03: Injection |
| 4 | **Broken Access Control**: role is client-supplied on registration — you can self-register as `admin` | `server.js` (`handleRegister`) | A01: Broken Access Control |
| 5 | **Broken Access Control**: no server-side role check on create/delete task, or on `/api/users` — UI hides buttons, but the API doesn't check | `server.js` (`handleCreateTask`, `handleDeleteTask`, `handleGetUsers`) | A01: Broken Access Control |
| 6 | **IDOR**: any logged-in user can view/update/delete any task by ID, regardless of ownership | `server.js` (`handleUpdateTask`, `handleGetTasks`) | A01: Broken Access Control |
| 7 | **Stored XSS**: comment text isn't sanitised server-side and is rendered via `innerHTML` client-side | `server.js` (`handleGetComments`), `app.js` (`loadComments`) | A03: Injection (XSS) |
| 8 | **Session cookie** missing `HttpOnly`, `Secure`, `SameSite` | `server.js` (`handleLogin`) | A07: Identification & Authentication Failures |
| 9 | **CORS misconfiguration**: reflects any `Origin` header with `Allow-Credentials: true` | `server.js` (CORS headers in the router) | A05: Security Misconfiguration |
| 10 | No input validation, size limits, or content checks on the avatar field | `server.js` (`handleAvatar`) | A04: Insecure Design |
| 11 | **SSRF**: the "link preview" feature fetches any user-supplied URL server-side with no validation — can reach internal-only services (e.g. this app's own admin endpoints, or cloud metadata endpoints in a real deployment) | `server.js` (`handleLinkPreview`) | A10: Server-Side Request Forgery |

## Suggested Phase 2 fixes (for your write-up)
- Hash passwords with `scrypt` (already imported via `node:crypto`) or `bcrypt`, with a per-user salt
- Use parameterised queries everywhere (the codebase already uses `db.prepare()` with `?` placeholders elsewhere — apply that consistently to login and search)
- Validate and enforce `role` server-side on registration (restrict self-registration to `employee`; require an admin to create managers/admins)
- Add real authorization middleware: check `session.role` and (for tasks) ownership/assignment before allowing create/update/delete
- Escape comment output (or use `textContent`/a templating engine with auto-escaping) and consider a Content-Security-Policy header
- Set `HttpOnly; Secure; SameSite=Strict` on the session cookie
- Restrict CORS to a known origin allowlist
- Add basic validation (length limits, type checks) on all inputs, including the avatar field
- Validate any server-side-fetched URL (link preview) against a private-IP/loopback blocklist and restrict to http/https schemes before fetching — see Phase 2's `ssrf-guard.js`

## Suggested Phase 3 pentest targets
See **[pentest/ITERATION3_PENTEST_GUIDE.md](./pentest/ITERATION3_PENTEST_GUIDE.md)**
for a full walkthrough with real executed output. Summary:
- **Burp Suite / Repeater**: intercept the login request and try the SQLi payload above; try changing `assignee_id`/task `id` in requests to access other users' tasks
- **sqlmap**: point at `POST /api/login` and `GET /api/tasks?search=`
- **ffuf**: enumerate endpoints using `pentest/wordlist.txt`
- **DevTools**: inspect the `tf_session` cookie flags; check if it's readable via `document.cookie` (it will be, since `HttpOnly` is missing)
- **Postman**: import `pentest/taskforge.postman_collection.json` — pre-built requests for every vulnerability, organized by category
- **SSRF**: use the link preview feature (`POST /api/tasks/:id/preview`) to reach `http://127.0.0.1:3000/api/users` and prove internal access
