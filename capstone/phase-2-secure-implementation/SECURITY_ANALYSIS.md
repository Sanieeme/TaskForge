# TaskForge — Security Analysis
### (CIA Triad · STRIDE Threat Model · Industry Frameworks · DevSecOps/SSDLC · Case Studies)

This document applies Iteration 1's fundamentals directly to TaskForge's real
architecture (Phase 2: `src/controllers/`, `src/db.js`, `public/app.js` — see
`ARCHITECTURE.md` for the full module map) and to the 10 concrete
vulnerabilities found in the Phase 1 baseline and fixed in Phase 2. It is not
a generic theory summary — every section below references an actual
endpoint, handler, or line of behaviour in this codebase.

---

## 1. System Overview (what we're analysing)

```
 Browser (public/*.html, app.js)
        │  fetch() with credentials
        ▼
 ┌───────────────────────────────────────────┐
 │  src/http/router.js                        │
 │  - dispatches to src/controllers/*         │
 │    (auth, tasks, comments, users, audit)   │
 │  - src/middleware/require-auth.js gates    │
 │    every privileged call                   │
 │  - src/auth/session-store.js (in-memory)   │
 └───────────────────────────────────────────┘
        │  db.prepare(...).run()/.get()/.all()
        ▼
 ┌───────────────────────────────────────────┐
 │  SQLite (taskforge.db) via src/db.js       │
 │  tables: users, tasks, comments, audit_log │
 └───────────────────────────────────────────┘
```

Phase 1's baseline (`taskforge/`, the intentionally vulnerable build this
document's findings originate from) still uses a single-file `server.js` —
it was left unrefactored on purpose, since a real "quickly-built, security
not yet considered" baseline is part of what makes the before/after
comparison honest. Phase 2's module boundaries are documented fully in
`ARCHITECTURE.md`.

**Trust boundaries** (the places STRIDE actually gets applied):
- **B1** — Browser ↔ Server, crossed on every `/api/*` call
- **B2** — Employee session ↔ Manager/Admin-only functionality (role boundary, *inside* the same HTTP boundary)
- **B3** — Server ↔ Database (SQL query construction)
- **B4** — One user's data ↔ another user's data (task ownership boundary)

---

## 2. CIA Triad Applied to TaskForge

| Property | What it means for TaskForge | Concrete asset |
|---|---|---|
| **Confidentiality** | Task content, comments, and account data are only visible to authorised roles/owners | The "Confidential salary review" seed task; the `users` table (usernames, password hashes) |
| **Integrity** | Task status/assignment/comments reflect only legitimate, authorised changes | `tasks.status`, `tasks.assignee_id`, `comments.body` |
| **Availability** | The API and dashboard stay responsive under normal and adversarial load | The Node HTTP server itself; the in-memory session Map |

Every Phase 1 vulnerability maps onto this triad directly:

| Vulnerability (from README) | CIA property violated | Why |
|---|---|---|
| Plaintext password storage | Confidentiality | A DB read exposes every user's real password |
| SQL Injection on login | Confidentiality + Integrity | Bypasses authentication entirely — attacker impersonates any account |
| SQL Injection on search | Confidentiality | Can be extended (via `UNION SELECT`) to read arbitrary table data |
| Client-controlled role on register | Confidentiality + Integrity | Self-granted admin rights corrupt the intended authorization model |
| Missing server-side role checks | Confidentiality + Integrity | Employees can read/write data outside their authority |
| IDOR on task read/update | Confidentiality + Integrity | Any user can view or modify another user's task by ID |
| Stored XSS in comments | Confidentiality + Integrity | Injected script can read the (non-HttpOnly) session cookie and act as the victim |
| Missing cookie flags | Confidentiality | Session token readable via `document.cookie`, stealable via XSS |
| CORS misconfiguration | Confidentiality | A malicious site can make credentialed requests on a logged-in user's behalf |
| No input/size validation | Availability + Integrity | Unbounded input can degrade the server or corrupt stored data |

Availability was deliberately *not* the focus of Phase 1 (no DoS-style flaw was seeded), which is itself worth noting in a report: TaskForge's baseline demonstrates that most real-world web vulnerabilities cluster around confidentiality and integrity failures, not availability — consistent with the OWASP Top 10's own weighting.

---

## 3. STRIDE Threat Model

Threat modelling should happen *before* code is written (that's the shift-left
principle in §5) — this table is what a proper Phase 1 planning session
should have produced, applied retroactively to show what was missed and why
each Phase 1 vulnerability existed in the first place.

| STRIDE category | Threat against TaskForge | Trust boundary | Present in Phase 1? | Mitigation (Phase 2) |
|---|---|---|---|---|
| **S**poofing | Attacker logs in as another user via SQLi in `handleLogin`, or via a stolen non-HttpOnly cookie | B1 | ✅ Yes | Parameterised query + hashed passwords + `HttpOnly` cookie |
| **T**ampering | Attacker modifies `assignee_id`/`status` on a task they don't own via `PUT /api/tasks/:id` | B4 | ✅ Yes | Ownership check in `handleUpdateTask` |
| **R**epudiation | No audit trail of who changed a task's status or deleted it | B1/B3 | ✅ Yes | `audit_log` table + structured logging (`logAudit()` in `server.js`, `logger.js`) — see below |
| **I**nformation Disclosure | `GET /api/users` returns every account (Phase 1: including plaintext passwords) to any logged-in user | B2 | ✅ Yes | Role check (`admin` only) + password hash/salt never serialised |
| **D**enial of Service | Oversized request bodies (e.g. a huge `avatar` string) consume memory/CPU with no limit; unlimited login attempts enable brute-forcing | B1 | ✅ Yes | Body-size cap in `readBody()`; per-account lockout after 5 failed logins (`rate-limiter.js`) |
| **E**levation of Privilege | Self-registering with `role: "admin"`; or an `employee` session calling `POST /api/tasks` / `DELETE /api/tasks/:id` | B1/B2 | ✅ Yes | Server enforces `role !== 'admin'` on register; `requireRole()` gate on every privileged handler |

**Repudiation — now addressed:** every state-changing action (login,
task create/update/delete, comment add) is recorded in an `audit_log` table
via `logAudit()`, capturing actor, action, target, and timestamp. An
admin-only `GET /api/audit-log` endpoint exposes the last 200 entries.
Every write also emits a structured JSON log line (`logger.js`), so a real
deployment could ship these to a log aggregator with no code change beyond
the transport. Repeated failed logins additionally emit an `alert`-level
log line when an account is locked out, giving real-time visibility into a
brute-force attempt in progress — see §5 for how this ties into the
previously-open rate-limiting finding (F10 in the pentest report).

---

## 4. Industry Frameworks Applied

### OWASP Top 10 — mapping (see also README.md)
Every Phase 1 vulnerability was deliberately chosen to land in a real OWASP
Top 10 (2021) category:

| OWASP category | TaskForge instance |
|---|---|
| A01: Broken Access Control | Missing role checks, IDOR, client-controlled role |
| A02: Cryptographic Failures | Plaintext password storage |
| A03: Injection | SQL Injection (login, search), Stored XSS |
| A04: Insecure Design | No validation/size limits anywhere |
| A05: Security Misconfiguration | Permissive CORS (reflects any Origin + credentials) |
| A07: Identification & Authentication Failures | Session cookie missing `HttpOnly`/`Secure`/`SameSite` |

### OWASP SAMM — maturity self-assessment
SAMM scores an organisation's *practices*, not just its code, across five
business functions. Rating TaskForge's own development process (Phase 1 →
Phase 2) against each:

| SAMM function | Phase 1 (baseline) maturity | Phase 2 (secured) maturity |
|---|---|---|
| **Governance** | 0 — no security requirements defined before building | 1 — vulnerabilities catalogued and tracked (README table) |
| **Design** | 0 — no threat modelling done before coding | 1 — this document retroactively threat-models the system; a mature process would do this *first* |
| **Implementation** | 0 — no secure coding standard followed | 1 — parameterised queries, hashing, escaping applied consistently |
| **Verification** | 0 — no testing beyond "does it run" | 1 — 17 automated security regression tests + custom SAST, run in CI on every push |
| **Operations** | 0 — no patching/monitoring story | 1 — structured logging with alerting on repeated auth failures, an admin-viewable audit log, per-account lockout, and Dependabot dependency monitoring |

This is a legitimate SAMM-style finding: Phase 2 meaningfully improves
maturity across all five functions relative to Phase 1. Operations was the
last function to reach a passing score, closing a gap this document
originally (and correctly, at the time) flagged as open.

### NIST SSDF (SP 800-218) — practice mapping

| SSDF group | Practice | Where TaskForge does/doesn't meet it |
|---|---|---|
| **PO** (Prepare the Organization) | Define secure coding standards | Not formally documented until this file; informally applied in Phase 2 code comments |
| **PS** (Protect the Software) | Protect code/credentials from tampering | No `.env`/secrets manager used (this demo has no real secrets), but the pattern is documented as a gap |
| **PW** (Produce Well-Secured Software) | Secure design, input validation, secure defaults | Achieved in Phase 2: parameterised queries, role checks, validation helpers in `auth-utils.js` |
| **RV** (Respond to Vulnerabilities) | Identify & remediate vulnerabilities continuously | Demonstrated once (Phase 1 → Phase 2), but no ongoing/automated process (no CI, no dependency scanning) |

### ISO/IEC 27034 — Application Security Management Process
ISO/IEC 27034 treats security as an ongoing organisational process with
reusable controls, not a one-time fix. TaskForge's Phase 1 → Phase 2 cycle is
a single iteration of that process (identify risk → apply control → verify).
A genuine ISO/IEC 27034-aligned team would formalise the 10-item
vulnerability table in README.md as a reusable **Application Security
Control Library**, and repeat the identify → fix → verify cycle continuously
(e.g. on every new feature), rather than once for a course project.

---

## 5. DevSecOps, Shift-Left, and the SSDLC — where TaskForge sits

**What actually happened (honest account):** Phase 1 was built *without*
threat modelling — vulnerabilities were seeded deliberately, but the process
mirrors a real "shift-right" failure mode: security was considered only
*after* the build, in Phase 2. This is intentional pedagogically, but it's
also the exact anti-pattern DevSecOps exists to prevent.

**Mapping the capstone phases onto the SSDLC:**

| SSDLC phase | Capstone phase | What actually happened |
|---|---|---|
| Requirements | *(missing from this exercise)* | No security requirements were defined before Phase 1 |
| Design | *(missing — done retroactively in §3)* | STRIDE modelling should have preceded the build |
| Implementation | Phase 1 → Phase 2 | Secure coding practices applied only in Phase 2 |
| Testing | Phase 3 | Burp/sqlmap/ffuf/DevTools pentesting |
| Deployment/Maintenance | *(not exercised)* | No CI/CD, no monitoring, no patch process implemented |

**What genuine shift-left would change:** threat modelling (§3) and the SAMM
Design-function checks would happen *before* Phase 1's first line of code,
so vulnerabilities like the SQLi login bypass would be caught in a design
review rather than discovered by a pentester in Phase 3. A DevSecOps pipeline
for this project would add, at minimum: automated dependency scanning (moot
here since TaskForge has zero external dependencies — itself a deliberate
supply-chain risk reduction), SAST on every commit, and a pre-merge check
that rejects string-concatenated SQL (a linting rule could catch the exact
pattern used in Phase 1's `handleLogin`).

---

## 6. Real-World Case Studies, Mapped to TaskForge's Actual Findings

Rather than generic case studies, each one below is chosen because it
mirrors a vulnerability class *actually present* in this codebase.

### RockYou (2009) ↔ TaskForge's plaintext password storage
RockYou's database of roughly 32 million user passwords was stored in
plaintext and stolen via a SQL Injection attack, exposing passwords instantly
usable across every other site because of password reuse. This is
structurally identical to Phase 1's `db.js` seed data and `handleRegister`
— TaskForge's `GET /api/users` exposing plaintext passwords in Phase 1 was
not a contrived worst case; it is what actually happened at scale.

### First American Financial Corp (2019) ↔ TaskForge's IDOR
A misconfigured web application allowed anyone with a valid document link to
change the number in the URL and access roughly 885 million other customers'
sensitive title-insurance documents — a textbook Insecure Direct Object
Reference, with no authentication or authorization check on the document ID
at all. This is the same flaw class as Phase 1's `handleGetTasks` /
`handleUpdateTask`: any logged-in user could access or modify any task by
simply changing the numeric ID.

### Samy Worm / MySpace (2005) ↔ TaskForge's stored XSS
A self-propagating stored XSS payload placed in a MySpace profile executed
in the browser of anyone who viewed that profile, eventually adding over a
million friends within about 20 hours. It's a direct precedent for Phase 1's
comment field: an unescaped `<script>` stored via `POST
/api/tasks/:id/comments` and rendered via `innerHTML` in `app.js` would
execute identically for every user who viewed that task.

### Capital One (2019) ↔ (adjacent lesson on trust boundaries)
A misconfigured Web Application Firewall combined with a Server-Side Request
Forgery vulnerability let an attacker reach internal cloud metadata and
exfiltrate data on roughly 100 million customers. TaskForge doesn't include
an SSRF-vulnerable feature, but the underlying lesson — a single missing
boundary check at one layer (the WAF/proxy) undermining the whole system —
is the same class of failure as TaskForge's missing role check in
`handleGetUsers`: one omitted `if` statement removed the entire access
control model for that endpoint.

### Log4Shell (2021) ↔ TaskForge's zero-dependency design (a deliberate contrast)
Log4Shell was a critical remote-code-execution flaw in a ubiquitous logging
library, compromising systems that never wrote insecure code themselves —
the risk lived entirely in a third-party dependency. TaskForge was built
using only Node's built-in modules (`node:http`, `node:sqlite`,
`node:crypto`) specifically to eliminate this class of risk for a small
teaching project; a production system of any real size could not make that
same trade-off and would need the dependency/supply-chain scanning practices
named in Iteration 2 instead.

---

## Summary Table (for quick reference in a report)

| Course requirement | Where it's satisfied in this document |
|---|---|
| CIA Triad | §2 |
| STRIDE threat modelling | §3 |
| OWASP Top 10 | §4 (and README.md) |
| OWASP SAMM | §4 |
| NIST SSDF | §4 |
| ISO/IEC 27034 | §4 |
| DevSecOps / shift-left | §5 |
| SSDLC | §5 |
| Real-world case studies | §6 |
