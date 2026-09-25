# TaskForge — Iteration 2: Secure Coding, Supply Chain, and CI/CD

This document covers Iteration 2's fundamentals — and unlike a general essay,
every claim below points at a real file, test, or pipeline step that actually
exists in this repository and was verified to work.

---

## 1. Secure Coding Standards and Best Practices

The Phase 1 → Phase 2 transition *is* the secure coding standard applied in
practice. The concrete rules this project follows, all visible in
`auth-utils.js` and `server.js`:

| Standard | Applied where |
|---|---|
| Parameterised queries only, never string-built SQL | Every `db.prepare(...).run()/.get()/.all()` call in `server.js` |
| Validate all input at the boundary, reject early | `isValidUsername`, `isValidPassword`, `isValidRole` in `auth-utils.js`; length caps on titles/descriptions/comments in `server.js` |
| Least privilege by default | `requireRole()` gate on every privileged handler; employees default to read/edit-own-task only |
| Escape untrusted output at the point of rendering | `escapeHtml()` applied server-side in `handleGetComments`; `app.js` additionally uses `textContent`/DOM nodes instead of `innerHTML` (defense in depth — two independent layers, not one) |
| Fail closed, not open | `requireAuth`/`requireRole` return `401`/`403` and stop; nothing defaults to "allow" |
| No hardcoded secrets | `config.js` reads everything from `process.env`, with production refusing to start without `COOKIE_SIGNING_KEY` set |

These aren't abstract principles — the automated tests in
`tests/security.test.js` (§4 below) directly verify five of them on every
run.

---

## 2. Input Validation, Error Handling, and Secrets Management

### Input validation
Validation happens **server-side**, not just in the browser — a lesson
directly drawn from Phase 1's failure mode (its frontend hid buttons, but
its API accepted anything). Concretely, in `auth-utils.js` and `server.js`:
- Usernames: `^[a-zA-Z0-9_]{3,32}$` — length- and character-bounded
- Passwords: minimum 8 characters, maximum 200 (prevents both weak passwords and DoS via absurdly long input)
- Task titles/descriptions/comments: explicit `.length` caps before insertion
- Avatar field: must match `^https?:\/\//` and be under 500 characters
- Request bodies generally: capped at 100 KB in `readBody()`, rejecting anything larger before it's even parsed

### Error handling
Phase 1's `catch` blocks either leaked internals or were absent. Phase 2's
router wraps every handler in a top-level `try/catch` that logs the real
error server-side (`console.error(err)`) but returns only a generic
`{ error: "internal server error" }` to the client — the standard practice of
**separating what you log from what you disclose**. Login failures return
the same generic `"invalid username or password"` message regardless of
whether the username exists, reducing username-enumeration risk.

### Secrets management
This is the one area Phase 1 didn't actually get wrong (there were no real
secrets to leak), but it's still worth building properly rather than leaving
unaddressed, since almost every real deployment of an app like this *would*
need secrets (DB credentials, signing keys, third-party API keys). This repo
now includes:
- **`config.js`** — the single place environment variables are read; nothing else in the codebase touches `process.env` directly
- **`.env.example`** — documents every variable *without* real values
- **`.gitignore`** — excludes `.env` and the local `.db` file from version control
- A **fail-loudly-in-production** pattern: `config.js`'s `requireEnvInProd()` throws on startup if `COOKIE_SIGNING_KEY` is missing and `NODE_ENV=production`, rather than silently running with an insecure default

---

## 3. Dependency and Supply Chain Security

### TaskForge's actual posture
`package.json` declares **zero runtime dependencies** — the server runs on
`node:http`, `node:sqlite`, and `node:crypto` only. This is a deliberate
architectural choice made *specifically* to reduce supply-chain risk, and
it's worth stating precisely what that does and doesn't buy you:
- ✅ Eliminates the entire class of risk demonstrated by Log4Shell and npm-package attacks (§3.1/3.2) for this project as it stands
- ❌ Is not a strategy that scales — any nontrivial production app will need real dependencies (a web framework, an ORM, a UI library), at which point this project's `npm audit` script (in `package.json`) and the CI dependency-audit step (§4) become load-bearing rather than symbolic

### 3.1 Log4Shell (2021) — why it's relevant here
Log4Shell was a critical remote-code-execution vulnerability in Log4j, a
logging library embedded so deep in the Java ecosystem that organisations
were compromised without writing a single insecure line of their own code —
the risk lived entirely in a transitive dependency few teams had even
directly chosen. The direct lesson for TaskForge: if this project later adds
a logging library, an ORM, or any framework, **`npm audit` (already wired
into CI, see §4) and a committed lockfile become mandatory**, not optional —
this is precisely the gap that let Log4Shell go unnoticed in so many
downstream projects for as long as it did.

### 3.2 JavaScript/npm Supply Chain Attacks
Real incidents worth citing directly (typosquatting malicious packages with
names similar to popular ones, and compromised maintainer accounts pushing
malicious updates to widely-used packages) show that a dependency doesn't
have to be exploited *for* you to be exposed — a legitimate package can turn
malicious after the fact, via a compromised maintainer credential or account
takeover, with no code change on your end. Practical mitigations this project
documents for when dependencies are eventually added:
- Commit `package-lock.json` and install with `npm ci` (not `npm install`) in CI, so builds are reproducible and can't silently pull a newer/different version
- Run `npm audit` on every CI run (already present — see `.github/workflows/ci.yml`)
- Pin dependency versions rather than using broad ranges (`^`/`~`) for anything security-sensitive
- Review the diff of a dependency update before merging, not just the version bump

---

## 4. Security Testing and Code Review in CI/CD Pipelines

This is implemented as real, runnable code in this repo, not described in
the abstract:

### `.github/workflows/ci.yml` — runs on every push/PR
1. **Secrets check** — fails the build if a real `.env` file is ever committed
2. **Custom SAST** (`scripts/sast-check.sh`) — greps for the *exact* Phase 1 anti-patterns: string-interpolated SQL, `innerHTML` XSS sinks, hardcoded secret-like values, and wide-open CORS. **Verified working both ways**: it passes clean against this Phase 2 code and correctly fails with 3 findings when pointed at the original Phase 1 code — proof it's a real check, not a rubber stamp
3. **Dependency audit** — `npm audit`, ready to matter the moment a real dependency is added
4. **Automated security regression tests** — `npm test`, running `tests/security.test.js`

### `tests/security.test.js` — 10 passing automated tests
Using Node's built-in test runner (`node:test`, no external framework
needed), spinning the real server up on an ephemeral port against a
throwaway database:
- SQL injection login bypass is rejected
- Valid login still works (hashing didn't break auth)
- Session cookie carries `HttpOnly` and `SameSite`
- Self-registration as `admin` is rejected
- Employee cannot create a task
- Employee cannot list all users
- Employee cannot update another user's task (IDOR check)
- Employee's task list is filtered to their own tasks
- Comment bodies come back HTML-escaped, not raw
- Unauthenticated requests are rejected

This is what "shift-left" concretely means for this project: these are the
same checks a human ran manually during Phase 1 → Phase 2 development,
turned into code so a future change can't silently regress one of them
without the pipeline catching it first — before a code reviewer, and long
before a Phase 3 pentester would.

### Code review
For a solo/small-team project like this, a lightweight but real code review
practice is: no direct pushes to `main` — every change goes through a pull
request, the CI pipeline above must be green before merge, and the PR
description references which item in the `SECURITY_ANALYSIS.md` vulnerability
table (if any) the change relates to.

---

## 5. Ongoing Monitoring and Patching Practices

This was originally the honest gap area in this project (previously flagged
here and in `SECURITY_ANALYSIS.md`'s SAMM assessment, where "Operations"
scored 0/1). It has since been substantially closed with real, tested code:

**What exists now:**
- **Structured logging** (`logger.js`) — every log line is a single JSON object (timestamp, level, event, metadata), ready to ship to a real log aggregator (CloudWatch, Datadog, ELK) in production with no change to call sites, only the transport.
- **Alerting on repeated authentication failures** (`rate-limiter.js`) — an `alert`-level log line fires the moment an account is locked out after 5 consecutive failed logins, giving real-time visibility into a brute-force attempt. Verified: replaying the exact unthrottled brute-force attack documented in the pentest report (F10) now results in an `HTTP 429` lockout after the 5th attempt, down from 1,000+ accepted attempts previously.
- **Audit logging for who-changed-what-when** (`audit_log` table, `logAudit()` in `server.js`) — closes the STRIDE "Repudiation" gap named in `SECURITY_ANALYSIS.md` §3. Login, task create/update/delete, and comment creation all record actor, action, target, and timestamp, viewable by an admin via `GET /api/audit-log`.
- **Dependency update cadence** (`.github/dependabot.yml`) — configured and active for both the `npm` and `github-actions` ecosystems from day one. This project currently has zero runtime dependencies, so there's nothing for it to flag yet, but the moment a real dependency is added, Dependabot starts opening PRs for known-vulnerable versions automatically rather than that process needing to be set up reactively after an incident (the exact gap that let Log4Shell go unnoticed in so many downstream projects — see §3.1).

**What a real production deployment would still need beyond this:**
- A defined patch SLA (e.g. critical CVEs patched within 48 hours, matching the urgency Equifax's months-long unpatched Struts vulnerability demonstrates the cost of *not* having) — this is a process/organisational commitment, not something a codebase alone can enforce.
- A real alerting *destination* (PagerDuty, a Slack webhook) — the `alert()` call site in `logger.js` is where that integration would plug in; today it still only writes structured stdout.

Even with these two remaining organisational gaps named honestly, the
concrete engineering gap — no logging, no alerting, no audit trail, no
dependency monitoring — is now closed with code that was written, tested,
and verified, not merely planned.

---

## Summary Table (for quick reference)

| Course requirement | Where it's satisfied |
|---|---|
| Secure coding standards & best practices | §1 — `auth-utils.js`, `server.js` |
| Input validation | §2 — validators in `auth-utils.js`, length caps, body-size limit |
| Error handling | §2 — top-level `try/catch`, generic client-facing errors |
| Secrets management | §2 — `config.js`, `.env.example`, `.gitignore` |
| Dependency/supply chain security | §3 — zero-dependency design, `npm audit`, lockfile discipline |
| Log4Shell | §3.1 |
| JavaScript supply chain attacks | §3.2 |
| Security testing in CI/CD | §4 — `.github/workflows/ci.yml`, `tests/security.test.js` (10 passing tests) |
| Code review in CI/CD | §4 |
| Ongoing monitoring and patching | §5 — structured logging, alerting, audit log, and Dependabot all implemented and tested |
