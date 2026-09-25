# TaskForge — Phase 2 (Secured)

📄 See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the module map and why
the code is organized this way (separation of concerns).

📄 See **[SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md)** for the CIA
triad, STRIDE threat model, and framework discussion applied to this build
(Iteration 1).

📄 See **[ITERATION2_SECURE_CODING.md](./ITERATION2_SECURE_CODING.md)** for
how each Phase 1 vulnerability maps to a secure-coding practice fixed here
(Iteration 2).

📄 See **[../../iteration-3-web-app-pentesting/](../../iteration-3-web-app-pentesting/)**
for the pentest re-run against this build, confirming each Phase 1 exploit
is now blocked (Phases 3–4).

The same task/ticket manager as Phase 1, rebuilt: every vulnerability fixed,
and the previous single `server.js` split into `src/` modules by
responsibility — config, data access, auth, validation, output encoding,
middleware, services, and one controller per resource.

## Stack

Still plain Node.js — zero runtime dependencies (see `package.json` and
`ITERATION2_SECURE_CODING.md` for why that's itself a supply-chain
mitigation):
- `node:http` for the server
- `node:sqlite` (built into Node 22+) for storage
- Vanilla HTML/CSS/JS on the frontend

## Running it

```bash
node server.js
```
Then open `http://localhost:3001`. `taskforge.db` is created and seeded
automatically on first run.

**Seed accounts:**
| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| manager1 | manager123 | manager |
| employee1 | employee123 | employee |
| employee2 | employee123 | employee |

## Verifying the fixes

```bash
npm test                    # 17 automated security regression tests
bash scripts/sast-check.sh  # custom static analysis (Phase 1 anti-patterns)
npm audit                   # dependency/supply-chain check
```

`.github/workflows/ci.yml` runs all three automatically on every push — the
shift-left principle from Iteration 1, in practice.

## What changed from Phase 1

| Phase 1 issue | Phase 2 fix |
|---|---|
| Plaintext passwords | `scrypt` hashing, per-user salt (`src/auth/password-utils.js`) |
| SQL injection (login, search) | Parameterised queries everywhere (`src/db.js`, controllers) |
| Client-supplied role on registration | Role forced server-side; only `employee` on self-register |
| No server-side authorization checks | `requireAuth()` / `requireRole()` gate every privileged route (`src/middleware/require-auth.js`) |
| IDOR on tasks | Ownership/assignment checked before read/update/delete |
| Stored XSS in comments | Server-side `escapeHtml()` + client-side `textContent` (defense in depth) |
| Insecure session cookie | `HttpOnly; Secure; SameSite=Strict` |
| Permissive CORS | Origin allowlist |
| No input limits | Length/type validation on every field (`src/validation/validators.js`) |
| SSRF via link preview | Private-IP/loopback blocklist, scheme restriction (`src/ssrf-guard.js`) |
| No rate limiting | Login lockout after 5 failed attempts (`src/rate-limiter.js`) |

Full detail and reasoning for each: `ITERATION2_SECURE_CODING.md`.
