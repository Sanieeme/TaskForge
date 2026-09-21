WTC-76Z77SB5

# TaskForge — Complete Capstone Package

Secure Web App Development and Penetration Testing Lifecycle: everything
produced across all 4 capstone phases and all 3 course iterations, in one
package.

## Structure

```
TaskForge_Penetration_Test_Report.docx      <- Phase 4 deliverable (start here for grading)
Iteration1_Cybersecurity_Fundamentals.md    <- standalone Iteration 1 theory doc

phase1-vulnerable-baseline/                 <- Phase 1 + intentional vulnerabilities
├── server.js, db.js, public/                  the app itself
├── README.md                                  vulnerability table (11 findings)
├── SECURITY_ANALYSIS.md                        Iteration 1 content, tied to this code
├── pentest/                                    Iteration 3 tooling + guide + the report

phase2-secured/                             <- Phase 2 + Phase 3 verification
├── server.js                                  thin entry point (~20 lines)
├── src/                                        Separation-of-Concerns layout:
│   ├── config.js, db.js                          config + data access
│   ├── auth/                                     password hashing, sessions
│   ├── validation/, utils/                       input validators, HTML escaping
│   ├── middleware/require-auth.js                the one place authorization is decided
│   ├── services/audit-service.js                 audit logging
│   ├── controllers/                              one file per resource (auth, tasks, comments, users, audit)
│   └── http/                                     router, response/body helpers, CORS, static files
├── ARCHITECTURE.md                              explains every module boundary and why
├── public/                                      the fixed frontend
├── tests/security.test.js                       17 automated regression tests
├── scripts/sast-check.sh                        custom static analysis
├── .github/workflows/ci.yml                     CI/CD pipeline
├── .github/dependabot.yml                       dependency monitoring
├── SECURITY_ANALYSIS.md, ITERATION2_SECURE_CODING.md
├── pentest/                                     same Iteration 3 materials, re-verified against this build

iteration3-pentest-standalone/              <- Iteration 3 as its own submission, if needed separately
├── README.md, ITERATION3_PENTEST_GUIDE.md
├── enumerate.py, sqli_check.py, wordlist.txt
├── taskforge.postman_collection.json
├── TaskForge_Penetration_Test_Report.docx
```

## Quick start

```bash
# Run the vulnerable baseline
cd phase1-vulnerable-baseline && node server.js   # http://localhost:3000

# Run the secured version (separate terminal)
cd phase2-secured && node server.js               # http://localhost:3001

# Run the automated security test suite
cd phase2-secured && npm test                     # 17 tests

# Run the custom SAST check
cd phase2-secured && bash scripts/sast-check.sh
```

Seed accounts (both apps): `admin/admin123`, `manager1/manager123`,
`employee1/employee123`, `employee2/employee123`.

## What's genuinely verified vs. simulated

Every vulnerability, every fix, and every automated test in this package was
actually run against a live instance during development — not written
speculatively. The one honest limitation: Burp Suite, ffuf, sqlmap, and a
real browser's DevTools could not run in the sandboxed environment this was
built in (no outbound internet access, confirmed by direct testing).
Functionally equivalent tooling (`enumerate.py`, `sqli_check.py`, and
`curl`-based header inspection) reproduces the same findings, with the real
tool commands documented alongside each substitute. See
`pentest/ITERATION3_PENTEST_GUIDE.md` for full detail.
