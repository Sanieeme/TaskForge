#!/bin/bash
# scripts/sast-check.sh
#
# A deliberately simple, dependency-free static analysis check. It won't
# catch everything a real SAST tool (Semgrep, CodeQL, Snyk Code, etc.) would,
# but it directly encodes the exact anti-patterns that caused the 10 Phase 1
# vulnerabilities - so if any of them are reintroduced, this fails the build
# before it ever reaches code review or Phase 3 pentesting.
#
# This is what "shift-left" and "security testing in CI/CD" (Iteration 2)
# look like as an actual, runnable artifact rather than a slide.

set -euo pipefail
FAIL=0

echo "== Custom SAST check =="

# All server-side source now lives under src/ (plus the thin server.js
# entry point) since the Separation-of-Concerns refactor - scan both.
SRC="server.js src"

# 1. SQL built by string interpolation/concatenation instead of parameters.
#    Catches the exact Phase 1 pattern: `... WHERE username = '${username}'`
if grep -rnE '(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{' --include="*.js" $SRC 2>/dev/null; then
  echo "FAIL: possible SQL built via string interpolation (use db.prepare(...).run(param) instead)"
  FAIL=1
fi

# 2. innerHTML assignment with a variable (potential DOM-based/stored XSS sink)
if grep -rnE '\.innerHTML\s*=.*\$\{' --include="*.js" public/ 2>/dev/null; then
  echo "FAIL: innerHTML assigned with interpolated content (XSS sink) - use textContent or escape first"
  FAIL=1
fi

# 3. Hardcoded secret-looking values (very naive, but catches obvious cases)
if grep -rnE '(password|secret|api[_-]?key)\s*[:=]\s*["'"'"'][^"'"'"']{6,}["'"'"']' \
    --include="*.js" $SRC 2>/dev/null \
    | grep -v -E '(process\.env|SESSION_SIGNING|dev-only-insecure-key|isValidPassword|hashPassword|verifyPassword|password_hash|password_salt)'; then
  echo "FAIL: possible hardcoded secret - move it to an environment variable (see src/config.js)"
  FAIL=1
fi

# 4. Wide-open CORS (reflects any Origin with credentials) - the Phase 1 pattern
if grep -rnE "Access-Control-Allow-Origin.*req\.headers\.origin \|\| .\*." --include="*.js" $SRC 2>/dev/null; then
  echo "FAIL: CORS reflects any Origin - use an explicit allowlist (see src/http/cors.js)"
  FAIL=1
fi

# 5. SSRF: a fetch() of a user-supplied URL with no safety check nearby.
#    This is a heuristic (it just checks a safety-check call appears
#    somewhere in the same file) rather than true taint tracking, but it
#    catches the exact Phase 1 pattern of fetching `url` directly.
if grep -rn 'await fetch(url' $SRC 2>/dev/null | grep -q .; then
  if ! grep -rq 'checkUrlIsSafe' $SRC 2>/dev/null; then
    echo "FAIL: fetch(url) on user input with no SSRF safety check (see src/ssrf-guard.js) found nearby"
    FAIL=1
  fi
fi

if [ "$FAIL" -eq 0 ]; then
  echo "PASS: no known Phase 1 anti-patterns detected"
fi

exit $FAIL
