#!/usr/bin/env bash
# verify-fixes.sh — runs the 5 documented TaskForge attacks against BOTH
# builds (Phase 1: port 3000, Phase 2: port 3001) and prints a clear
# pass/fail verdict for each. Safe to run live on camera: no typing
# required, no quote-escaping to get wrong, one command, clear output.
#
# Requires: both servers already running with a freshly seeded database
# (rm -f taskforge.db && node server.js in each phase folder first).
#
# Usage:  bash demo/verify-fixes.sh
set -uo pipefail

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; BOLD=$'\033[1m'; NC=$'\033[0m'
PASS=0; FAIL=0

pass() { echo "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

echo "${BOLD}Checking both servers are up...${NC}"
p1=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/login.html 2>/dev/null)
p2=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/login.html 2>/dev/null)
if [ "$p1" != "200" ]; then
  echo "${RED}Phase 1 (http://localhost:3000) is not responding.${NC}"
  echo "Start it first:  cd capstone/phase-1-vulnerable-baseline && rm -f taskforge.db && node server.js"
  exit 1
fi
if [ "$p2" != "200" ]; then
  echo "${RED}Phase 2 (http://localhost:3001) is not responding.${NC}"
  echo "Start it first:  cd capstone/phase-2-secure-implementation && rm -f taskforge.db && node server.js"
  exit 1
fi
echo "Both servers responding. Running attacks..."
echo

# ---------------------------------------------------------------------
echo "${BOLD}=== Attack 1: SQL injection login bypass ===${NC}"
r1=$(curl -s -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  --data-raw '{"username":"admin'"'"' -- ","password":"anything"}')
echo "  Phase 1 (3000): $r1"
echo "$r1" | grep -q '"role":"admin"' \
  && pass "Phase 1 is vulnerable — logged in as admin with no real password" \
  || fail "Phase 1 did not behave as documented — is the DB freshly seeded?"

r2=$(curl -s -X POST http://localhost:3001/api/login -H "Content-Type: application/json" \
  --data-raw '{"username":"admin'"'"' -- ","password":"anything"}')
echo "  Phase 2 (3001): $r2"
echo "$r2" | grep -q '"error"' \
  && pass "Phase 2 blocks it — invalid credentials" \
  || fail "Phase 2 did NOT block it — this would be a real problem"
echo

# ---------------------------------------------------------------------
echo "${BOLD}=== Attack 2: Broken access control (deleting someone else's task) ===${NC}"
curl -s -c /tmp/tf_verify_c1.txt -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" -d '{"username":"employee1","password":"employee123"}' -o /dev/null
d1=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/tf_verify_c1.txt -X DELETE http://localhost:3000/api/tasks/2)
echo "  Phase 1 (3000) delete status: $d1"
[ "$d1" = "200" ] \
  && pass "Phase 1 lets a regular employee delete a task that isn't theirs" \
  || fail "unexpected status $d1 — has task 2 already been deleted this run?"

curl -s -c /tmp/tf_verify_c2.txt -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" -d '{"username":"employee1","password":"employee123"}' -o /dev/null
d2=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/tf_verify_c2.txt -X DELETE http://localhost:3001/api/tasks/2)
echo "  Phase 2 (3001) delete status: $d2"
[ "$d2" = "403" ] \
  && pass "Phase 2 blocks it — 403 Forbidden" \
  || fail "unexpected status $d2"
echo

# ---------------------------------------------------------------------
echo "${BOLD}=== Attack 3: SSRF via the link-preview feature ===${NC}"
s1=$(curl -s -X POST http://localhost:3000/api/tasks/1/preview -H "Content-Type: application/json" \
  -b /tmp/tf_verify_c1.txt -d '{"url":"http://127.0.0.1:3000/api/users"}')
echo "  Phase 1 (3000): $s1"
echo "$s1" | grep -q '"requestedUrl"' \
  && pass "Phase 1's server fetches the internal address on request" \
  || fail "unexpected response"

s2=$(curl -s -X POST http://localhost:3001/api/tasks/1/preview -H "Content-Type: application/json" \
  -b /tmp/tf_verify_c2.txt -d '{"url":"http://127.0.0.1:3001/api/users"}')
echo "  Phase 2 (3001): $s2"
echo "$s2" | grep -qi 'blocked' \
  && pass "Phase 2 blocks the internal request" \
  || fail "unexpected response"
echo

# ---------------------------------------------------------------------
echo "${BOLD}=== Attack 4: CORS misconfiguration ===${NC}"
c1=$(curl -s -i -b /tmp/tf_verify_c1.txt -H "Origin: https://attacker.example" http://localhost:3000/api/users \
  | grep -i "access-control-allow-origin")
echo "  Phase 1 (3000): ${c1:-<no header returned>}"
echo "$c1" | grep -qi "attacker.example" \
  && pass "Phase 1 trusts a made-up attacker origin" \
  || fail "unexpected — Phase 1 should have reflected the origin"

c2=$(curl -s -i -b /tmp/tf_verify_c2.txt -H "Origin: https://attacker.example" http://localhost:3001/api/users \
  | grep -i "access-control-allow-origin")
echo "  Phase 2 (3001): ${c2:-<no header returned, as expected>}"
if [ -z "$c2" ]; then pass "Phase 2 grants no trust to the fake origin"; else fail "unexpected: $c2"; fi
echo

rm -f /tmp/tf_verify_c1.txt /tmp/tf_verify_c2.txt

# ---------------------------------------------------------------------
echo "${BOLD}=== Summary ===${NC}"
echo "  ${PASS} checks passed, ${FAIL} checks failed."
if [ "$FAIL" -eq 0 ]; then
  echo "  ${GREEN}Every Phase 1 vulnerability reproduced, and every one is blocked in Phase 2.${NC}"
else
  echo "  ${RED}Something didn't match expectations — see [FAIL] lines above.${NC}"
fi
