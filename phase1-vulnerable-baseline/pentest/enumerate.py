#!/usr/bin/env python3
"""
enumerate.py — a minimal ffuf-equivalent for this environment.

This sandbox has no outbound internet access, so the real `ffuf` binary
can't be installed here. This script does the same core job against a
locally-running TaskForge instance: take a wordlist, request each entry,
and report status code + content length so a real endpoint can be told
apart from a 404.

The exact real-world command this replaces is documented at the bottom of
this file and in ITERATION3_PENTEST_GUIDE.md - run that instead when ffuf
is actually available (e.g. on a Kali box or after `apt install ffuf`).

Usage:
    python3 enumerate.py http://localhost:3000 wordlist.txt
    python3 enumerate.py http://localhost:3000 wordlist.txt --cookie "tf_session=..."
"""
import sys
import requests

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <base_url> <wordlist_file> [--cookie 'name=value']")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    wordlist_file = sys.argv[2]
    cookie = None
    if "--cookie" in sys.argv:
        cookie = sys.argv[sys.argv.index("--cookie") + 1]

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    with open(wordlist_file) as f:
        words = [w.strip() for w in f if w.strip()]

    print(f"{'STATUS':<8}{'LENGTH':<10}WORD")
    print("-" * 50)

    found = []
    for word in words:
        url = f"{base_url}/{word}"
        try:
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            length = len(r.content)
            # A 404 with a near-identical body size to other 404s is noise;
            # anything else is worth a closer look, same triage ffuf gives you.
            marker = "  <-- interesting" if r.status_code != 404 else ""
            print(f"{r.status_code:<8}{length:<10}{word}{marker}")
            if r.status_code != 404:
                found.append((word, r.status_code, length))
        except requests.RequestException as e:
            print(f"ERR     -         {word}  ({e})")

    print("\n=== Summary: non-404 endpoints found ===")
    for word, status, length in found:
        print(f"  {status}  {word}  ({length} bytes)")

if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# Real-world equivalent (run this instead when ffuf is actually available):
#
#   ffuf -u http://localhost:3000/FUZZ -w wordlist.txt -mc all -fc 404
#
# Authenticated enumeration (pass a session cookie, matching -c above):
#
#   ffuf -u http://localhost:3000/FUZZ -w wordlist.txt -mc all -fc 404 \
#        -b "tf_session=<value-from-devtools-or-burp>"
# ---------------------------------------------------------------------------
