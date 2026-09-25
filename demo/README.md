# demo/

Tooling for presenting or recording TaskForge, not part of the app itself.

## `verify-fixes.sh`

Runs the 5 documented Phase 1 attacks (SQL injection, broken access control,
SSRF, CORS misconfiguration — XSS is shown separately, in-browser, since it
has no clean curl equivalent) against **both** builds and prints a plain
PASS/FAIL verdict for each, instead of you typing five separate curl
commands live.

**Requirements:** both servers already running, with a fresh database
(`rm -f taskforge.db && node server.js` in each phase folder first).

```bash
bash demo/verify-fixes.sh
```

Expected result on a fresh run: `8 checks passed, 0 checks failed`. It's
safe to re-run without restarting the servers — every check either targets
a fresh piece of data each phase seeds by default, or is naturally
idempotent (the delete check returns 200 whether or not the task still
exists, matching Phase 1's actual — also vulnerable — behavior of never
checking if a row existed before reporting success).
