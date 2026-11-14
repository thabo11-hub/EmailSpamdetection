# EmailSpamdetection: rules for changing this code

This app can read, label and delete the owner's email. Treat every change as security-sensitive.

## Shape
- `src/Detect.gs`: detection rules. Pure JavaScript, no Google services. Also served to browsers as `detect.js`.
- `src/Code.gs`: Gmail, storage, triggers and the dashboard API. Runs as the owner in Apps Script.
- `public/app.txt` (built, not committed): the three `src/` files as ONE pasteable file, also embedded behind the site's Copy button.
- `src/Dashboard.html`: the private dashboard (Apps Script web app, "Only myself").
- `web/`: the public Vercel site. Static only: no server code, no secrets.

## Rules
1. Every function the dashboard calls starts with `api` and returns `guarded_(...)` (owner check, rate limit, plain errors). Every other function ends with `_` so `google.script.run` cannot reach it. `tests/security.test.mjs` enforces the list.
2. Never delete or trash mail without an explicit decision from the owner. The guard only labels and archives; removals come from "Remove" in the review list, a block, or a quarantine action.
3. Build Gmail searches only through `fromQuery_` / `reviewQuery_` from validated parts. Never from stored text or the page.
4. Store data only through `storeSet_` / `storeGet_` (user properties, chunked, 500 KB per user). Render in the dashboard only with `textContent` (the `h()` helper). No `innerHTML` with data.
5. Fetch only URLs that pass `safeHttpsUrl_`. Never log a URL that can carry an API key.
6. API keys live in user properties, are write-only from the page and never appear in logs, activity or responses.
7. `doGet` must not act on its parameters. Do not add `doPost`.
8. No npm dependencies. Tests use `node:test`.
9. Keep `vercel.json` security headers. The site must keep `connect-src 'none'`: the checker never sends what people paste.
10. The one-file install must keep working: no top-level code in `Code.gs` that depends on file order, and `dashboardOutput_` must handle both `DASHBOARD_HTML` and `Dashboard.html`.

## Before a PR
`npm test`, then `npm run test:browser`, then `python3 .github/scripts/secret_scan.py`. CI runs the same.
