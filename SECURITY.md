# Security

## Model
EmailSpamdetection runs as Google Apps Script inside the owner's Google account. Gmail access never leaves Google:
there is no server holding mailbox tokens, no password database and no public API. The dashboard is an Apps Script web
app deployed as *Execute as: Me / Who has access: Only myself*, and every dashboard call checks again that the signed-in
user is the owner. The Vercel site is static and holds no secrets: its copy button carries the app's code inside the page,
so setting up never sends anything anywhere.

The biggest remaining risk is the owner's Google account itself. Turn on 2-Step Verification.

## How each pre-launch item is handled
| Item | How |
| --- | --- |
| Authentication | Google sign-in and "Only myself" access, plus a server-side owner check in every API call, `setup` and `turnOff` (`requireUser_`). Denied attempts are logged. If Google still needs a permission, the app shows a link to Google's own sign-in page only (checked host). |
| API keys hidden | Optional VirusTotal / Safe Browsing keys live in the owner's private Apps Script storage: write-only from the page, masked, never logged. No keys in the repo or the website. |
| Database | No database and no spreadsheet. Data lives in the owner's own Apps Script user storage (`PropertiesService.getUserProperties`), stored as escaped JSON within Google's 9 KB per value and 500 KB per user limits; when full, the senders who email most are kept. |
| HTTPS | Google and Vercel serve HTTPS only. HSTS on the site. Unsubscribe requests go only to plain `https://` public hosts. |
| Passwords / reset links / session cookies | Not applicable: there are no app passwords or sessions. Google handles sign-in. |
| Server-side validation | Every API input is checked on the server: ids, actions, settings (types and ranges), list entries, draft ids. |
| XSS | The dashboard and the checker render all email text with `textContent`. Tested in a real browser with attack payloads. The site has a strict CSP. |
| Logging and monitoring | Recent activity on Home: quarantined mail, removals, unsubscribes, denied access, rate-limit hits, errors, outbox alerts (last 150). Alert email if the outbox looks hacked. |
| Admin routes | Every API function is owner-only. Internal functions end in `_`, so the page cannot call them. |
| Parameterized queries | Gmail searches are built only from validated addresses and fixed rules (`fromQuery_`, `reviewQuery_`). |
| Environment / settings | Settings are validated on load and save. Unsafe combinations are refused. The time zone sent by the page must match a strict pattern, and a bad one falls back to the default. |
| Rate limiting | 120 API calls a minute, tighter limits on removals, settings and unsubscribes (20 an hour). |
| CORS / CSRF | No `doPost` and no cross-site API. `doGet` never acts on parameters. Calls go through Google's `google.script.run`. |
| Security headers | Site: CSP (`default-src 'none'`, `connect-src 'none'`), HSTS, nosniff, `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP. Dashboard cannot be framed by other sites. |
| Uploads | Not applicable. Attachments are never opened or run. Zip files are read from their table of contents only, so zip bombs can't fill memory. |
| Prices and payments | Not applicable: free, no payments. |
| Debug off | Errors reach the page as plain sentences, never stack traces. No source maps. |
| Dependencies | None at runtime or for tests (`node:test`). CI fails if one is added without review. |
| Exposed files | Vercel serves only `public/` (built from `web/`, `src/Detect.gs` and the one-file app `app.txt`). The build refuses unexpected file types. |
| Secrets in git history | `.github/scripts/secret_scan.py` scans every commit on every branch, in CI on every push and weekly. |

## Reporting
Open a private security advisory on the repository.
