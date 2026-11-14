# EmailSpamdetection

Keeps phishing, scams and junk out of your Gmail, from inside your own Google account.

- **Inbox guard:** every few minutes it checks new mail for fake senders, look-alike domains, failed sender checks, risky links and dangerous attachments (including inside zip files). Risky mail moves out of your inbox to `EmailSpamdetection/Dangerous` or `EmailSpamdetection/Check first`. Nothing is deleted.
- **Websites:** every website and mailing list that emails you, how much of it you open, and one-tap unsubscribe (the safe one-click standard) or block.
- **Review before removing:** suggestions such as old promotions, old login codes and big attachments. Nothing is removed until you press Remove, and removed mail stays in Trash for 30 days.
- **Outbox watch:** alerts you if your sent mail, drafts or scheduled emails look like someone else is using your account.
- **Public site** (`web/`, on Vercel): the phone setup with a one-tap copy button, and a "check a suspicious email" tool that runs entirely in the browser.

## Set it up (3 steps, from your phone)
Go to the website and follow the three cards: **Copy the app**, **Open Google Apps Script** (paste over everything, save), then **Deploy > New deployment > Web app > Deploy**, allow access and tap **Turn on protection** in your new app. Keep the defaults *Execute as: Me* and *Who has access: Only myself*.

The copy button gives you `public/app.txt`: `src/Detect.gs`, `src/Code.gs` and `src/Dashboard.html` built into one file (`npm run build:web`), so there is only one thing to paste and no spreadsheet. Everything the app keeps (settings, senders, the clean-up list, recent activity) lives in your own private Apps Script storage.

On a computer you can also paste the three files separately: `Code.gs`, `Detect.gs` and an HTML file called `Dashboard`.

To switch it off: dashboard **More > Switch protection off**. To remove it completely, also remove its access at https://myaccount.google.com/connections.

## Develop
```
npm test                 # attack + detection + end-to-end tests (no dependencies)
npm run test:browser     # builds the site, then a real-browser XSS test (needs Playwright)
python3 .github/scripts/secret_scan.py
```
Security model and checklist: [SECURITY.md](SECURITY.md). Rules for changes: [CLAUDE.md](CLAUDE.md).
