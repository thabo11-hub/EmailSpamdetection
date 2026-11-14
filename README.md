# EmailSpamdetection

Keeps phishing, scams and junk out of your Gmail, from inside your own Google account.

- **Inbox guard:** every few minutes it checks new mail for fake senders, look-alike domains, failed sender checks, risky links and dangerous attachments (including inside zip files). Risky mail moves out of your inbox to `EmailSpamdetection/Dangerous` or `EmailSpamdetection/Check first`. Nothing is deleted.
- **Websites:** every website and mailing list that emails you, how much of it you open, and one-tap unsubscribe (the safe one-click standard) or block.
- **Review before removing:** suggestions such as old promotions, old login codes and big attachments. Nothing is removed until you press Remove, and removed mail stays in Trash for 30 days.
- **Outbox watch:** alerts you if your sent mail, drafts or scheduled emails look like someone else is using your account.
- **Public site** (`web/`, on Vercel): a home page, the setup guide and a "check a suspicious email" tool that runs entirely in the browser.

## Set it up (about 5 minutes, on a computer)
1. Create a Google Sheet called **EmailSpamdetection**.
2. Open **Extensions > Apps Script**. Replace `Code.gs` with `src/Code.gs`, then add `src/Detect.gs` (a script file) and `src/Dashboard.html` (an HTML file called `Dashboard`).
3. In **Project Settings**, tick "Show appsscript.json manifest file in editor", then paste `src/appsscript.json`.
4. Select `setup` and press **Run**. Allow access. Google shows "unverified app" because this is your own script: choose **Advanced > Go to EmailSpamdetection**.
5. **Deploy > New deployment > Web app**: *Execute as: Me*, *Who has access: Only myself*. Bookmark the link: that is your dashboard.

To switch it off: dashboard **Settings > Turn protection off**, or run `turnOff` in the editor.

## Develop
```
npm test                 # attack + detection + end-to-end tests (no dependencies)
npm run test:browser     # builds the site, then a real-browser XSS test (needs Playwright)
python3 .github/scripts/secret_scan.py
```
Security model and checklist: [SECURITY.md](SECURITY.md). Rules for changes: [CLAUDE.md](CLAUDE.md).
