// Smoke test: runs setup, the websites scan, the nightly job and every dashboard call end to end,
// so a typo in a rarely used path fails here instead of in your Google account.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadApp, makeMessage, OWNER, AUTH_PASS, DAY_MS } from './harness.mjs';

test('setup, scan, nightly and every dashboard call work end to end', () => {
  const { app, env } = loadApp({ setup: false });
  const ago = (d) => new Date(Date.now() - d * DAY_MS);
  for (let i = 0; i < 6; i++) {
    env.addThread(makeMessage({ from: 'Uber Eats <uber@uber.com>', subject: 'Deals ' + i, date: ago(40 + i), headers: { 'Authentication-Results': AUTH_PASS,
      'List-Unsubscribe': '<mailto:unsub@uber.com?subject=unsubscribe>, <https://uber.com/unsub?x=1>', 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } }),
    { category: 'promotions', inbox: false });
  }
  env.addThread(makeMessage({ from: 'Takealot <welcome@takealot.com>', subject: 'Welcome to Takealot', date: ago(900) }));
  env.addThread(makeMessage({ from: 'Mpho <mpho@gmail.com>', subject: 'Photos', date: ago(5) }));
  env.addThread(makeMessage({ from: 'PayPal <service@paypa1.com>', subject: 'Your account is limited', date: new Date(),
    plain: 'Click here to verify your account within 24 hours', headers: { 'Authentication-Results': 'dmarc=fail' } }));
  env.addDraft(makeMessage({ from: OWNER, subject: 'old CV', date: ago(800) }), 'r9');

  assert.match(app.setup(), /Protection is on/);
  assert.deepEqual(env.triggers.map((t) => t.getHandlerFunction()).sort(), ['runGuard', 'runNightly', 'runScanBatch']);
  assert.ok(env.labels.has('EmailSpamdetection/Dangerous') && env.labels.has('EmailSpamdetection/Check first'));
  assert.ok(env.threads.find((t) => /limited/.test(t.getFirstMessageSubject())).labels.has('EmailSpamdetection/Dangerous'), 'setup runs a first check');

  assert.equal(app.runScanBatch(), true, 'scan finishes on a small mailbox');
  assert.ok(!env.triggers.some((t) => t.getHandlerFunction() === 'runScanBatch'), 'scan trigger removed when done');
  const sites = app.apiWebsites().data;
  const uber = sites.find((s) => s.email === 'uber@uber.com');
  assert.equal(uber.emails, 6);
  assert.equal(uber.unsub, 'one-click');
  assert.equal(uber.suggestion, 'Unsubscribe');
  assert.ok(!sites.some((s) => s.email === 'mpho@gmail.com'), 'people are not listed as websites');
  assert.ok(sites.some((s) => s.site === 'takealot.com' && s.type.includes('Account')));

  app.runNightly();
  const review = app.apiReview().data;
  assert.ok(review.some((r) => r.key === 'sender:uber@uber.com'));
  assert.ok(review.every((r) => !r.decision), 'nothing is decided for you');
  assert.equal(env.trashed.length, 0, 'nothing removed without approval');

  for (const call of ['apiOverview', 'apiQuarantine', 'apiOutgoing', 'apiSettings', 'apiCheckNow']) {
    const r = app[call]();
    assert.equal(r.ok, true, call + ': ' + r.error);
  }
  assert.equal(app.apiOutgoing().data.drafts.filter((d) => d.old).length, 1);
  const q = app.apiQuarantine().data;
  assert.equal(q.dangerous.length, 1);
  assert.match(q.dangerous[0].reasons, /imitates PayPal|PayPal/);
  assert.equal(app.apiQuarantineAction(q.dangerous[0].id, 'restore', true).ok, true);
  assert.ok(app.getLists_().allow.includes('service@paypa1.com'));
  const overview = app.apiOverview().data;
  assert.ok(overview.activity.some((a) => a.event === 'Protection switched on'), 'Home shows recent activity');
  assert.equal(app.apiTurnOff().ok, true);
  assert.equal(env.triggers.length, 0);
  assert.equal(env.scriptProps.size, 0, 'everything is kept in your own user storage');
});
