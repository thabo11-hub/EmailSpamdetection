// Detection: real-world style phishing must be caught, and the real legitimate mail it was
// tuned on (Uber, Booking.com, Supabase, Google Play, GitHub, Samsung...) must not be.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadApp, AUTH_PASS, AUTH_FAIL, fixture } from './harness.mjs';

const { app } = loadApp();
const score = (m, ctx) => app.scoreMessage_(Object.assign({ fromName: '', fromEmail: '', replyTo: '', subject: '', text: '', html: '', auth: AUTH_PASS, attachments: [] }, m), ctx || {});
const zip = (name) => Array.from(fixture(name)).map((b) => (b > 127 ? b - 256 : b));

test('legitimate mail from the inbox it was tuned on stays clean', () => {
  const legit = [
    { fromName: 'Uber Receipts', fromEmail: 'noreply@uber.com', subject: 'Payment failed - your Wednesday morning trip with Uber', text: 'You have an unfinished payment. Please review and pay.' },
    { fromName: 'Booking.com', fromEmail: 'noreply@booking.com', subject: 'Booking.com - New sign-in to your account', text: 'For security precautions, check to make sure your URL reads https://admin.booking.com when you sign in.' },
    { fromName: 'Supabase Auth', fromEmail: 'noreply@mail.app.supabase.io', subject: 'Reset your password', text: 'We received a request to reset your password. Follow the link below.', html: '<a href="https://abc.supabase.co/auth/v1/verify?token=x">Reset password</a>' },
    { fromName: 'Google Play', fromEmail: 'googleplay-noreply@google.com', subject: 'PUBG MOBILE subscription suspended due to payment issue', text: 'Your payment was declined. To keep your subscription active, please change the payment method.' },
    { fromName: 'vercel[bot]', fromEmail: 'notifications@github.com', subject: 'Re: [thabo11-hub/event-pulse] Deploy preview ready', text: 'Preview: https://event-pulse-git-x.vercel.app' },
    { fromName: 'Samsung account', fromEmail: 'sa.noreply@samsung-mail.com', subject: 'New sign-in to your Samsung account', text: 'Your Samsung account was signed in to from a new device.' },
    { fromName: 'Mia from Higgsfield', fromEmail: 'mia@team.higgsfield.ai', subject: 'Final notice: Your last chance to get into Higgsfield with the lowest price', text: '62% off expires tonight at midnight.' },
    { fromName: 'IBM', fromEmail: 'ibmacct@iam.ibm.com', subject: 'Verify your identity', text: 'Please use the following verification code: V5824. It will expire after 20min.' },
    { fromName: 'Meta for Business', fromEmail: 'advertise-noreply@global.metamail.com', subject: 'Grow your business', text: 'Boost your post today.' },
    { fromName: 'Mpho Mangena', fromEmail: 'mpho@gmail.com', subject: 'Logos', text: 'Please see the attached logos', attachments: [{ name: 'logo.png' }, { name: 'brief.pdf' }] },
    { fromName: 'Takealot', fromEmail: 'deals@newsletters.takealot.com', subject: 'Deals', html: '<a href="https://click.takealot.com/x">www.takealot.com</a>' },
  ];
  for (const m of legit) {
    const r = score(m);
    assert.equal(r.level, 'clean', `${m.fromEmail} "${m.subject}" scored ${r.score}: ${r.reasons.join(' | ')}`);
  }
});

test('brand impersonation and look-alike domains are caught', () => {
  const cases = [
    [{ fromName: 'PayPal', fromEmail: 'service@paypa1.com', auth: AUTH_FAIL, subject: 'Your account is limited', text: 'Click here to verify your account within 24 hours', html: '<a href="http://paypa1.com/login">https://www.paypal.com/signin</a>' }, 'dangerous'],
    [{ fromName: 'Absa Bank', fromEmail: 'absa.alerts@gmail.com', auth: 'dmarc=pass', subject: 'Account suspended', text: 'Your account has been suspended. Verify your identity to restore access.' }, 'dangerous'],
    [{ fromName: 'SARS eFiling', fromEmail: 'refunds@sars-efiling.com', subject: 'Tax refund approved', text: 'Your tax refund is pending. Click here to verify your banking details.' }, 'dangerous'],
    [{ fromName: 'Booking.com Partner Help', fromEmail: 'noreply@booking-guest-review.com', subject: 'Guest complaint', text: 'A guest has reported a problem. Verify your property within 24 hours or your listing will be suspended.', html: '<a href="https://booking-guest-review.com/extranet">Open extranet</a>' }, 'dangerous'],
    [{ fromName: 'Netflix', fromEmail: 'billing@netf1ix.com', subject: 'Payment declined', text: 'Update your payment details to keep watching.' }, 'dangerous'],
    [{ fromName: 'FNB', fromEmail: 'alerts@fnbsecure.co.za', subject: 'OTP needed', text: 'Reply with your OTP to cancel this transaction.' }, 'dangerous'],
  ];
  for (const [m, level] of cases) {
    const r = score(m);
    assert.equal(r.level, level, `${m.fromEmail} scored ${r.score}: ${r.reasons.join(' | ')}`);
  }
});

test('dangerous attachments are caught even from trusted senders', () => {
  const exe = score({ fromName: 'Friend', fromEmail: 'friend@example.org', attachments: [{ name: 'invoice.pdf.exe' }] }, { allowed: true });
  assert.equal(exe.level, 'dangerous');
  assert.match(exe.reasons[0], /Disguised file/);
  const rtlo = score({ fromEmail: 'x@example.org', attachments: [{ name: 'invoice‮fdp.exe' }] });
  assert.equal(rtlo.level, 'dangerous');
  assert.equal(score({ fromEmail: 'x@example.org', attachments: [{ name: 'scan.html' }] }).level, 'suspicious');
  assert.equal(score({ fromEmail: 'x@example.org', attachments: [{ name: 'Q3.xlsm' }] }).level, 'suspicious');
  assert.equal(score({ fromEmail: 'x@example.org', attachments: [{ name: 'photo.jpg' }, { name: 'notes.pdf' }] }).level, 'clean');
});

test('zip files are read without unpacking: malware inside, password locks and zip bombs', () => {
  const ok = app.zipEntries_(zip('report.zip'));
  assert.deepEqual(Array.from(ok.names), ['report.pdf']);
  assert.equal(ok.encrypted, false);
  assert.equal(score({ fromEmail: 'x@example.org', attachments: [{ name: 'report.zip', inner: ok }] }).level, 'clean');

  const evil = app.zipEntries_(zip('evil.zip'));
  const r = score({ fromEmail: 'x@example.org', attachments: [{ name: 'documents.zip', inner: evil }] });
  assert.equal(r.level, 'dangerous');
  assert.match(r.reasons[0], /payment\.js|\.js/);

  const locked = app.zipEntries_(zip('locked.zip'));
  assert.equal(locked.encrypted, true);
  assert.equal(score({ fromEmail: 'x@example.org', attachments: [{ name: 'secret.zip', inner: locked }] }).level, 'suspicious');

  const bomb = app.zipEntries_(zip('bomb.zip'));
  assert.equal(bomb.bomb, true);
  assert.equal(app.zipEntries_([1, 2, 3]), null);   // garbage is "unreadable", never a crash
});

test('link tricks are caught', () => {
  assert.ok(score({ fromEmail: 'x@example.org', html: '<a href="javascript:alert(1)">Open</a>' }).reasons.some((x) => /runs code/.test(x)));
  assert.ok(score({ fromEmail: 'x@example.org', html: '<a href="http://185.22.1.9/login">Sign in</a>' }).reasons.some((x) => /IP address/.test(x)));
  assert.ok(score({ fromEmail: 'x@example.org', html: '<a href="https://www.paypal.com@evil.example/x">PayPal</a>' }).reasons.some((x) => /"@"/.test(x)));
  assert.ok(score({ fromEmail: 'x@example.org', html: '<a href="https://xn--pypal-4ve.com/">paypal</a>' }).reasons.some((x) => /xn--/.test(x)));
  const mismatch = score({ fromEmail: 'x@example.org', auth: 'dmarc=fail', html: '<a href="https://evil.example/a">https://www.absa.co.za</a>' });
  assert.ok(mismatch.reasons.some((x) => /shows www\.absa\.co\.za but really goes to evil\.example/.test(x)));
});

test('a known contact is trusted more, a first-time sender less', () => {
  const m = { fromName: 'Ann', fromEmail: 'ann@example.org', subject: 'Urgent', text: 'Act now: confirm your details' };
  assert.ok(score(m, { knownContact: true }).score < score(m).score);
  assert.ok(score(m, { firstTime: true }).score > score(m).score);
});

test('helpers: addresses, domains and URLs', () => {
  assert.deepEqual({ ...app.parseAddress_('"PayPal Support" <Service@PayPa1.com>') }, { name: 'PayPal Support', email: 'service@paypa1.com' });
  assert.equal(app.rootDomain_('e.fnb.co.za'), 'fnb.co.za');
  assert.equal(app.rootDomain_('mail.app.supabase.io'), 'supabase.io');
  assert.equal(app.lookalike_('paypal.com'), null);
  assert.equal(app.lookalike_('paypa1.com').points, 60);
  assert.equal(app.lookalike_('absa-secure.com').brand.name, 'Absa');
  assert.equal(app.lookalike_('fabsalon.com'), null);
});
