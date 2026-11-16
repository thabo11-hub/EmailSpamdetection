/**
 * EmailSpamdetection: keeps your Gmail safe and tidy, from inside your own Google account.
 *
 *  - Inbox guard: every few minutes it checks new mail for phishing, scams and dangerous
 *    attachments, and moves anything risky out of your inbox before you open it. Nothing is deleted.
 *  - Senders: every website and mailing list that emails you, with unsubscribe and block.
 *  - Clean up: suggests old mail to clear out. Nothing is removed until you approve it.
 *  - Outbox watch: checks sent mail, drafts and scheduled sends for signs that your account was hacked.
 *
 * Install from a phone: paste this one file into a new Apps Script project, deploy it as a web app,
 * open the link and tap "Turn on protection".
 *
 * Security model (SECURITY.md): the code runs as you, inside Google, and keeps its data in your own
 * private script storage: no spreadsheet, no server, no database. The dashboard only works when the
 * person opening it is the Google account it runs as, and every call checks that again.
 * Functions whose names end in "_" are private: the dashboard page cannot call them.
 */

var APP_NAME = 'EmailSpamdetection';

var APP_VERSION = '1.1.1';

var LABEL_PARENT = 'EmailSpamdetection';

var LABEL_DANGEROUS = 'EmailSpamdetection/Dangerous';

var LABEL_CHECK = 'EmailSpamdetection/Check first';

var LOG_MAX = 150;      // activity entries kept
var WEB_MAX = 500;      // senders kept (the ones that email you most)
var STORE_CHUNK = 8000; // characters per stored piece (Apps Script allows 9 KB per property)

var DAY_MS = 86400000;

var TRIGGER_HANDLERS = ['runGuard', 'runNightly', 'runScanBatch'];

var RANK = { clean: 0, suspicious: 1, dangerous: 2, blocked: 3 };

var SETTING_RULES = {
  checkEveryMinutes: { type: 'choice', choices: [1, 5, 10, 15] },
  dangerousScore: { type: 'int', min: 50, max: 100 },
  suspiciousScore: { type: 'int', min: 20, max: 90 },
  dangerousToSpam: { type: 'bool' },
  promoDays: { type: 'int', min: 7, max: 3650 },
  socialDays: { type: 'int', min: 7, max: 3650 },
  codeDays: { type: 'int', min: 1, max: 3650 },
  draftDays: { type: 'int', min: 30, max: 3650 },
  scanYears: { type: 'int', min: 1, max: 25 },
  massRecipients: { type: 'int', min: 5, max: 500 },
  maxSentPerHour: { type: 'int', min: 5, max: 1000 },
  alertEmails: { type: 'bool' }
};

// Optional outside checks. The keys live in your private script storage, never on the page or in the activity log.
var API_KEYS = { virustotal: 'key_virustotal', safebrowsing: 'key_safebrowsing' };

var SCAN_QUERY = '-in:sent -in:chats -in:drafts (unsubscribe OR category:promotions OR category:social OR category:forums OR ' +
  'category:updates OR subject:(welcome OR verify OR verification OR confirm OR activate OR registration OR password OR ' +
  '"sign in" OR "sign-in" OR login OR "log in" OR receipt OR order OR invoice OR booking OR reservation OR subscription OR account))';

// Everything is stored per Google account (user properties), so two people never share data.
function props_() { return PropertiesService.getUserProperties(); }

// Bigger data (senders, clean-up list, activity) is JSON split into pieces that fit the property limit.
function storeGet_(name, fallback) {
  var p = props_(), n = Number(p.getProperty('s:' + name + ':n') || 0), parts = [];
  if (!n) return fallback;
  for (var i = 0; i < n; i++) parts.push(p.getProperty('s:' + name + ':' + i) || '');
  try { return JSON.parse(parts.join('')); } catch (e) { return fallback; }
}

// Non-ASCII is escaped, so one character is always one byte and a piece never exceeds the limit.
function storeSet_(name, value) {
  var json = JSON.stringify(value).replace(/[\u007f-\uffff]/g, function (c) { return '\\u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4); });
  var p = props_(), old = Number(p.getProperty('s:' + name + ':n') || 0), n = Math.max(1, Math.ceil(json.length / STORE_CHUNK)), out = {};
  for (var i = 0; i < n; i++) out['s:' + name + ':' + i] = json.slice(i * STORE_CHUNK, (i + 1) * STORE_CHUNK);
  out['s:' + name + ':n'] = String(n);
  p.setProperties(out);
  for (var j = n; j < old; j++) p.deleteProperty('s:' + name + ':' + j);
}

function userError_(message) {
  var e = new Error(message);
  e.isUserError = true;
  return e;
}

function validateSettings_(input, lenient) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    if (lenient) return {};
    throw userError_('Settings must be a list of names and values.');
  }
  var out = {}, errors = [];
  Object.keys(input).forEach(function (key) {
    var rule = SETTING_RULES[key];
    if (!rule) { errors.push('Unknown setting: ' + clip_(key, 40)); return; }
    var v = input[key];
    if (rule.type === 'bool') {
      if (typeof v === 'boolean') out[key] = v; else errors.push(key + ' must be on or off');
      return;
    }
    var n = typeof v === 'number' ? v : (typeof v === 'string' && /^\s*-?\d+\s*$/.test(v) ? Number(v) : NaN);
    if (!isFinite(n) || Math.floor(n) !== n) { errors.push(key + ' must be a whole number'); return; }
    if (rule.type === 'choice' && rule.choices.indexOf(n) < 0) { errors.push(key + ' must be one of ' + rule.choices.join(', ')); return; }
    if (rule.type === 'int' && (n < rule.min || n > rule.max)) { errors.push(key + ' must be between ' + rule.min + ' and ' + rule.max); return; }
    out[key] = n;
  });
  if (errors.length && !lenient) throw userError_(errors.join('. ') + '.');
  return out;
}

function getSettings_() {
  var saved = {};
  try { saved = JSON.parse(props_().getProperty('settings') || '{}'); } catch (e) { saved = {}; }
  var clean = validateSettings_(saved, true);
  var out = {};
  Object.keys(DEFAULT_SETTINGS).forEach(function (k) { out[k] = Object.prototype.hasOwnProperty.call(clean, k) ? clean[k] : DEFAULT_SETTINGS[k]; });
  if (out.suspiciousScore >= out.dangerousScore) out.suspiciousScore = Math.max(20, out.dangerousScore - 30);
  return out;
}

function saveSettings_(input) {
  var changes = validateSettings_(input, false);
  var merged = getSettings_();
  Object.keys(changes).forEach(function (k) { merged[k] = changes[k]; });
  if (merged.suspiciousScore >= merged.dangerousScore) throw userError_('"Check first" must start below "Dangerous".');
  props_().setProperty('settings', JSON.stringify(merged));
  return merged;
}

function mask_(v) { return v ? String(v).slice(0, 4) + '… (' + String(v).length + ' characters)' : ''; }

// Gmail searches are built only from checked addresses and domains (the Gmail version of a
// parameterized query): a sender can't slip "OR in:anywhere" into a search that deletes mail.
function fromQuery_(entry) {
  var e = String(entry || '').trim().toLowerCase();
  if (isValidEmail_(e)) return 'from:' + e;
  var d = e.replace(/^@/, '');
  if (isValidDomain_(d)) return 'from:' + d;
  throw userError_('That is not a valid email address or domain.');
}

function fmtDate_(d) { return Utilities.formatDate(d, timeZone_(), 'yyyy/MM/dd'); }

// Your time zone comes from your phone or browser when you turn protection on (see validTimeZone_).
function timeZone_() { return props_().getProperty('tz') || Session.getScriptTimeZone(); }

function validTimeZone_(tz) {
  var s = String(tz === null || tz === undefined ? '' : tz);
  return s.length <= 40 && /^(?:UTC|GMT|[A-Za-z]+(?:\/[A-Za-z0-9_+\-]+){1,2})$/.test(s) ? s : '';
}

// The Google account this copy runs as: the only person whose mail it touches.
function ownerEmail_() {
  try { return String(Session.getEffectiveUser().getEmail() || '').toLowerCase(); } catch (e) { return ''; }
}

function gmailSearchLink_(query) {
  return 'https://mail.google.com/mail/?authuser=' + encodeURIComponent(ownerEmail_()) + '#search/' + encodeURIComponent(query);
}

function safeHeader_(msg, name) { try { return String(msg.getHeader(name) || ''); } catch (e) { return ''; } }

function inspectZip_(att) {
  try {
    if (att.getSize() > 15 * 1024 * 1024) return 'too-big';
    return zipEntries_(att.getBytes());
  } catch (e) { return null; }
}

function toPlain_(msg, from) {
  from = from || parseAddress_(msg.getFrom());
  var html = '', text = '', atts = [];
  try { html = String(msg.getBody() || '').slice(0, 300000); } catch (e) { html = ''; }
  try { text = String(msg.getPlainBody() || '').slice(0, 20000); } catch (e) { text = ''; }
  try {
    msg.getAttachments({ includeInlineImages: false, includeAttachments: true }).slice(0, 20).forEach(function (a) {
      var name = String(a.getName() || '');
      var item = { name: name, size: a.getSize(), type: String(a.getContentType() || '') };
      if (/\.zip$/i.test(name)) item.inner = inspectZip_(a);
      atts.push(item);
    });
  } catch (e) { atts.push({ name: 'attachment.zip', size: 0, inner: null }); }
  var rt = '';
  try { rt = msg.getReplyTo() ? parseAddress_(msg.getReplyTo()).email : ''; } catch (e) { rt = ''; }
  return { fromName: from.name, fromEmail: from.email, replyTo: rt, subject: String(msg.getSubject() || ''), text: text, html: html,
    auth: safeHeader_(msg, 'Authentication-Results'), attachments: atts };
}

var MY_ADDRESSES_ = null;

function myAddresses_() {
  if (MY_ADDRESSES_) return MY_ADDRESSES_;
  var list = [ownerEmail_()];
  try { list = list.concat(GmailApp.getAliases()); } catch (e) { /* no aliases */ }
  MY_ADDRESSES_ = list.filter(Boolean).map(function (a) { return String(a).toLowerCase(); });
  return MY_ADDRESSES_;
}

function cachedFlag_(key, compute) {
  var cache = CacheService.getUserCache();
  var hit = cache.get(key);
  if (hit !== null && hit !== undefined) return hit === '1';
  var v = !!compute();
  cache.put(key, v ? '1' : '0', 21600);
  return v;
}

function hasEmailedBefore_(email) {
  if (!isValidEmail_(email)) return false;
  return cachedFlag_('kc:' + email, function () { return GmailApp.search('in:sent to:' + email, 0, 1).length > 0; });
}

function isFirstTimeSender_(email) {
  if (!isValidEmail_(email)) return true;
  return GmailApp.search(fromQuery_(email), 0, 2).length <= 1;
}

function hexOf_(bytes) {
  return bytes.map(function (b) { var h = (b & 0xff).toString(16); return h.length === 1 ? '0' + h : h; }).join('');
}

// Optional: VirusTotal (attachments) and Google Safe Browsing (links), only if you added keys.
// Errors are swallowed on purpose: a failed lookup must never log a URL that carries a key.
function externalChecks_(msg, m) {
  var hits = [];
  var gsb = props_().getProperty(API_KEYS.safebrowsing);
  if (gsb) {
    try {
      var urls = extractLinks_(m.html).map(function (l) { return l.href; }).concat(extractTextUrls_(m.text))
        .filter(function (u) { return /^https?:\/\//i.test(u); }).slice(0, 20);
      if (urls.length) {
        var res = UrlFetchApp.fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(gsb), {
          method: 'post', contentType: 'application/json', muteHttpExceptions: true,
          payload: JSON.stringify({ client: { clientId: 'emailspamdetection', clientVersion: APP_VERSION },
            threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: urls.map(function (u) { return { url: u }; }) } })
        });
        if (res.getResponseCode() === 200 && (JSON.parse(res.getContentText() || '{}').matches || []).length) hits.push('Google Safe Browsing lists a link in this email as dangerous');
      }
    } catch (e) { /* lookup failed: no penalty */ }
  }
  var vt = props_().getProperty(API_KEYS.virustotal);
  if (vt) {
    try {
      var checked = 0;
      msg.getAttachments({ includeInlineImages: false, includeAttachments: true }).forEach(function (a) {
        if (checked >= 3 || a.getSize() > 25 * 1024 * 1024) return;
        checked++;
        var sha = hexOf_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, a.getBytes()));
        var r = UrlFetchApp.fetch('https://www.virustotal.com/api/v3/files/' + sha, { headers: { 'x-apikey': vt }, muteHttpExceptions: true });
        if (r.getResponseCode() !== 200) return;
        var stats = ((JSON.parse(r.getContentText() || '{}').data || {}).attributes || {}).last_analysis_stats || {};
        if ((stats.malicious || 0) >= 2) hits.push('VirusTotal: ' + stats.malicious + ' antivirus engines flag ' + clip_(a.getName(), 60));
      });
    } catch (e) { /* lookup failed: no penalty */ }
  }
  return hits;
}

function assessMessage_(msg, from, lists, st) {
  var m = toPlain_(msg, from);
  var ctx = { allowed: matchesList_(from.email, lists.allow) };
  var r = scoreMessage_(m, ctx, st);
  if (r.score >= 15 || m.attachments.length) {
    if (!ctx.allowed) {
      ctx.knownContact = hasEmailedBefore_(from.email);
      ctx.firstTime = !ctx.knownContact && isFirstTimeSender_(from.email);
    }
    ctx.external = externalChecks_(msg, m);
    r = scoreMessage_(m, ctx, st);
  }
  return r;
}

function runGuard() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(5000)) return 0;
  try {
    var st = getSettings_();
    var started = Date.now();
    var last = Number(props_().getProperty('guardLast') || 0);
    var result = guardThreads_(GmailApp.search('in:inbox newer_than:2d', 0, 50), last ? last - 10 * 60000 : 0, st, started + 4 * 60000);
    if (result.complete) props_().setProperty('guardLast', String(started));
    try { checkOutgoing_(st, false); } catch (e) { log_('Error', '', '', '', 'Outbox check failed: ' + clip_(e.message, 200)); }
    return result.acted;
  } finally {
    lock.releaseLock();
  }
}

function guardThreads_(threads, sinceMs, st, deadline) {
  var fresh = threads.filter(function (t) { return t.getLastMessageDate().getTime() > sinceMs; });
  if (!fresh.length) return { acted: 0, checked: 0, complete: true };
  var me = myAddresses_(), seen = loadSeen_(), lists = getLists_(), acted = 0, i;
  var all = GmailApp.getMessagesForThreads(fresh);
  for (i = 0; i < fresh.length; i++) {
    if (Date.now() > deadline) break;
    var worst = null;
    for (var j = 0; j < all[i].length; j++) {
      var msg = all[i][j], id = msg.getId();
      if (seen[id]) continue;
      seen[id] = Math.floor(Date.now() / 60000);
      var from = parseAddress_(msg.getFrom());
      if (me.indexOf(from.email) >= 0) continue;
      var v = matchesList_(from.email, lists.block)
        ? { level: 'blocked', score: 100, reasons: ['You blocked this sender'] }
        : assessMessage_(msg, from, lists, st);
      if (!worst || RANK[v.level] > RANK[worst.level]) { worst = v; worst.from = from.email; worst.subject = msg.getSubject(); }
    }
    if (worst && worst.level !== 'clean') { applyVerdict_(fresh[i], worst, st); acted++; }
  }
  saveSeen_(seen);
  return { acted: acted, checked: i, complete: i >= fresh.length };
}

function applyVerdict_(thread, v, st) {
  var details = (v.reasons || []).slice(0, 4).join('; ');
  if (v.level === 'blocked') {
    thread.moveToTrash();
    log_('Removed: you blocked this sender', v.from, v.subject, '', 'Moved to Trash (you can restore it for 30 days)', thread.getId());
    return;
  }
  var dangerous = v.level === 'dangerous';
  thread.addLabel(label_(dangerous ? LABEL_DANGEROUS : LABEL_CHECK));
  thread.moveToArchive();
  if (dangerous && st.dangerousToSpam) GmailApp.moveThreadToSpam(thread);
  markSuspiciousSender_(v.from);
  log_(dangerous ? 'Dangerous: moved out of your inbox' : 'Check first: moved out of your inbox', v.from, v.subject, v.score, details, thread.getId());
}

function loadSeen_() { try { return JSON.parse(props_().getProperty('guardSeen') || '{}'); } catch (e) { return {}; } }

function saveSeen_(seen) {
  var keys = Object.keys(seen).sort(function (a, b) { return seen[b] - seen[a]; }).slice(0, 250);
  var out = {};
  keys.forEach(function (k) { out[k] = seen[k]; });
  props_().setProperty('guardSeen', JSON.stringify(out));
}

function getLists_() {
  function load(key) { try { var v = JSON.parse(props_().getProperty(key) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; } }
  return { allow: load('allowList'), block: load('blockList') };
}

function normalizeListEntry_(value) {
  var v = String(value || '').trim().toLowerCase();
  if (isValidEmail_(v)) return v;
  var d = v.replace(/^@/, '');
  if (isValidDomain_(d)) return '@' + d;
  throw userError_('Enter an email address like news@shop.com, or a domain like @shop.com.');
}

function updateList_(which, op, value) {
  if (which !== 'allow' && which !== 'block') throw userError_('Unknown list.');
  if (op !== 'add' && op !== 'remove') throw userError_('Unknown change.');
  var entry = normalizeListEntry_(value);
  var key = which === 'allow' ? 'allowList' : 'blockList';
  var list = getLists_()[which].filter(function (e) { return e !== entry; });
  if (op === 'add') {
    if (list.length >= 150) throw userError_('That list is full (150). Remove some first.');
    list.unshift(entry);
  }
  props_().setProperty(key, JSON.stringify(list));
  return list;
}

function matchesList_(email, list) {
  email = String(email || '').toLowerCase();
  var domain = email.split('@')[1] || '';
  for (var i = 0; i < list.length; i++) {
    var e = list[i];
    if (e.charAt(0) === '@') {
      var d = e.slice(1);
      if (domain === d || domain.slice(-(d.length + 1)) === '.' + d) return true;
    } else if (e === email) return true;
  }
  return false;
}

function markSuspiciousSender_(email) {
  if (!isValidEmail_(email)) return;
  var list = suspiciousSenders_().filter(function (e) { return e !== email; });
  list.unshift(email);
  props_().setProperty('susSenders', JSON.stringify(list.slice(0, 200)));
}

function suspiciousSenders_() { try { return JSON.parse(props_().getProperty('susSenders') || '[]'); } catch (e) { return []; } }

function countRecipients_(m) {
  return [m.getTo(), m.getCc(), m.getBcc()].join(',').split(',').filter(function (x) { return x.indexOf('@') > 0; }).length;
}

function checkOutgoing_(st, force) {
  var p = props_(), now = Date.now();
  var last = Number(p.getProperty('outLast') || 0);
  if (!force && now - last < 10 * 60000) return [];
  p.setProperty('outLast', String(now));
  var me = myAddresses_(), alerts = [], seen = {};
  try { seen = JSON.parse(p.getProperty('outSeen') || '{}'); } catch (e) { seen = {}; }
  var minute = Math.floor(now / 60000);

  var sentThreads = GmailApp.search('in:sent newer_than:1d', 0, 100);
  var sentLists = sentThreads.length ? GmailApp.getMessagesForThreads(sentThreads) : [];
  var lastHour = 0;
  sentLists.forEach(function (msgs) {
    msgs.forEach(function (m) {
      if (me.indexOf(parseAddress_(m.getFrom()).email) < 0) return;
      if (now - m.getDate().getTime() < 3600000) lastHour++;
      var id = m.getId();
      if (seen[id]) return;
      seen[id] = minute;
      var n = countRecipients_(m);
      if (n >= st.massRecipients) alerts.push({ kind: 'Email sent to ' + n + ' people', detail: '"' + clip_(m.getSubject(), 80) + '"' });
      var r = scoreOutgoing_(toPlain_(m), st);
      if (r.level !== 'clean') alerts.push({ kind: 'Risky email sent from your account', detail: '"' + clip_(m.getSubject(), 80) + '": ' + r.reasons.slice(0, 2).join('; ') });
    });
  });
  if (lastHour >= st.maxSentPerHour) alerts.push({ kind: 'Unusual sending', detail: lastHour + ' emails sent in the last hour', key: 'volume' });

  GmailApp.getDrafts().slice(0, 50).forEach(function (d) {
    var m = d.getMessage(), id = 'd' + m.getId();
    if (seen[id]) return;
    seen[id] = minute;
    var r = scoreOutgoing_(toPlain_(m), st);
    if (r.level !== 'clean') alerts.push({ kind: 'Risky draft', detail: '"' + clip_(m.getSubject() || '(no subject)', 80) + '": ' + r.reasons.slice(0, 2).join('; ') });
  });

  var scheduled = GmailApp.search('in:scheduled', 0, 25);
  (scheduled.length ? GmailApp.getMessagesForThreads(scheduled) : []).forEach(function (msgs) {
    msgs.forEach(function (m) {
      var id = 's' + m.getId();
      if (seen[id]) return;
      seen[id] = minute;
      var n = countRecipients_(m), r = scoreOutgoing_(toPlain_(m), st);
      if (n >= st.massRecipients || r.level !== 'clean') {
        alerts.push({ kind: 'Scheduled email to check', detail: '"' + clip_(m.getSubject(), 80) + '" to ' + n + ' people' + (r.reasons.length ? ': ' + r.reasons[0] : '') });
      }
    });
  });

  var keys = Object.keys(seen).filter(function (k) { return minute - seen[k] < 7 * 1440; })
    .sort(function (a, b) { return seen[b] - seen[a]; }).slice(0, 250);
  var trimmed = {};
  keys.forEach(function (k) { trimmed[k] = seen[k]; });
  p.setProperty('outSeen', JSON.stringify(trimmed));
  if (alerts.length) recordAlerts_(alerts, st);
  return alerts;
}

function getAlerts_() {
  try {
    var list = JSON.parse(props_().getProperty('alerts') || '[]');
    return list.filter(function (a) { return Date.now() - a.at < 14 * DAY_MS; });
  } catch (e) { return []; }
}

function recordAlerts_(alerts, st) {
  var p = props_(), now = Date.now(), list = getAlerts_();
  var fresh = alerts.filter(function (a) {
    if (a.key !== 'volume') return true;
    return !list.some(function (x) { return x.key === 'volume' && now - x.at < 3600000; });
  });
  if (!fresh.length) return;
  fresh.forEach(function (a) {
    list.unshift({ at: now, kind: clip_(a.kind, 80), detail: clip_(a.detail, 240), key: a.key || '' });
    log_('Outbox alert: ' + clip_(a.kind, 60), '', '', '', a.detail);
  });
  p.setProperty('alerts', JSON.stringify(list.slice(0, 20)));
  var lastMail = Number(p.getProperty('alertMailLast') || 0);
  if (st.alertEmails && now - lastMail > 3600000 && ownerEmail_()) {
    p.setProperty('alertMailLast', String(now));
    GmailApp.sendEmail(ownerEmail_(), APP_NAME + ': check your Gmail account',
      'EmailSpamdetection noticed something unusual in your sent mail, drafts or scheduled emails:\n\n' +
      fresh.map(function (a) { return '- ' + a.kind + ': ' + a.detail; }).join('\n') +
      '\n\nIf this was not you:\n1. Change your Google password now.\n2. Check signed-in devices at myaccount.google.com/device-activity and sign out the ones you don\'t know.\n' +
      '3. In Gmail settings, check "Forwarding and POP/IMAP" and "Filters and Blocked Addresses" for anything you didn\'t add.\n4. Turn on 2-Step Verification.\n\nIf it was you, ignore this email.');
  }
}

function runScanBatch() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(5000)) return false;
  try {
    var done = scanBackfill_(Date.now() + 4 * 60000);
    if (done) {
      removeTrigger_('runScanBatch');
      log_('Websites scan finished', '', '', '', loadWebsites_().order.length + ' senders found');
      buildReview_(getSettings_(), Date.now() + 60000);
    }
    return done;
  } finally {
    lock.releaseLock();
  }
}

function monthStart_(ms) { var d = new Date(ms); return new Date(d.getFullYear(), d.getMonth(), 1).getTime(); }

function scanBackfill_(deadline) {
  var p = props_();
  if (p.getProperty('scanDone') === '1') return true;
  var st = getSettings_();
  var t0 = Number(p.getProperty('scanT0') || Date.now());
  var cursor = Number(p.getProperty('scanCursor') || t0);
  var offset = Number(p.getProperty('scanOffset') || 0);
  var floor = t0 - st.scanYears * 365.25 * DAY_MS;
  var table = loadWebsites_(), me = myAddresses_(), changed = false;
  while (Date.now() < deadline) {
    if (cursor <= floor) { p.setProperty('scanDone', '1'); break; }
    var winStart = Math.max(floor, monthStart_(cursor - 1));
    // Pad the search by a day each side (Gmail reads dates in its own time zone), then count
    // each message only in the window that holds its exact time, so nothing is counted twice.
    var q = SCAN_QUERY + ' after:' + fmtDate_(new Date(winStart - DAY_MS)) + ' before:' + fmtDate_(new Date(cursor + DAY_MS));
    var threads = GmailApp.search(q, offset, 100);
    if (threads.length) {
      GmailApp.getMessagesForThreads(threads).forEach(function (msgs) {
        msgs.forEach(function (m) {
          var t = m.getDate().getTime();
          if (t >= winStart && t < cursor) { aggregate_(table, m, me); changed = true; }
        });
      });
    }
    if (threads.length < 100) { cursor = winStart; offset = 0; } else { offset += threads.length; }
    p.setProperties({ scanCursor: String(cursor), scanOffset: String(offset) });
  }
  if (changed) saveWebsites_(table);
  return p.getProperty('scanDone') === '1';
}

function scanIncremental_(deadline) {
  var p = props_();
  var high = Number(p.getProperty('scanHigh') || p.getProperty('scanT0') || Date.now());
  var now = Date.now();
  var table = loadWebsites_(), me = myAddresses_(), changed = false, start = 0;
  var q = SCAN_QUERY + ' after:' + fmtDate_(new Date(high - DAY_MS));
  while (Date.now() < deadline) {
    var threads = GmailApp.search(q, start, 100);
    if (!threads.length) break;
    GmailApp.getMessagesForThreads(threads).forEach(function (msgs) {
      msgs.forEach(function (m) {
        var t = m.getDate().getTime();
        if (t > high && t <= now) { aggregate_(table, m, me); changed = true; }
      });
    });
    if (threads.length < 100) break;
    start += threads.length;
  }
  if (changed) saveWebsites_(table);
  p.setProperty('scanHigh', String(now));
}

function classifySubject_(subject) {
  var s = String(subject || '');
  return {
    acc: /\b(welcome|verify|verification|confirm (your )?(email|account|registration)|activate|account (created|registration|activated)|sign(ed)? ?up|registration|password|sign-?in|log-?in|security (alert|code)|one-?time|otp|2-?step|two-?factor)\b/i.test(s),
    cust: /\b(order|receipt|invoice|purchase|payment|booking|reservation|subscription|trip|delivery|shipped|statement)\b/i.test(s)
  };
}

function listHeaders_(msg) {
  var raw = safeHeader_(msg, 'List-Unsubscribe');
  if (!raw) return { u: '', m: '', oc: false };
  var post = safeHeader_(msg, 'List-Unsubscribe-Post');
  var u = '', mt = '';
  (raw.match(/<[^>]+>/g) || []).forEach(function (part) {
    var v = part.slice(1, -1).trim();
    if (!u && safeHttpsUrl_(v)) u = v;
    else if (!mt && /^mailto:/i.test(v) && parseMailto_(v)) mt = v;
  });
  return { u: u, m: mt, oc: !!u && /list-unsubscribe\s*=\s*one-click/i.test(post) };
}

function newRecord_(email, name, site) {
  return { site: site, name: name, email: email, emails: 0, unread: 0, last: null, first: null, status: '',
    flags: { list: false, acc: false, cust: false }, hc: 0, la: 0, meta: { u: '', m: '', oc: false } };
}

function applyUnsub_(rec, h, date) {
  rec.flags.list = true;
  if (date.getTime() >= rec.la) { rec.meta = { u: h.u, m: h.m, oc: h.oc }; rec.la = date.getTime(); }
}

function aggregate_(table, msg, me) {
  var from = parseAddress_(msg.getFrom());
  var email = from.email;
  if (!isValidEmail_(email) || me.indexOf(email) >= 0) return;
  var site = rootDomain_(email.split('@')[1]);
  var date = msg.getDate();
  var rec = table.byEmail[email];
  var hdr = null;
  if (!rec) {
    if (WEBMAIL.indexOf(site) >= 0) {           // a person, unless it is a mailing list
      hdr = listHeaders_(msg);
      if (!hdr.u && !hdr.m) return;
    }
    rec = newRecord_(email, from.name, site);
    table.byEmail[email] = rec;
    table.order.push(rec);
  }
  rec.emails++;
  if (msg.isUnread()) rec.unread++;
  if (!rec.last || date > rec.last) { rec.last = date; if (from.name) rec.name = from.name; }
  if (!rec.first || date < rec.first) rec.first = date;
  var c = classifySubject_(msg.getSubject());
  if (c.acc) rec.flags.acc = true;
  if (c.cust) rec.flags.cust = true;
  var wantHeader = (!rec.flags.list && rec.hc < 3) || (rec.flags.list && date.getTime() > rec.la);
  if (wantHeader) {
    if (!hdr) { hdr = listHeaders_(msg); rec.hc++; }
    if (hdr.u || hdr.m) applyUnsub_(rec, hdr, date);
  }
}

function websiteType_(f) {
  var t = [];
  if (f.acc) t.push('Account');
  if (f.cust) t.push('Customer');
  if (f.list) t.push('Mailing list');
  return t.join(' + ') || 'Other';
}

function openedPct_(r) { return r.emails ? Math.round((r.emails - r.unread) / r.emails * 100) : 0; }

// Senders are stored compactly: [email, name, site, emails, unread, last, first, status, flags, hc, la, url, mailto, oneClick].
function loadWebsites_() {
  var t = { byEmail: {}, order: [] };
  (storeGet_('web', []) || []).forEach(function (a) {
    var email = String(a[0] || '').toLowerCase();
    if (!isValidEmail_(email) || t.byEmail[email]) return;
    var rec = newRecord_(email, String(a[1] || ''), rootDomain_(email.split('@')[1]));
    rec.emails = Number(a[3]) || 0;
    rec.unread = Number(a[4]) || 0;
    rec.last = a[5] ? new Date(Number(a[5])) : null;
    rec.first = a[6] ? new Date(Number(a[6])) : null;
    rec.status = String(a[7] || '');
    var f = Number(a[8]) || 0;
    rec.flags = { list: !!(f & 1), acc: !!(f & 2), cust: !!(f & 4) };
    rec.hc = Number(a[9]) || 0;
    rec.la = Number(a[10]) || 0;
    rec.meta = { u: safeHttpsUrl_(a[11]) ? a[11] : '', m: parseMailto_(a[12]) ? a[12] : '', oc: !!a[13] };
    t.byEmail[email] = rec;
    t.order.push(rec);
  });
  return t;
}

function saveWebsites_(t) {
  var rows = t.order.slice().sort(function (a, b) { return b.emails - a.emails || (b.last || 0) - (a.last || 0); }).slice(0, WEB_MAX).map(function (r) {
    var u = r.meta.u && r.meta.u.length <= 500 ? r.meta.u : '';
    var m = r.meta.m && r.meta.m.length <= 250 ? r.meta.m : '';
    return [r.email, clip_(r.name, 60), r.site, r.emails, r.unread, r.last ? r.last.getTime() : 0, r.first ? r.first.getTime() : 0,
      clip_(r.status, 80), (r.flags.list ? 1 : 0) | (r.flags.acc ? 2 : 0) | (r.flags.cust ? 4 : 0), r.hc, r.la, u, m, r.meta.oc && u ? 1 : 0];
  });
  // Google keeps 500 KB per person for this app. If a huge mailbox would go over, keep the senders who email most.
  for (var n = rows.length; ; n = Math.floor(n * 0.7)) {
    try { storeSet_('web', rows.slice(0, n)); return n; } catch (e) {
      if (n < 20 || !/quota|too large|exceed/i.test(String(e && e.message))) throw e;
    }
  }
}

function findWebsite_(email) {
  var e = String(email || '').toLowerCase();
  if (!isValidEmail_(e)) throw userError_('That is not a valid email address.');
  var t = loadWebsites_();
  var rec = t.byEmail[e];
  if (!rec) throw userError_('That sender is not in your websites list.');
  return { table: t, rec: rec };
}

// Unsubscribes the safe way: the one-click standard (RFC 8058), or the sender's unsubscribe email.
// Never for a sender that looked suspicious: that would only confirm your address to a spammer.
function unsubscribe_(rec) {
  if (suspiciousSenders_().indexOf(rec.email) >= 0) {
    throw userError_('This sender looked suspicious. Unsubscribing would confirm your address to them, so use Block instead.');
  }
  var meta = rec.meta;
  if (meta.u && meta.oc && safeHttpsUrl_(meta.u)) {
    var res = UrlFetchApp.fetch(meta.u, { method: 'post', contentType: 'application/x-www-form-urlencoded',
      payload: 'List-Unsubscribe=One-Click', followRedirects: false, muteHttpExceptions: true, validateHttpsCertificates: true });
    var code = res.getResponseCode();
    if (code >= 200 && code < 400) return { done: true, how: 'one-click' };
  }
  var mt = parseMailto_(meta.m);
  if (mt) {
    GmailApp.sendEmail(mt.to, mt.subject, mt.body);
    return { done: true, how: 'email' };
  }
  if (meta.u && safeHttpsUrl_(meta.u)) return { done: false, link: meta.u };
  throw userError_('This sender gives no way to unsubscribe. Use Block instead.');
}

var REVIEW_RULES = {
  'rule:promotions': function (st) { return { what: 'Promotions older than ' + st.promoDays + ' days', why: 'Old adverts and expired deals', q: 'category:promotions older_than:' + st.promoDays + 'd' }; },
  'rule:social': function (st) { return { what: 'Social notifications older than ' + st.socialDays + ' days', why: 'Old Facebook, LinkedIn and similar alerts', q: 'category:social older_than:' + st.socialDays + 'd' }; },
  'rule:codes': function (st) {
    return { what: 'Login codes and sign-in links older than ' + st.codeDays + ' days', why: 'One-time codes stop working within minutes',
      q: 'subject:("verification code" OR "security code" OR "login code" OR "sign-in code" OR "one-time pin" OR "one-time password" OR OTP OR "sign-in link" OR "magic link" OR "your code") older_than:' + st.codeDays + 'd' };
  },
  'rule:big': function () { return { what: 'Big emails (10 MB or more) older than a year', why: 'They use the most storage. Look first: some hold photos or documents you want', q: 'larger:10M older_than:1y' }; }
};

// The search for a review item comes from its key, never from stored text.
function reviewQuery_(key, st) {
  var guard = ' -is:starred -is:important -has:userlabels -in:chats';
  if (String(key).indexOf('sender:') === 0) return fromQuery_(key.slice(7)) + ' older_than:7d' + guard;
  if (REVIEW_RULES[key]) return REVIEW_RULES[key](st).q + guard;
  throw userError_('Unknown review item.');
}

function queryStats_(q) {
  var threads = GmailApp.search(q, 0, 250);
  var examples = threads.slice(0, 3).map(function (t) { return clip_(t.getFirstMessageSubject() || '(no subject)', 70); });
  return { count: threads.length, countText: threads.length >= 250 ? '250+' : String(threads.length),
    newest: threads.length ? threads[0].getLastMessageDate() : '', oldest: threads.length ? threads[threads.length - 1].getLastMessageDate() : '',
    examples: examples };
}

function readReview_() {
  var items = storeGet_('review', {}) || {};
  Object.keys(items).forEach(function (k) {
    var it = items[k];
    it.key = k;
    it.oldest = it.oldest ? new Date(it.oldest) : '';
    it.newest = it.newest ? new Date(it.newest) : '';
  });
  return items;
}

function writeReview_(items) {
  var out = {};
  Object.keys(items).slice(0, 60).forEach(function (k) {
    var it = items[k];
    out[k] = { what: clip_(it.what, 160), why: clip_(it.why, 240), count: String(it.count || ''), examples: clip_(it.examples, 300),
      oldest: it.oldest instanceof Date ? it.oldest.getTime() : Number(it.oldest) || 0,
      newest: it.newest instanceof Date ? it.newest.getTime() : Number(it.newest) || 0,
      link: safeHttpsUrl_(it.link) ? it.link : '', decision: it.decision || '', status: clip_(it.status, 120) };
  });
  storeSet_('review', out);
}

function setReviewDecision_(key, decision, status) {
  var items = readReview_();
  if (!items[key]) throw userError_('That item is no longer in your list. Refresh the page.');
  items[key].decision = decision;
  items[key].status = status;
  writeReview_(items);
}

function buildReview_(st, deadline) {
  var existing = readReview_(), groups = [];
  loadWebsites_().order
    .filter(function (r) { return r.flags.list && r.emails >= 5 && openedPct_(r) < 20; })
    .sort(function (a, b) { return b.emails - a.emails; }).slice(0, 30)
    .forEach(function (r) {
      groups.push({ key: 'sender:' + r.email, what: 'Emails from ' + (r.name || r.email) + ' (' + r.email + ')',
        why: 'A mailing list you opened ' + openedPct_(r) + '% of (' + r.emails + ' emails). Unsubscribe from it too.' });
    });
  Object.keys(REVIEW_RULES).forEach(function (key) { var r = REVIEW_RULES[key](st); groups.push({ key: key, what: r.what, why: r.why }); });
  Object.keys(existing).forEach(function (key) {   // keep anything you already decided on
    if (!groups.some(function (g) { return g.key === key; }) && existing[key].decision) groups.push({ key: key, what: existing[key].what, why: existing[key].why });
  });
  var out = {};
  groups.forEach(function (g) {
    var prev = existing[g.key];
    if (Date.now() > deadline) { if (prev) out[g.key] = prev; return; }
    var q = reviewQuery_(g.key, st), s = queryStats_(q);
    if (!s.count && !(prev && prev.decision)) return;
    out[g.key] = { what: g.what, why: g.why, count: s.countText, oldest: s.oldest, newest: s.newest, examples: s.examples.join(' | '),
      link: gmailSearchLink_(q), decision: prev ? prev.decision : '', status: prev ? prev.status : '' };
  });
  writeReview_(out);
}

function ensureReviewItem_(key, what, why) {
  var items = readReview_();
  if (items[key]) return;
  items[key] = { what: what, why: why, count: '', examples: '', oldest: 0, newest: 0, link: '', decision: '', status: '' };
  writeReview_(items);
}

// Moves to Trash only what you approved ("Remove"), in batches, until the time runs out.
function applyApprovedRemovals_(deadline, onlyKey) {
  var st = getSettings_(), items = readReview_(), total = 0;
  Object.keys(items).forEach(function (key) {
    var it = items[key];
    if (onlyKey && key !== onlyKey) return;
    if (it.decision !== 'Remove' || /^Removed/.test(it.status) || Date.now() > deadline) return;
    var q;
    try { q = reviewQuery_(key, st); } catch (e) { setReviewDecision_(key, it.decision, 'Skipped: unknown item'); return; }
    var removed = Number((/(\d+)/.exec(it.status) || [0, 0])[1]) || 0, finished = false;
    while (Date.now() < deadline) {
      var batch = GmailApp.search(q, 0, 100);
      if (!batch.length) { finished = true; break; }
      GmailApp.moveThreadsToTrash(batch);
      removed += batch.length; total += batch.length;
    }
    setReviewDecision_(key, it.decision, finished ? 'Removed ' + removed + ' emails on ' + fmtDate_(new Date()) : 'Removing... ' + removed + ' so far');
    log_(finished ? 'Removed after your approval' : 'Removing after your approval', '', '', '', clip_(it.what, 120) + ': ' + removed + ' emails moved to Trash (restorable for 30 days)');
  });
  return total;
}

function log_(event, from, subject, score, details, threadId) {
  try {
    var list = storeGet_('log', []) || [];
    list.unshift([Date.now(), clip_(event, 80), clip_(from, 120), clip_(subject, 140), score === '' || score === undefined ? '' : Number(score) || 0,
      clip_(details, 400), String(threadId || '').slice(0, 30)]);
    storeSet_('log', list.slice(0, LOG_MAX));
  } catch (e) {
    console.error('Activity log failed: ' + e.message);
  }
}

function recentActivity_(n) {
  return (storeGet_('log', []) || []).slice(0, n).map(function (r) {
    return { at: r[0], event: r[1], from: r[2], subject: r[3], score: r[4], details: r[5], thread: r[6] };
  });
}

/** Optional: run from the Apps Script editor. The dashboard's "Turn on protection" button does the same. */
function setup() { requireUser_(); return turnOn_(); }

function turnOn_(tz) {
  var p = props_(), me = ownerEmail_();
  if (!me) throw userError_('Could not read your Google account. Open the app from its web app link.');
  var owner = p.getProperty('owner');
  if (owner && owner !== me) throw userError_('This copy belongs to another Google account.');
  p.setProperty('owner', me);
  if (validTimeZone_(tz)) p.setProperty('tz', validTimeZone_(tz));
  MY_ADDRESSES_ = null;
  label_(LABEL_PARENT); label_(LABEL_DANGEROUS); label_(LABEL_CHECK);
  if (!p.getProperty('scanT0')) {
    var now = String(Date.now());
    p.setProperties({ scanT0: now, scanCursor: now, scanHigh: now, scanOffset: '0' });
  }
  installTriggers_(getSettings_());
  log_('Protection switched on', me, '', '', 'Checks every ' + getSettings_().checkEveryMinutes + ' minutes');
  var mailed = false;
  try { mailed = emailAppLink_(me); } catch (e) { log_('Could not email your app link', me, '', '', clip_(e && e.message, 200)); }
  runGuard();
  return mailed ? 'Protection is on. Your app link is in your Gmail.' : 'Protection is on.';
}

// On a phone the web app link is easy to lose (Google's "Done" button closes it), so the first time
// protection switches on, the app emails you its own link. Only a Google Apps Script address is sent,
// and only to you.
function emailAppLink_(me) {
  var p = props_();
  if (p.getProperty('linkSent')) return false;
  var url = '';
  try { url = String(ScriptApp.getService().getUrl() || ''); } catch (e) { url = ''; }
  if (!safeHttpsUrl_(url) || !/^https:\/\/script\.google\.com\/(?:a\/macros\/[A-Za-z0-9.\-]+|macros)\/s\/[A-Za-z0-9_\-]+\/(?:exec|dev)$/.test(url)) return false;
  GmailApp.sendEmail(me, APP_NAME + ': your app link', 'Tap to open your EmailSpamdetection app:\n' + url +
    '\n\nOnly your Google account can open it. Tip: open it and use your browser\'s "Add to Home screen" so it opens like an app.\n', { name: APP_NAME });
  p.setProperty('linkSent', String(Date.now()));
  log_('App link emailed to you', me, '', '', 'So you can always find your app');
  return true;
}

/** Switches all automatic checks off. Your settings and lists stay. */
function turnOff() {
  requireUser_();
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (TRIGGER_HANDLERS.indexOf(t.getHandlerFunction()) >= 0) ScriptApp.deleteTrigger(t);
  });
  log_('Protection switched off', ownerEmail_(), '', '', 'All automatic checks stopped');
  return 'Protection is off.';
}

function installTriggers_(st) {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (TRIGGER_HANDLERS.indexOf(t.getHandlerFunction()) >= 0) ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('runGuard').timeBased().everyMinutes(st.checkEveryMinutes).create();
  try { ScriptApp.newTrigger('runNightly').timeBased().everyDays(1).atHour(2).inTimezone(timeZone_()).create(); }
  catch (e) { ScriptApp.newTrigger('runNightly').timeBased().everyDays(1).atHour(2).create(); }
  if (props_().getProperty('scanDone') !== '1') ScriptApp.newTrigger('runScanBatch').timeBased().everyMinutes(10).create();
}

function removeTrigger_(handler) {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === handler) ScriptApp.deleteTrigger(t); });
}

function protectionOn_() {
  return ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'runGuard'; });
}

function label_(name) { return GmailApp.getUserLabelByName(name) || GmailApp.createLabel(name); }

function runNightly() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(30000)) return false;
  try {
    var st = getSettings_(), end = Date.now() + 5 * 60000;
    var steps = [
      ['approved removals', function () { applyApprovedRemovals_(Math.min(end, Date.now() + 2 * 60000)); }],
      ['websites update', function () { if (props_().getProperty('scanDone') === '1') scanIncremental_(Math.min(end, Date.now() + 90000)); }],
      ['review list', function () { buildReview_(st, end); }]
    ];
    steps.forEach(function (s) {
      try { s[1](); } catch (e) { log_('Error', '', '', '', 'Nightly ' + s[0] + ' failed: ' + clip_(e.message, 200)); }
    });
    return true;
  } finally {
    lock.releaseLock();
  }
}

// GET only shows the page. Nothing in the address can make it change anything (no CSRF by link),
// and there is no doPost, so the only way in is the page's own google.script.run calls below.
function doGet() {
  try {
    requireUser_();
  } catch (e) {
    var url = authUrl_();
    var msg = url ? '<p>Google needs your permission before this app can open.</p><p><a href="' + htmlEscape_(url) +
      '" target="_top">Give permission</a>, tap Select all, then open your app link again.</p>' : '<p>Not allowed. Open your own copy of EmailSpamdetection.</p>';
    return HtmlService.createHtmlOutput('<div style="font:17px/1.5 sans-serif;padding:18px">' + msg + '</div>')
      .setTitle(APP_NAME).addMetaTag('viewport', 'width=device-width, initial-scale=1');
  }
  return dashboardOutput_()
    .setTitle(APP_NAME)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
}

// If Google has not been given every permission yet (on a phone it is easy to untick one), this is the
// link that asks again. Only a Google sign-in address is ever returned.
function authUrl_() {
  try {
    var info = ScriptApp.getAuthorizationInfo(ScriptApp.AuthMode.FULL);
    if (info.getAuthorizationStatus() !== ScriptApp.AuthorizationStatus.REQUIRED) return '';
    var url = String(info.getAuthorizationUrl() || '');
    return safeHttpsUrl_(url) && /^https:\/\/(accounts\.google\.com|script\.google\.com)\//.test(url) ? url : '';
  } catch (e) {
    return '';
  }
}

function htmlEscape_(v) {
  return String(v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
}

// The one-file install carries the page inside the script (DASHBOARD_HTML); the repo version uses Dashboard.html.
function dashboardOutput_() {
  return typeof DASHBOARD_HTML === 'string' ? HtmlService.createHtmlOutput(DASHBOARD_HTML) : HtmlService.createHtmlOutputFromFile('Dashboard');
}

// The dashboard works only for the Google account this copy runs as. If a copy were ever deployed as
// "Execute as: Me" but opened by someone else, the two accounts differ and every call is refused.
function requireUser_() {
  var active = '', me = ownerEmail_();
  try { active = String(Session.getActiveUser().getEmail() || '').toLowerCase(); } catch (e) { active = ''; }
  var owner = props_().getProperty('owner');
  if (!active || !me || active !== me || (owner && owner !== me)) {
    log_('Access denied', active || 'unknown user', '', '', 'Someone other than the owner tried to use the dashboard');
    throw userError_('Not allowed.');
  }
  return me;
}

function rateLimit_(bucket, max, windowSec) {
  var cache = CacheService.getUserCache();
  var key = 'rl:' + bucket + ':' + Math.floor(Date.now() / 1000 / windowSec);
  var n = Number(cache.get(key) || 0) + 1;
  cache.put(key, String(n), windowSec + 5);
  if (n > max) {
    if (n === max + 1) log_('Rate limit', ownerEmail_(), '', '', bucket + ': more than ' + max + ' requests in ' + windowSec + ' seconds');
    throw userError_('Too many requests. Wait a minute and try again.');
  }
}

// Every API call: owner check, rate limit, and errors without stack traces.
function guarded_(fn, bucket, max, windowSec) {
  try {
    requireUser_();
    rateLimit_('api', 120, 60);
    if (bucket) rateLimit_(bucket, max, windowSec);
    return { ok: true, data: fn() };
  } catch (e) {
    if (e && e.isUserError) return { ok: false, error: e.message };
    var msg = String((e && e.message) || e);
    if (/permission|authori[sz]|required scopes?/i.test(msg)) {
      var url = authUrl_();
      return { ok: false, authUrl: url, error: url ? 'Google needs your permission for this. Tap "Give permission", choose Select all, then come back.' :
        'Google has not given this app permission yet. In the Apps Script editor, pick "setup", tap Run and allow everything.' };
    }
    console.error(e && e.stack ? e.stack : msg);
    log_('Error', '', '', '', clip_(msg, 300));
    return { ok: false, error: 'Something went wrong. Try again in a minute. Details are under Recent activity on Home.' };
  }
}

function labelThreads_(name, max) {
  var l = GmailApp.getUserLabelByName(name);
  return l ? l.getThreads(0, max) : [];
}

function apiOverview() {
  return guarded_(function () {
    var st = getSettings_(), p = props_();
    var since = Date.now() - 7 * DAY_MS;
    var acts = recentActivity_(LOG_MAX);
    var review = readReview_();
    return {
      version: APP_VERSION, owner: ownerEmail_(), setupDone: !!p.getProperty('owner'), protectionOn: protectionOn_(),
      checkEveryMinutes: st.checkEveryMinutes, lastCheck: Number(p.getProperty('guardLast') || 0),
      dangerous: labelThreads_(LABEL_DANGEROUS, 100).length, checkFirst: labelThreads_(LABEL_CHECK, 100).length,
      caughtThisWeek: acts.filter(function (a) { return a.at > since && /^(Dangerous|Check first)/.test(a.event); }).length,
      toReview: Object.keys(review).filter(function (k) { return !review[k].decision; }).length,
      websites: loadWebsites_().order.length,
      scanDone: p.getProperty('scanDone') === '1', scanCursor: Number(p.getProperty('scanCursor') || 0),
      alerts: getAlerts_(), activity: acts.slice(0, 12)
    };
  });
}

function apiQuarantine() {
  return guarded_(function () {
    var reasons = {};
    recentActivity_(1500).forEach(function (a) { if (a.thread && !reasons[a.thread]) reasons[a.thread] = a.details; });
    function list(name, level) {
      var threads = labelThreads_(name, 50);
      var msgs = threads.length ? GmailApp.getMessagesForThreads(threads) : [];
      return threads.map(function (t, i) {
        var first = msgs[i] && msgs[i][0];
        return { id: t.getId(), level: level, from: first ? clip_(first.getFrom(), 120) : '', subject: clip_(t.getFirstMessageSubject() || '(no subject)', 160),
          date: t.getLastMessageDate().getTime(), reasons: clip_(reasons[t.getId()] || '', 500) };
      });
    }
    return { dangerous: list(LABEL_DANGEROUS, 'dangerous'), check: list(LABEL_CHECK, 'check') };
  });
}

function apiQuarantineAction(threadId, action, trustSender) {
  return guarded_(function () {
    var id = String(threadId || '');
    if (!/^[0-9a-f]{10,24}$/i.test(id)) throw userError_('Unknown email.');
    if (['restore', 'spam', 'remove'].indexOf(action) < 0) throw userError_('Unknown action.');
    var t = GmailApp.getThreadById(id);
    if (!t) throw userError_('That email is gone.');
    var names = t.getLabels().map(function (l) { return l.getName(); });
    if (names.indexOf(LABEL_DANGEROUS) < 0 && names.indexOf(LABEL_CHECK) < 0) throw userError_('That email is not in quarantine.');
    var from = parseAddress_(t.getMessages()[0].getFrom()).email, subject = t.getFirstMessageSubject();
    if (action === 'restore') {
      [LABEL_DANGEROUS, LABEL_CHECK].forEach(function (n) { var l = GmailApp.getUserLabelByName(n); if (l) t.removeLabel(l); });
      t.moveToInbox();
      if (trustSender === true && isValidEmail_(from)) updateList_('allow', 'add', from);
      log_('Restored to inbox by you', from, subject, '', trustSender === true ? 'Sender added to your trusted list' : '', id);
    } else if (action === 'spam') {
      GmailApp.moveThreadToSpam(t);
      log_('Reported as spam by you', from, subject, '', '', id);
    } else {
      t.moveToTrash();
      log_('Removed by you', from, subject, '', 'Moved to Trash (restorable for 30 days)', id);
    }
    return true;
  }, 'quarantine', 60, 60);
}

function apiReview() {
  return guarded_(function () {
    var items = readReview_();
    return Object.keys(items).map(function (k) {
      var it = items[k];
      return { key: k, what: it.what, why: it.why, count: it.count, examples: it.examples,
        oldest: it.oldest instanceof Date ? it.oldest.getTime() : 0, newest: it.newest instanceof Date ? it.newest.getTime() : 0,
        link: safeHttpsUrl_(it.link) ? it.link : '', decision: it.decision, status: it.status };
    });
  });
}

function apiReviewDecision(key, decision) {
  return guarded_(function () {
    var k = String(key || '');
    if (!readReview_()[k]) throw userError_('That item is no longer in your review list. Refresh the page.');
    reviewQuery_(k, getSettings_());   // throws for anything that is not a known kind of item
    if (decision === 'remove') {
      setReviewDecision_(k, 'Remove', 'Approved by you');
      applyApprovedRemovals_(Date.now() + 25000, k);
    } else if (decision === 'keep') {
      setReviewDecision_(k, 'Keep', 'Kept');
    } else if (decision === 'undo') {
      var st = readReview_()[k].status;
      setReviewDecision_(k, '', /^Removing/.test(st) ? 'Stopped: ' + st : '');
    } else {
      throw userError_('Unknown decision.');
    }
    log_('Review decision: ' + decision, '', '', '', clip_(k, 120));
    return readReview_()[k].status;
  }, 'review', 30, 60);
}

function apiWebsites() {
  return guarded_(function () {
    var sus = suspiciousSenders_();
    return loadWebsites_().order.slice().sort(function (a, b) { return b.emails - a.emails; }).slice(0, 1500).map(function (r) {
      var opened = openedPct_(r), years = r.last ? (Date.now() - r.last.getTime()) / (365 * DAY_MS) : 0;
      var suggestion = sus.indexOf(r.email) >= 0 ? 'Block' : (r.flags.list && r.emails >= 5 && opened < 20) ? 'Unsubscribe' :
        (r.flags.acc && years > 2) ? 'Old account: close it?' : '';
      return { site: r.site, name: clip_(r.name, 80), email: r.email, type: websiteType_(r.flags), emails: r.emails, opened: opened,
        last: r.last ? r.last.getTime() : 0, unsub: r.meta.oc ? 'one-click' : r.meta.m ? 'email' : r.meta.u ? 'link' : '',
        status: clip_(r.status, 120), suggestion: suggestion };
    });
  });
}

function apiCountFrom(email) {
  return guarded_(function () {
    var q = fromQuery_(findWebsite_(email).rec.email) + ' -is:starred -is:important -has:userlabels';
    var n = GmailApp.search(q, 0, 500).length;
    return n >= 500 ? '500+' : String(n);
  });
}

function apiWebsiteAction(email, action) {
  return guarded_(function () {
    if (['unsubscribe', 'remove', 'block', 'keep'].indexOf(action) < 0) throw userError_('Unknown action.');
    var found = findWebsite_(email), rec = found.rec, result = { done: true };
    if (action === 'unsubscribe') {
      rateLimit_('unsubscribe', 20, 3600);
      result = unsubscribe_(rec);
      rec.status = result.done ? 'Unsubscribed (' + result.how + ') ' + fmtDate_(new Date()) : 'Open the unsubscribe page to finish';
    } else if (action === 'remove' || action === 'block') {
      if (action === 'block') updateList_('block', 'add', rec.email);
      var key = 'sender:' + rec.email;
      ensureReviewItem_(key, 'Emails from ' + (rec.name || rec.email) + ' (' + rec.email + ')', action === 'block' ? 'You blocked this sender' : 'You chose to remove these');
      setReviewDecision_(key, 'Remove', 'Approved by you');
      applyApprovedRemovals_(Date.now() + 20000, key);
      rec.status = (action === 'block' ? 'Blocked' : 'Old emails removed') + ' ' + fmtDate_(new Date());
    } else {
      rec.status = 'Keeping';
    }
    saveWebsites_(found.table);
    log_('Website action: ' + action, rec.email, '', '', rec.status);
    return { status: rec.status, link: result.link && safeHttpsUrl_(result.link) ? result.link : '' };
  }, 'websites', 30, 60);
}

function apiOutgoing() {
  return guarded_(function () {
    var st = getSettings_(), now = Date.now();
    var drafts = GmailApp.getDrafts().slice(0, 150).map(function (d) {
      var m = d.getMessage(), t = m.getDate().getTime();
      return { id: d.getId(), to: clip_(m.getTo(), 120), subject: clip_(m.getSubject() || '(no subject)', 150), date: t,
        old: now - t > st.draftDays * DAY_MS };
    }).sort(function (a, b) { return a.date - b.date; });
    var sched = GmailApp.search('in:scheduled', 0, 25);
    var scheduled = (sched.length ? GmailApp.getMessagesForThreads(sched) : []).map(function (msgs) {
      var m = msgs[msgs.length - 1];
      return { to: clip_(m.getTo(), 120), subject: clip_(m.getSubject() || '(no subject)', 150), recipients: countRecipients_(m) };
    });
    return { drafts: drafts, scheduled: scheduled, alerts: getAlerts_(), draftDays: st.draftDays };
  });
}

// Deletes only drafts you picked on the page, and only ones still old enough to be offered.
function apiDeleteDrafts(ids) {
  return guarded_(function () {
    if (!Array.isArray(ids) || !ids.length || ids.length > 100) throw userError_('Pick between 1 and 100 drafts.');
    var st = getSettings_(), now = Date.now(), deleted = 0;
    ids.forEach(function (raw) {
      var id = String(raw || '');
      if (!/^r-?\d{1,25}$/.test(id)) throw userError_('Unknown draft.');
      var d = GmailApp.getDraft(id);
      if (!d) return;
      var m = d.getMessage();
      if (now - m.getDate().getTime() <= st.draftDays * DAY_MS) return;
      log_('Draft deleted by you', '', m.getSubject(), '', 'To: ' + clip_(m.getTo(), 120));
      d.deleteDraft();
      deleted++;
    });
    return deleted;
  }, 'drafts', 10, 60);
}

function apiSettings() {
  return guarded_(function () {
    var p = props_(), lists = getLists_();
    return { settings: getSettings_(), keys: { virustotal: mask_(p.getProperty(API_KEYS.virustotal)), safebrowsing: mask_(p.getProperty(API_KEYS.safebrowsing)) },
      allow: lists.allow, block: lists.block };
  });
}

function apiSaveSettings(input) {
  return guarded_(function () {
    var before = getSettings_();
    var after = saveSettings_(input);
    if (before.checkEveryMinutes !== after.checkEveryMinutes && protectionOn_()) installTriggers_(after);
    log_('Settings changed by you', '', '', '', Object.keys(input || {}).join(', '));
    return after;
  }, 'settings', 10, 60);
}

// API keys are write-only: the page can set or clear one, but never read it back.
function apiSetKey(which, value) {
  return guarded_(function () {
    var prop = API_KEYS[which];
    if (!prop) throw userError_('Unknown key.');
    var v = String(value === null || value === undefined ? '' : value).trim();
    if (!v) { props_().deleteProperty(prop); log_('API key removed', '', '', '', which); return ''; }
    if (!/^[A-Za-z0-9_\-]{20,128}$/.test(v)) throw userError_('That does not look like an API key.');
    props_().setProperty(prop, v);
    log_('API key saved', '', '', '', which);
    return mask_(v);
  }, 'settings', 10, 60);
}

function apiUpdateList(which, op, value) {
  return guarded_(function () {
    var list = updateList_(which, op, value);
    log_('List changed by you', '', '', '', which + ' ' + op + ' ' + clip_(normalizeListEntry_(value), 120));
    return list;
  }, 'settings', 30, 60);
}

function apiCheckNow() {
  return guarded_(function () {
    var lock = LockService.getUserLock();
    if (!lock.tryLock(10000)) throw userError_('A check is already running. Try again in a minute.');
    try {
      var r = guardThreads_(GmailApp.search('in:inbox newer_than:30d', 0, 150), 0, getSettings_(), Date.now() + 4 * 60000);
      return { acted: r.acted, checked: r.checked, complete: r.complete };
    } finally {
      lock.releaseLock();
    }
  }, 'checknow', 3, 60);
}

function apiTurnOff() { return guarded_(function () { return turnOff(); }, 'settings', 5, 60); }

function apiTurnOn(timeZone) { return guarded_(function () { return turnOn_(timeZone); }, 'settings', 5, 60); }
