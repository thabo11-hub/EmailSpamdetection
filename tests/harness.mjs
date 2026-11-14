// A fake Apps Script world (Gmail, Properties, triggers...) so the real src/*.gs files, or the one-file
// install built from them, can be loaded and attacked in Node with no network and no packages.
// Only what the app uses is modelled, including Google's storage limits.
import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildBundle } from '../scripts/build-web.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OWNER = 'owner@example.com';
const DAY = 86400000;

let idSeq = 0x1a00000000000000n;
const nextId = () => (idSeq++).toString(16);

export function makeMessage(o = {}) {
  const m = {
    id: o.id || nextId(), from: o.from || 'Someone <someone@example.org>', to: o.to || OWNER, cc: o.cc || '', bcc: o.bcc || '',
    replyTo: o.replyTo || '', subject: o.subject || 'Hello', date: o.date || new Date(), plain: o.plain || '', html: o.html || '',
    headers: o.headers || {}, attachments: o.attachments || [], unread: o.unread !== false,
  };
  return {
    _m: m,
    getId: () => m.id, getFrom: () => m.from, getTo: () => m.to, getCc: () => m.cc, getBcc: () => m.bcc,
    getReplyTo: () => m.replyTo, getSubject: () => m.subject, getDate: () => m.date, getPlainBody: () => m.plain,
    getBody: () => m.html, isUnread: () => m.unread,
    getHeader: (name) => { const k = Object.keys(m.headers).find((h) => h.toLowerCase() === name.toLowerCase()); return k ? m.headers[k] : ''; },
    getAttachments: () => m.attachments.map((a) => ({
      getName: () => a.name, getSize: () => (a.bytes ? a.bytes.length : a.size || 1000), getContentType: () => a.type || 'application/octet-stream',
      getBytes: () => Array.from(a.bytes || Buffer.alloc(10)).map((b) => (b > 127 ? b - 256 : b)),
    })),
  };
}

export function makeEnv(opts = {}) {
  const env = {
    owner: OWNER, activeUser: opts.activeUser === undefined ? OWNER : opts.activeUser, props: new Map(), scriptProps: new Map(), cache: new Map(),
    threads: [], labels: new Map(), drafts: [], triggers: [], sent: [], fetchLog: [], queries: [], trashed: [], spammed: [], logs: [],
    fetchResponder: null, aliases: [], authRequired: false, authUrl: 'https://accounts.google.com/o/oauth2/auth?client_id=1&scope=x',
  };

  const label = (name) => ({ getName: () => name, getThreads: (s, n) => env.threads.filter((t) => t.labels.has(name) && !t.trash).slice(s, s + n), getUnreadCount: () => 0 });

  function makeThread(messages, o = {}) {
    const t = { id: o.id || messages[0].getId(), msgs: messages, labels: new Set(o.labels || []), inbox: o.inbox !== false, trash: false, spam: false,
      sent: !!o.sent, scheduled: !!o.scheduled, starred: !!o.starred, important: !!o.important, category: o.category || 'primary', size: o.size || 0 };
    t.getId = () => t.id;
    t.getMessages = () => t.msgs;
    t.getLastMessageDate = () => new Date(Math.max(...t.msgs.map((m) => m.getDate().getTime())));
    t.getFirstMessageSubject = () => t.msgs[0].getSubject();
    t.isUnread = () => t.msgs.some((m) => m.isUnread());
    t.addLabel = (l) => { t.labels.add(l.getName()); return t; };
    t.removeLabel = (l) => { t.labels.delete(l.getName()); return t; };
    t.getLabels = () => [...t.labels].map(label);
    t.moveToArchive = () => { t.inbox = false; return t; };
    t.moveToInbox = () => { t.inbox = true; return t; };
    t.moveToTrash = () => { t.trash = true; env.trashed.push(t.id); return t; };
    return t;
  }
  env.addThread = (messages, o) => { const t = makeThread(Array.isArray(messages) ? messages : [messages], o); env.threads.push(t); return t; };

  // A small Gmail search: enough operators for the app's own queries. Every query is recorded.
  function matches(t, q) {
    if (t.trash || t.spam) return false;
    const now = Date.now(), last = t.getLastMessageDate().getTime();
    const toks = (q.match(/-?\w+:\([^)]*\)|-?\w+:"[^"]*"|-?\w+:\S+|\S+/g) || []).map((x) => x.replace(/^\(+/, '').replace(/\)+$/, ''));
    function one(raw) {
      const neg = raw.startsWith('-'); const tok = neg ? raw.slice(1) : raw;
      let ok;
      const [op, ...rest] = tok.split(':'); const val = rest.join(':').replace(/^"|"$/g, '');
      if (op === 'in' && val === 'inbox') ok = t.inbox && !t.sent;
      else if (op === 'in' && val === 'sent') ok = t.sent;
      else if (op === 'in' && val === 'scheduled') ok = t.scheduled;
      else if (op === 'in' && (val === 'chats' || val === 'drafts')) ok = false;
      else if (op === 'newer_than') ok = now - last < parseInt(val, 10) * (val.endsWith('y') ? 365 * DAY : DAY);
      else if (op === 'older_than') ok = now - last > parseInt(val, 10) * (val.endsWith('y') ? 365 * DAY : DAY);
      else if (op === 'from') ok = t.msgs.some((m) => m.getFrom().toLowerCase().includes(val.toLowerCase()));
      else if (op === 'to') ok = t.msgs.some((m) => m.getTo().toLowerCase().includes(val.toLowerCase()));
      else if (op === 'is' && val === 'starred') ok = t.starred;
      else if (op === 'is' && val === 'important') ok = t.important;
      else if (op === 'has' && val === 'userlabels') ok = t.labels.size > 0;
      else if (op === 'category') ok = t.category === val;
      else if (op === 'larger') ok = t.size >= parseInt(val, 10) * 1024 * 1024;
      else return true;                                // anything else: not modelled, matches
      return neg ? !ok : ok;
    }
    for (let i = 0; i < toks.length; i++) {            // "a OR b OR c" passes if any part passes
      const group = [toks[i]];
      while (toks[i + 1] === 'OR' && i + 2 < toks.length) { group.push(toks[i + 2]); i += 2; }
      if (!group.some(one)) return false;
    }
    return true;
  }

  const GmailApp = {
    search(q, start = 0, max = 500) {
      env.queries.push(q);
      return env.threads.filter((t) => matches(t, q)).sort((a, b) => b.getLastMessageDate() - a.getLastMessageDate()).slice(start, start + max);
    },
    getMessagesForThreads: (ts) => ts.map((t) => t.getMessages()),
    moveThreadsToTrash: (ts) => { if (ts.length > 100) throw new Error('max 100'); ts.forEach((t) => t.moveToTrash()); },
    moveThreadToSpam: (t) => { t.spam = true; env.spammed.push(t.id); },
    getUserLabelByName: (n) => (env.labels.has(n) ? label(n) : null),
    createLabel: (n) => { env.labels.set(n, true); return label(n); },
    getAliases: () => env.aliases,
    getThreadById: (id) => env.threads.find((t) => t.id === id) || null,
    getDrafts: () => env.drafts.filter((d) => !d.deleted).map((d) => d.api),
    getDraft: (id) => { const d = env.drafts.find((x) => x.id === id && !x.deleted); return d ? d.api : null; },
    sendEmail: (to, subject, body) => { env.sent.push({ to, subject, body }); },
  };
  env.addDraft = (message, id) => {
    const d = { id: id || 'r' + (1000 + env.drafts.length), message, deleted: false };
    d.api = { getId: () => d.id, getMessage: () => message, deleteDraft: () => { d.deleted = true; } };
    env.drafts.push(d);
    return d;
  };

  // Properties, with Google's limits: 9 KB per value and 500 KB per store. A write that would go over fails whole.
  const QUOTA = 500 * 1024;
  const store = (map) => {
    const api = {
      getProperty: (k) => (map.has(k) ? map.get(k) : null),
      setProperty: (k, v) => api.setProperties({ [k]: v }),
      setProperties: (o) => {
        const next = new Map(map);
        for (const [k, v] of Object.entries(o)) {
          if (Buffer.byteLength(String(v)) > 9216) throw new Error('Argument too large: value');
          next.set(k, String(v));
        }
        let total = 0;
        for (const [k, v] of next) total += Buffer.byteLength(k) + Buffer.byteLength(v);
        if (total > QUOTA) throw new Error('You have exceeded the property storage quota. Please remove some properties and try again.');
        for (const [k, v] of next) map.set(k, v);
        return api;
      },
      deleteProperty: (k) => { map.delete(k); return api; },
    };
    return api;
  };
  const props = store(env.props), scriptProps = store(env.scriptProps);
  env.storeBytes = () => [...env.props].reduce((n, [k, v]) => n + Buffer.byteLength(k) + Buffer.byteLength(v), 0);

  const triggerBuilder = (fn) => {
    const t = { fn, every: null, atHour: null, tz: null };
    const b = { timeBased: () => b, everyMinutes: (n) => { if (![1, 5, 10, 15, 30].includes(n)) throw new Error('bad interval'); t.every = n + 'm'; return b; },
      everyDays: (n) => { t.every = n + 'd'; return b; }, atHour: (h) => { t.atHour = h; return b; },
      inTimezone: (tz) => { if (!/^(UTC|GMT|[A-Z][A-Za-z_]+\/[A-Za-z_\/+-]+)$/.test(tz) || /Atlantis/.test(tz)) throw new Error('Invalid argument: timezone'); t.tz = tz; return b; },
      create: () => { const tr = { getHandlerFunction: () => fn, _t: t }; env.triggers.push(tr); return tr; } };
    return b;
  };

  const htmlOut = (content) => { const o = { content, title: '', xfo: null, meta: [] };
    o.setTitle = (t) => { o.title = t; return o; }; o.addMetaTag = (k, v) => { o.meta.push([k, v]); return o; };
    o.setXFrameOptionsMode = (m) => { o.xfo = m; return o; }; o.getContent = () => content; return o; };

  env.globals = {
    console: { log() {}, error: (...a) => env.logs.push(a.join(' ')), warn() {} },
    Date, Math, JSON, Object, Array, String, Number, RegExp, Error, isFinite, parseInt, encodeURIComponent, decodeURIComponent,
    GmailApp,
    PropertiesService: { getUserProperties: () => props, getScriptProperties: () => scriptProps },
    CacheService: { getUserCache: () => ({ get: (k) => (env.cache.has(k) ? env.cache.get(k) : null), put: (k, v) => env.cache.set(k, String(v)), remove: (k) => env.cache.delete(k) }) },
    LockService: { getUserLock: () => ({ tryLock: () => true, releaseLock() {}, waitLock() {} }) },
    Session: { getActiveUser: () => ({ getEmail: () => env.activeUser }), getEffectiveUser: () => ({ getEmail: () => env.owner }), getScriptTimeZone: () => 'Africa/Johannesburg' },
    Utilities: {
      formatDate: (d, tz, fmt) => { const p = (n) => String(n).padStart(2, '0'); return fmt.replace('yyyy', d.getFullYear()).replace('MM', p(d.getMonth() + 1)).replace('dd', p(d.getDate())); },
      DigestAlgorithm: { SHA_256: 'sha256' },
      computeDigest: (alg, bytes) => Array.from(crypto.createHash(alg).update(Buffer.from(bytes.map((b) => b & 0xff))).digest()).map((b) => (b > 127 ? b - 256 : b)),
    },
    UrlFetchApp: { fetch: (url, params = {}) => { env.fetchLog.push({ url, params }); const r = env.fetchResponder ? env.fetchResponder(url, params) : { code: 200, body: '{}' };
      if (r instanceof Error) throw r; return { getResponseCode: () => r.code, getContentText: () => r.body }; } },
    HtmlService: { createHtmlOutputFromFile: (n) => htmlOut(fs.readFileSync(path.join(ROOT, 'src', n + '.html'), 'utf8')), createHtmlOutput: (h) => htmlOut(h),
      XFrameOptionsMode: { DEFAULT: 'DEFAULT', ALLOWALL: 'ALLOWALL' } },
    ScriptApp: { getProjectTriggers: () => env.triggers.slice(), deleteTrigger: (t) => { env.triggers = env.triggers.filter((x) => x !== t); }, newTrigger: triggerBuilder,
      AuthMode: { FULL: 'FULL' }, AuthorizationStatus: { REQUIRED: 'REQUIRED', NOT_REQUIRED: 'NOT_REQUIRED' },
      getAuthorizationInfo: () => ({ getAuthorizationStatus: () => (env.authRequired ? 'REQUIRED' : 'NOT_REQUIRED'), getAuthorizationUrl: () => env.authUrl }) },
  };
  return env;
}

export function loadApp(opts = {}) {
  const env = makeEnv(opts);
  const ctx = vm.createContext(env.globals);
  if (opts.bundle) vm.runInContext(buildBundle().text, ctx, { filename: 'app.txt' });   // the one-file install
  else for (const f of ['src/Detect.gs', 'src/Code.gs']) vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), ctx, { filename: f });
  if (opts.setup !== false) env.props.set('owner', OWNER);
  return { app: ctx, env };
}

export const AUTH_PASS = 'mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass (p=REJECT) header.from=example.com';
export const AUTH_FAIL = 'mx.google.com; dkim=fail; spf=fail smtp.mailfrom=evil.example; dmarc=fail (p=NONE) header.from=paypal.com';
export const DAY_MS = DAY;
export const fixture = (name) => fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', name));
