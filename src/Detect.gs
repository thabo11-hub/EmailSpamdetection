/**
 * EmailSpamdetection: the detection rules. Pure JavaScript with no Google services, so the same
 * file runs in Apps Script (next to Code.gs) and in the browser on the public "Check an email" page.
 * Names ending in "_" are private: the dashboard page cannot call them.
 */

var DEFAULT_SETTINGS = {
  checkEveryMinutes: 5,   // how often the inbox guard runs
  dangerousScore: 70,     // at or above: "Dangerous" (moved out of the inbox)
  suspiciousScore: 40,    // at or above: "Check first" (moved out of the inbox)
  dangerousToSpam: false, // true: dangerous mail goes straight to Spam instead of the Dangerous label
  promoDays: 30,          // review list: promotions older than this
  socialDays: 30,         // review list: social notifications older than this
  codeDays: 3,            // review list: login codes older than this
  draftDays: 365,         // outbox: drafts older than this are offered for deletion
  scanYears: 10,          // how far back the websites scan reads
  massRecipients: 25,     // an email you sent to this many people raises an alert
  maxSentPerHour: 40,     // this many emails sent in one hour raises an alert
  alertEmails: true       // email you when the outbox watch sees something
};

// Brands that phishing pretends to be. Words are lower case with punctuation turned into spaces.
var BRANDS = [
  { name: 'PayPal', words: ['paypal'], domains: ['paypal.com'] },
  { name: 'Apple', words: ['apple', 'apple id', 'icloud', 'itunes'], domains: ['apple.com', 'icloud.com', 'itunes.com', 'me.com'] },
  { name: 'Microsoft', words: ['microsoft', 'microsoft 365', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint'], domains: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'msn.com', 'office.com', 'office365.com', 'microsoftonline.com', 'microsoft365.com', 'sharepoint.com', 'onedrive.com'] },
  { name: 'Google', words: ['google', 'gmail', 'youtube'], domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'googlegroups.com', 'google.co.za', 'withgoogle.com', 'android.com'] },
  { name: 'Netflix', words: ['netflix'], domains: ['netflix.com'] },
  { name: 'Amazon', words: ['amazon'], domains: ['amazon.com', 'amazon.co.za', 'amazonaws.com', 'amazonses.com'] },
  { name: 'DHL', words: ['dhl'], domains: ['dhl.com', 'dhl.co.za'] },
  { name: 'FedEx', words: ['fedex'], domains: ['fedex.com'] },
  { name: 'SARS', words: ['sars', 'efiling', 'e filing', 'south african revenue'], domains: ['sars.gov.za'] },
  { name: 'Absa', words: ['absa'], domains: ['absa.co.za', 'absa.africa', 'absa.com'] },
  { name: 'FNB', words: ['fnb', 'first national bank'], domains: ['fnb.co.za', 'firstrand.co.za'] },
  { name: 'Standard Bank', words: ['standard bank', 'standardbank'], domains: ['standardbank.co.za', 'standardbank.com'] },
  { name: 'Nedbank', words: ['nedbank'], domains: ['nedbank.co.za'] },
  { name: 'Capitec', words: ['capitec'], domains: ['capitecbank.co.za'] },
  { name: 'TymeBank', words: ['tymebank', 'tyme bank', 'gotyme'], domains: ['tymebank.co.za', 'gotyme.co.za'] },
  { name: 'Discovery', words: ['discovery bank', 'discovery health', 'discovery vitality'], domains: ['discovery.co.za'] },
  { name: 'African Bank', words: ['african bank'], domains: ['africanbank.co.za'] },
  { name: 'Investec', words: ['investec'], domains: ['investec.com', 'investec.co.za'] },
  { name: 'Takealot', words: ['takealot'], domains: ['takealot.com'] },
  { name: 'Vodacom', words: ['vodacom', 'vodapay'], domains: ['vodacom.co.za'] },
  { name: 'MTN', words: ['mtn'], domains: ['mtn.co.za', 'mtn.com'] },
  { name: 'Telkom', words: ['telkom'], domains: ['telkom.co.za'] },
  { name: 'DStv', words: ['dstv', 'multichoice', 'showmax'], domains: ['dstv.com', 'multichoice.co.za', 'multichoice.com', 'showmax.com'] },
  { name: 'PostNet', words: ['postnet'], domains: ['postnet.co.za'] },
  { name: 'The Courier Guy', words: ['the courier guy', 'courier guy'], domains: ['thecourierguy.co.za'] },
  { name: 'Aramex', words: ['aramex'], domains: ['aramex.com', 'aramex.co.za'] },
  { name: 'SA Post Office', words: ['sapo', 'post office'], domains: ['postoffice.co.za'] },
  { name: 'SANRAL', words: ['sanral', 'e toll', 'etoll'], domains: ['sanral.co.za'] },
  { name: 'Booking.com', words: ['booking com'], domains: ['booking.com'] },
  { name: 'Airbnb', words: ['airbnb'], domains: ['airbnb.com', 'airbnb.co.za'] },
  { name: 'Vrbo', words: ['vrbo', 'expedia'], domains: ['vrbo.com', 'expedia.com', 'expediagroup.com'] },
  { name: 'Agoda', words: ['agoda'], domains: ['agoda.com'] },
  { name: 'Uber', words: ['uber'], domains: ['uber.com'] },
  { name: 'WhatsApp', words: ['whatsapp'], domains: ['whatsapp.com'] },
  { name: 'Meta', words: ['facebook', 'instagram', 'meta for business', 'meta business'], domains: ['facebook.com', 'facebookmail.com', 'meta.com', 'instagram.com', 'metamail.com'] },
  { name: 'LinkedIn', words: ['linkedin'], domains: ['linkedin.com'] },
  { name: 'DocuSign', words: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', words: ['dropbox'], domains: ['dropbox.com'] },
  { name: 'WeTransfer', words: ['wetransfer'], domains: ['wetransfer.com'] },
  { name: 'Adobe', words: ['adobe'], domains: ['adobe.com'] },
  { name: 'Stripe', words: ['stripe'], domains: ['stripe.com'] },
  { name: 'Coinbase', words: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'Binance', words: ['binance'], domains: ['binance.com'] },
  { name: 'Luno', words: ['luno'], domains: ['luno.com'] },
  { name: 'VALR', words: ['valr'], domains: ['valr.com'] },
  { name: 'GitHub', words: ['github'], domains: ['github.com', 'githubusercontent.com', 'githubapp.com'] },
  { name: 'Vercel', words: ['vercel'], domains: ['vercel.com'] },
  { name: 'Samsung', words: ['samsung'], domains: ['samsung.com', 'samsung-mail.com'] }
];

// Platforms that put other people's chosen names in the From line ("vercel[bot]" via GitHub).
var RELAY_PLATFORMS = ['github.com', 'gitlab.com', 'google.com', 'linkedin.com', 'facebookmail.com', 'slack.com',
  'atlassian.net', 'atlassian.com', 'notion.so', 'zoom.us', 'docusign.net', 'dropbox.com', 'calendly.com', 'figma.com',
  'trello.com', 'asana.com', 'microsoft.com', 'sharepoint.com', 'vercel.com', 'supabase.io', 'discord.com', 'x.com',
  'medium.com', 'substack.com', 'beehiiv.com'];

var WEBMAIL = ['gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'icloud.com', 'me.com', 'aol.com', 'protonmail.com', 'proton.me', 'ymail.com', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com',
  'yandex.com', 'mweb.co.za', 'telkomsa.net', 'vodamail.co.za', 'webmail.co.za', 'iafrica.com'];

var SHORTENERS = ['bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rebrand.ly', 't.ly', 'shorturl.at', 'rb.gy', 'ow.ly', 'tiny.cc',
  's.id', 'v.gd', 'qrco.de', 'goo.su', 'bl.ink', 'short.gy'];

// Free hosts that fake login pages often sit on. Only counted when the email also asks you to log in.
var FREE_HOSTS = ['firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'r2.dev', 'github.io', 'glitch.me', 'netlify.app',
  'vercel.app', 'onrender.com', 'weebly.com', 'wixsite.com', '000webhostapp.com', 'ipfs.io', 'dweb.link', 'sites.google.com',
  'forms.gle', 'docs.google.com', 'forms.office.com', 'herokuapp.com', 'replit.app', 'repl.co', 'ngrok.io', 'ngrok-free.app',
  'trycloudflare.com', 'surge.sh', 'blogspot.com', 'godaddysites.com', 'square.site', 'webflow.io', 'notion.site', 'canva.site',
  'jimdosite.com', 'azurewebsites.net', 'blob.core.windows.net', 'storage.googleapis.com', 'dropboxusercontent.com'];

var EXT_DANGEROUS = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'cpl', 'msi', 'msix', 'msp', 'jar', 'js', 'jse', 'vbs', 'vbe', 'wsf',
  'wsh', 'hta', 'ps1', 'psm1', 'lnk', 'reg', 'dll', 'iso', 'img', 'vhd', 'vhdx', 'xll', 'appx', 'appxbundle', 'chm', 'one', 'url',
  'scf', 'inf', 'gadget', 'application', 'msc', 'sys', 'apk'];

var EXT_WEBPAGE = ['html', 'htm', 'shtml', 'xhtml', 'xht', 'mht', 'mhtml', 'svg', 'svgz'];

var EXT_MACRO = ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'xlsb', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm'];

var EXT_ARCHIVE_UNSCANNABLE = ['rar', '7z', 'ace', 'cab', 'gz', 'tgz', 'tar', 'bz2', 'xz', 'arj', 'lz', 'lzh', 'zipx'];

var EXT_LOOKS_HARMLESS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'mp3', 'mp4', 'zip', 'csv'];

var URGENCY_PATTERNS = [
  /\b(urgent(ly)?|immediately|within (24|48) hours|final (notice|warning|reminder)|last (chance|warning)|act now|action required|expires? (today|soon)|suspend(ed|ion)?|deactivat(e|ed|ion)|locked|restricted|unusual (activity|sign-?in|login))\b/i,
  /\b(you (have )?won|winner|prize|lottery|jackpot|inheritance|beneficiary|claim your (reward|prize|refund)|gift ?card|free money|investment opportunity|double your|crypto ?(investment|profit))\b/i,
  /\b(parcel|package|delivery|shipment)\b.{0,40}\b(held|on hold|pending|failed|unpaid|customs|fee)\b/i,
  /\b(tax|sars|e-?filing) refund\b|\brefund (is )?(pending|available|approved)\b/i,
  /\b(unpaid|outstanding|overdue) (invoice|toll|fine|balance|bill)\b/i,
  /\b(wire|bank) transfer\b|\bchange (of|in) (bank|banking) details\b|\bnew bank(ing)? details\b/i,
  /\bdear (customer|user|client|member|valued|account holder|sir\/madam)\b/i,
  /\b(guest|customer) (has )?(complain|reported|left a negative)|\bnegative review\b|\bverify your (property|listing)\b/i,
  /\b(mailbox|storage|inbox) (is )?(full|almost full|over quota)\b|\bvoice ?mail\b.{0,30}\b(waiting|received|message)\b/i,
  /\bshared (a|an) (document|file|invoice|pdf) with you\b|\b(document|file) (is )?(ready|waiting) (for you|to view|for signature)\b/i
];

var CREDENTIAL_PATTERNS = [
  /\b(verify|confirm|validate|update|re-?activate|unlock|restore) (your )?(account|identity|password|login|credentials|details|information|card|banking|payment)/i,
  /\b(enter|provide|share|send|reply with) (your )?(password|pin|otp|one-?time pin|cvv|card number|login details|id number)/i,
  /\b(click|tap) (here|below|the link) to (verify|confirm|login|log in|sign in|unlock|restore|update|avoid)/i,
  /\b(login|log in|sign in) (to|and) (avoid|prevent|keep|restore|confirm)/i
];

var PHISHY_SUFFIXES = ['secure', 'security', 'login', 'online', 'verify', 'update', 'refund', 'support', 'account', 'service',
  'alert', 'alerts', 'help', 'pay', 'billing', 'notice', 'auth', 'portal', 'mail', 'team'];

function clip_(s, n) {
  return String(s === null || s === undefined ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n || 200);
}

function parseAddress_(s) {
  s = String(s || '');
  var m = /<([^<>\s]+@[^<>\s]+)>\s*$/.exec(s);
  var email = m ? m[1] : ((s.match(/[^\s<>"',;]+@[^\s<>"',;]+/) || [''])[0]);
  var name = m ? s.slice(0, m.index).trim().replace(/^"+|"+$/g, '').trim() : '';
  return { name: name, email: email.toLowerCase() };
}

function isValidEmail_(e) {
  e = String(e || '');
  return e.length <= 254 && /^[a-z0-9][a-z0-9._%+\-]{0,63}@(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(e);
}

function isValidDomain_(d) {
  d = String(d || '');
  return d.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(d);
}

var TWO_LEVEL_SUFFIXES = ['co.za', 'org.za', 'gov.za', 'ac.za', 'net.za', 'web.za', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'co.in', 'co.jp', 'com.ng', 'co.ke', 'com.na', 'co.bw', 'co.zw', 'com.mx',
  'com.sg', 'com.my', 'com.tr', 'co.ug'];

function rootDomain_(domain) {
  var p = String(domain || '').toLowerCase().replace(/\.$/, '').split('.');
  if (p.length >= 3 && TWO_LEVEL_SUFFIXES.indexOf(p.slice(-2).join('.')) >= 0) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}

function hostOf_(url) {
  var m = /^([a-z][a-z0-9+.\-]*):\/\/([^\/?#\\]*)/i.exec(String(url || '').trim());
  if (!m) return null;
  var authority = m[2];
  var host = authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d*$/, '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  return { scheme: m[1].toLowerCase(), host: host, userinfo: authority.indexOf('@') >= 0 };
}

function isIpHost_(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(':') >= 0 || /^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host);
}

function hostInList_(host, list) {
  host = String(host || '').toLowerCase();
  for (var i = 0; i < list.length; i++) {
    if (host === list[i] || host.slice(-(list[i].length + 1)) === '.' + list[i]) return true;
  }
  return false;
}

function decodeEntities_(s) {
  return String(s || '')
    .replace(/&#x([0-9a-f]+);?/gi, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
    .replace(/&#(\d+);?/g, function (_, d) { return String.fromCharCode(Number(d)); })
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function levenshtein_(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  var prev = [], i, j;
  for (j = 0; j <= b.length; j++) prev[j] = j;
  for (i = 1; i <= a.length; i++) {
    var cur = [i];
    for (j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

function normalizeHomoglyphs_(s) {
  return String(s).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1i!|]/g, 'l')
    .replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/\$/g, 's');
}

// Only plain https web addresses on a public name, no tricks, are ever fetched or shown as links.
function safeHttpsUrl_(u) {
  u = String(u || '').trim();
  if (!u || u.length > 2048 || /[\s\u0000-\u001f\u007f<>"'`\\]/.test(u)) return false;
  var h = hostOf_(u);
  if (!h || h.scheme !== 'https' || h.userinfo) return false;
  if (!isValidDomain_(h.host) || isIpHost_(h.host)) return false;
  if (/(^|\.)(localhost|local|internal|intranet|home|lan|corp)$/i.test(h.host)) return false;
  return true;
}

function decodeUri_(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }

// mailto: unsubscribe addresses. CR/LF are stripped so nothing can add extra mail headers,
// and only to, subject and body are used (cc/bcc in the link are ignored).
function parseMailto_(v) {
  var m = /^mailto:([^?]+)(?:\?(.*))?$/i.exec(String(v || '').trim());
  if (!m) return null;
  var to = decodeUri_(m[1]).trim().toLowerCase();
  if (!isValidEmail_(to)) return null;
  var params = {};
  (m[2] || '').split('&').forEach(function (kv) {
    var i = kv.indexOf('=');
    if (i > 0) params[kv.slice(0, i).toLowerCase()] = decodeUri_(kv.slice(i + 1).replace(/\+/g, ' '));
  });
  function plain(s, n) { return String(s || '').replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, n).trim(); }
  return { to: to, subject: plain(params.subject, 200) || 'unsubscribe', body: plain(params.body, 500) || 'unsubscribe' };
}

function parseAuth_(header) {
  var h = String(header || '').toLowerCase();
  function get(k) { var m = new RegExp('\\b' + k + '=([a-z]+)').exec(h); return m ? m[1] : 'none'; }
  return { spf: get('spf'), dkim: get('dkim'), dmarc: get('dmarc') };
}

function normalizeName_(s) { return ' ' + String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim() + ' '; }

function brandClaimed_(text) {
  var n = normalizeName_(text);
  for (var i = 0; i < BRANDS.length; i++) {
    for (var j = 0; j < BRANDS[i].words.length; j++) {
      if (n.indexOf(' ' + BRANDS[i].words[j] + ' ') >= 0) return BRANDS[i];
    }
  }
  return null;
}

function allBrandDomains_() {
  var out = [];
  BRANDS.forEach(function (b) { out = out.concat(b.domains); });
  return out;
}

// Does this registered domain imitate a brand? (paypa1.com, absa-secure.com, sars.gov.za.refund.xyz…)
function lookalike_(root) {
  root = String(root || '').toLowerCase();
  if (!root || allBrandDomains_().indexOf(root) >= 0) return null;
  var label = root.split('.')[0];
  var norm = normalizeHomoglyphs_(label);
  var tokens = label.split('-');
  var best = null;
  function consider(brand, points, how) { if (!best || points > best.points) best = { brand: brand, points: points, how: how }; }
  BRANDS.forEach(function (b) {
    b.domains.forEach(function (d) {
      var bl = d.split('.')[0];
      if (bl.length < 3) return;
      if (label === bl) { consider(b, 25, 'same name, different ending'); return; }
      if (norm === normalizeHomoglyphs_(bl)) { consider(b, 60, 'look-alike letters'); return; }
      if (tokens.length > 1 && tokens.indexOf(bl) >= 0) { consider(b, 50, 'brand name with extra words'); return; }
      for (var s = 0; s < PHISHY_SUFFIXES.length; s++) {
        if (label === bl + PHISHY_SUFFIXES[s] || label === PHISHY_SUFFIXES[s] + bl) { consider(b, 45, 'brand name with extra words'); return; }
      }
      if (bl.length >= 5 && label.length >= 5 && levenshtein_(label, bl) === 1) { consider(b, 45, 'one letter different'); return; }
      if (bl.length >= 5 && label.indexOf(bl) === 0 && label.length >= bl.length + 3) consider(b, 30, 'brand name with extra letters');
    });
  });
  return best;
}

// Reads a zip file's table of contents without unpacking it, so a "zip bomb" can't fill memory.
function zipEntries_(bytes) {
  var n = bytes ? bytes.length : 0;
  if (n < 22) return null;
  function u8(i) { return bytes[i] & 0xff; }
  function u16(i) { return u8(i) | (u8(i + 1) << 8); }
  function u32(i) { return (u8(i) | (u8(i + 1) << 8) | (u8(i + 2) << 16)) + u8(i + 3) * 16777216; }
  var eocd = -1;
  for (var i = n - 22; i >= Math.max(0, n - 65557); i--) { if (u32(i) === 0x06054b50) { eocd = i; break; } }
  if (eocd < 0) return null;
  var count = u16(eocd + 10), p = u32(eocd + 16);
  if (p >= n) return null;
  var names = [], encrypted = false, total = 0, packed = 0;
  for (var k = 0; k < count && k < 2000; k++) {
    if (p + 46 > n || u32(p) !== 0x02014b50) return null;
    var flags = u16(p + 8), csize = u32(p + 20), usize = u32(p + 24), nlen = u16(p + 28), xlen = u16(p + 30), clen = u16(p + 32);
    var name = '';
    for (var j = 0; j < nlen && p + 46 + j < n; j++) name += String.fromCharCode(u8(p + 46 + j));
    if (flags & 1) encrypted = true;
    total += usize; packed += csize;
    names.push(name);
    p += 46 + nlen + xlen + clen;
  }
  return { names: names, encrypted: encrypted, total: total, entries: count,
    bomb: total > 1e9 || (packed > 0 && total > 1e8 && total / packed > 1000) };
}

function fileRisk_(name, inner) {
  var raw = String(name || '');
  var n = raw.toLowerCase().trim();
  if (/[‪-‮⁦-⁩]/.test(raw)) return { points: 90, why: 'File name hides its real type with invisible characters: ' + clip_(raw, 60) };
  var parts = n.split('.');
  var ext = parts.length > 1 ? parts.pop() : '';
  var prev = parts.length > 1 ? parts[parts.length - 1] : '';
  if (EXT_DANGEROUS.indexOf(ext) >= 0) {
    if (EXT_LOOKS_HARMLESS.indexOf(prev) >= 0) return { points: 90, why: 'Disguised file: "' + clip_(raw, 60) + '" looks like a .' + prev + ' but is a .' + ext };
    return { points: 80, why: 'Dangerous file type .' + ext + ' (' + clip_(raw, 60) + ')' };
  }
  if (EXT_WEBPAGE.indexOf(ext) >= 0) return { points: 60, why: 'Web-page attachment (.' + ext + '), a common way to send fake login pages' };
  if (EXT_MACRO.indexOf(ext) >= 0) return { points: 55, why: 'Office file with macros (.' + ext + ')' };
  if (ext === 'zip') return zipRisk_(raw, inner);
  if (EXT_ARCHIVE_UNSCANNABLE.indexOf(ext) >= 0) return { points: 30, why: 'Archive that can\'t be checked (.' + ext + ')' };
  return { points: 0, why: '' };
}

function zipRisk_(name, z) {
  if (z === 'too-big') return { points: 25, why: 'Zip file too big to check: ' + clip_(name, 60) };
  if (!z || typeof z !== 'object') return { points: 20, why: 'Zip file that could not be read: ' + clip_(name, 60) };
  if (z.encrypted) return { points: 45, why: 'Password-protected zip, which hides its contents from virus scanners: ' + clip_(name, 60) };
  if (z.bomb) return { points: 40, why: 'Zip file that would unpack to a huge size' };
  var worst = { points: 0, why: '' };
  (z.names || []).forEach(function (inner) {
    var r = fileRisk_(inner, null);
    if (r.points > worst.points) worst = r;
  });
  if (worst.points > 0) return { points: Math.max(worst.points, 50), why: 'Inside ' + clip_(name, 40) + ': ' + worst.why };
  return { points: 0, why: '' };
}

function attachmentRisk_(atts) {
  var best = 0, reasons = [];
  (atts || []).forEach(function (a) {
    var r = fileRisk_(a.name, a.inner);
    if (r.points > 0 && reasons.length < 3) reasons.push(r.why);
    if (r.points > best) best = r.points;
  });
  return { points: best, reasons: reasons };
}

function extractLinks_(html) {
  var out = [], re = /<a\b[^>]*?\bhref\s*=\s*(["'])([\s\S]*?)\1[^>]*>([\s\S]*?)<\/a>/gi, m, count = 0;
  var src = String(html || '').slice(0, 300000);
  while ((m = re.exec(src)) && count++ < 300) {
    out.push({ href: decodeEntities_(m[2]).trim(), text: decodeEntities_(m[3].replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim() });
  }
  return out;
}

function extractTextUrls_(text) {
  return (String(text || '').slice(0, 50000).match(/\bhttps?:\/\/[^\s<>"'()\[\]]+/gi) || []).slice(0, 100);
}

function linkRisk_(html, text, authPass) {
  var links = extractLinks_(html).concat(extractTextUrls_(text).map(function (u) { return { href: u, text: '' }; }));
  var f = { script: false, userinfo: false, ip: false, puny: false, short: false, free: false, look: null, mismatch: null };
  links.slice(0, 400).forEach(function (l) {
    var href = l.href;
    if (/^\s*(javascript|data|vbscript|file):/i.test(href)) { f.script = true; return; }
    var h = hostOf_(href);
    if (!h || (h.scheme !== 'http' && h.scheme !== 'https')) return;
    if (h.userinfo) f.userinfo = true;
    if (isIpHost_(h.host)) f.ip = true;
    if (h.host.indexOf('xn--') >= 0) f.puny = true;
    if (hostInList_(h.host, SHORTENERS)) f.short = true;
    if (hostInList_(h.host, FREE_HOSTS)) f.free = true;
    var hr = rootDomain_(h.host);
    if (!f.look) { var la = lookalike_(hr); if (la && la.points >= 45) f.look = { la: la, root: hr }; }
    var tm = /^(?:https?:\/\/)?((?:[a-z0-9\-]+\.)+[a-z]{2,24})(?:[\/?#]\S*)?$/i.exec(l.text || '');
    if (tm && !f.mismatch && rootDomain_(tm[1].toLowerCase()) !== hr) f.mismatch = { shown: tm[1].toLowerCase(), real: h.host };
  });
  var pts = 0, reasons = [];
  function add(p, why) { pts += p; reasons.push(why); }
  if (f.script) add(40, 'Has a link that runs code (javascript: or data:)');
  if (f.userinfo) add(30, 'Has a link that hides its real address with "@"');
  if (f.ip) add(30, 'Links to a bare IP address instead of a website name');
  if (f.puny) add(25, 'Links to an address written in look-alike international letters (xn--)');
  if (f.look) add(40, 'Links to ' + f.look.root + ', which imitates ' + f.look.la.brand.name);
  if (f.mismatch) add(authPass ? 8 : 25, 'A link shows ' + f.mismatch.shown + ' but really goes to ' + f.mismatch.real);
  if (f.short) add(8, 'Uses a link shortener that hides where it goes');
  return { points: Math.min(pts, 70), reasons: reasons, freeHost: f.free };
}

function contentRisk_(text, fromRoot, freeHost) {
  var u = 0, c = 0, reasons = [];
  URGENCY_PATTERNS.forEach(function (p) { if (p.test(text)) u += 7; });
  CREDENTIAL_PATTERNS.forEach(function (p) { if (p.test(text)) c += 12; });
  u = Math.min(u, 21); c = Math.min(c, 24);
  if (u) reasons.push('Pressure words (urgent, suspended, prize, refund, final notice...)');
  if (c) reasons.push('Asks you to verify, log in or share details');
  var pts = u + c;
  if (c && freeHost) { pts += 20; reasons.push('The login link is on a free website host, not the company\'s own site'); }
  var b = brandClaimed_(text.slice(0, 300));
  if (b && (u || c) && b.domains.indexOf(fromRoot) < 0) { pts += 20; reasons.push('Talks about ' + b.name + ' but was not sent by ' + b.name); }
  return { points: pts, reasons: reasons, credential: c > 0 };
}

/**
 * Scores one email. m = plain data (see toPlain_), ctx = what is known about the sender.
 * Returns { score, level: clean | suspicious | dangerous, reasons: [...] }.
 */
function scoreMessage_(m, ctx, st) {
  ctx = ctx || {}; st = st || DEFAULT_SETTINGS;
  var reasons = [], score = 0;
  function add(points, why) { if (points > 0) { score += points; reasons.push(why); } }
  var fromEmail = String(m.fromEmail || '').toLowerCase();
  var fromDomain = fromEmail.split('@')[1] || '';
  var fromRoot = rootDomain_(fromDomain);
  var auth = parseAuth_(m.auth);
  var authPass = auth.dmarc === 'pass' || (auth.dkim === 'pass' && auth.spf === 'pass');
  var att = attachmentRisk_(m.attachments);   // always counted, even for trusted senders

  if (!ctx.allowed) {
    if (!isValidEmail_(fromEmail)) add(15, 'The sender address is malformed');
    if (auth.dmarc === 'fail') add(35, 'Failed DMARC: the sender address is probably forged');
    if (auth.spf === 'fail') add(15, 'Failed SPF: sent from a server that may not send for ' + fromDomain);
    else if (auth.spf === 'softfail') add(8, 'SPF soft fail for ' + fromDomain);
    if (auth.dkim === 'fail') add(10, 'Failed DKIM signature');
    if (fromDomain.indexOf('xn--') >= 0) add(30, 'Sender domain uses look-alike international letters');

    // A platform that shows other people's chosen names ("vercel[bot]" via GitHub) is not impersonating
    // anyone. Free webmail never counts as such a platform: anyone can call themselves "Absa Bank" on Gmail.
    var relayed = authPass && WEBMAIL.indexOf(fromRoot) < 0 &&
      (hostInList_(fromDomain, RELAY_PLATFORMS) || allBrandDomains_().indexOf(fromRoot) >= 0);
    var claimed = relayed ? null : brandClaimed_(m.fromName);
    if (claimed && claimed.domains.indexOf(fromRoot) < 0) {
      add(35, 'Says it is from ' + claimed.name + ' but was sent from ' + (fromDomain || 'an unknown address'));
      if (WEBMAIL.indexOf(fromRoot) >= 0) add(25, claimed.name + ' would not email you from a free ' + fromRoot + ' address');
    }
    var look = lookalike_(fromRoot);
    if (look) add(look.points, 'Sender domain ' + fromRoot + ' imitates ' + look.brand.name + ' (' + look.how + ')');

    var rt = String(m.replyTo || '').toLowerCase();
    if (rt.indexOf('@') > 0) {
      var rtRoot = rootDomain_(rt.split('@')[1]);
      if (rtRoot && rtRoot !== fromRoot) {
        if (WEBMAIL.indexOf(rtRoot) >= 0 && WEBMAIL.indexOf(fromRoot) < 0) add(20, 'Replies would go to a free ' + rtRoot + ' address, not to ' + fromRoot);
        else add(8, 'Replies would go to a different domain (' + rtRoot + ')');
      }
    }
    var lk = linkRisk_(m.html, m.text, authPass);
    if (lk.points) { score += lk.points; reasons = reasons.concat(lk.reasons); }
    var text = (String(m.subject || '') + '\n' + String(m.text || '')).slice(0, 20000);
    var ct = contentRisk_(text, fromRoot, lk.freeHost);
    if (ct.points) { score += ct.points; reasons = reasons.concat(ct.reasons); }

    if (ctx.knownContact) score = Math.max(0, score - 25);
    else if (ctx.firstTime && (score >= 15 || att.points > 0)) add(10, 'First email ever from this sender');
  }
  (ctx.external || []).forEach(function (hit) { add(80, hit); });

  var total = score + att.points;
  var level = total >= st.dangerousScore ? 'dangerous' : total >= st.suspiciousScore ? 'suspicious' : 'clean';
  return { score: total, level: level, reasons: att.reasons.concat(reasons) };
}

// Outgoing mail: your own address passes every sender check, so only attachments and links count.
function scoreOutgoing_(m, st) {
  st = st || DEFAULT_SETTINGS;
  var a = attachmentRisk_(m.attachments), l = linkRisk_(m.html, m.text, false);
  var score = a.points + l.points;
  return { score: score, level: score >= st.dangerousScore ? 'dangerous' : score >= st.suspiciousScore ? 'suspicious' : 'clean', reasons: a.reasons.concat(l.reasons) };
}
