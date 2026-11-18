// Builds the public website into public/:
//  - the files in web/
//  - the detection rules (src/Detect.gs) as detect.js, for the in-browser checker
//  - app.txt: the whole Apps Script app as ONE file (rules + app + dashboard page), which the home page
//    also carries in a hidden box so the "Copy the app" button works with no network access.
// Only these files are served, so nothing else in the repo is ever exposed.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'public');
const allowed = /\.(html|css|js|ico|png|svg|txt|webmanifest)$/i;
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

export function buildBundle() {
  const detect = read('src/Detect.gs'), code = read('src/Code.gs'), page = read('src/Dashboard.html');
  const version = (/var APP_VERSION = '([0-9.]+)'/.exec(code) || [])[1];
  if (!version) throw new Error('APP_VERSION not found in src/Code.gs');
  if (/^\s*function\s+(doGet|setup|runGuard)\b/m.test(detect)) throw new Error('Detect.gs must not define app entry points');
  const header = [
    '// EmailSpamdetection ' + version + ': the whole app in one file.',
    '// Paste this over EVERYTHING in Code.gs (nothing else should be left), tap Save, then',
    '// Deploy > New deployment > Web app > Deploy, allow access, open the Web app link and tap "Turn on protection".',
    '// Source and tests: https://github.com/thabo11-hub/EmailSpamdetection',
    ''
  ].join('\n');
  // The page goes in as one short JavaScript string per line (JSON.stringify makes each one safe). One giant line
  // can get cut off when pasted, so no line in the bundle is long. The last line marks the end, so a cut-off paste is easy to spot.
  const pageLines = page.replace(/\r\n/g, '\n').split('\n').map((l) => '  ' + JSON.stringify(l));
  const text = [header, detect.trim(), '', code.trim(), '', '// The dashboard page (src/Dashboard.html), one line per line.',
    'var DASHBOARD_HTML = [', pageLines.join(',\n'), "].join('\\n');", '',
    '// End of EmailSpamdetection ' + version + '. If this line is missing in your editor, the paste was cut off: copy the app again.', ''].join('\n');
  return { text, version };
}

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function build() {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out);
  for (const f of fs.readdirSync(path.join(root, 'web'))) {
    if (!allowed.test(f)) throw new Error('Refusing to publish unexpected file: web/' + f);
    fs.copyFileSync(path.join(root, 'web', f), path.join(out, f));
  }
  fs.copyFileSync(path.join(root, 'src', 'Detect.gs'), path.join(out, 'detect.js'));

  const bundle = buildBundle();
  fs.writeFileSync(path.join(out, 'app.txt'), bundle.text);
  const index = path.join(out, 'index.html');
  const html = fs.readFileSync(index, 'utf8');
  if (html.split('@@APP_CODE@@').length !== 2) throw new Error('web/index.html needs exactly one @@APP_CODE@@');
  // Function replacements, so "$&" and friends inside the code are never treated as patterns.
  fs.writeFileSync(index, html
    .replace('@@APP_CODE@@', () => escapeHtml(bundle.text))
    .replace(/@@APP_VERSION@@/g, () => bundle.version)
    .replace(/@@APP_SIZE@@/g, () => Math.round(Buffer.byteLength(bundle.text) / 1024) + ' KB'));
  console.log('Built public/: ' + fs.readdirSync(out).sort().join(', ') + ' (app ' + bundle.version + ')');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) build();
