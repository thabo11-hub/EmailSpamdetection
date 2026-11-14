// Builds the public website into public/: the files in web/ plus the detection rules (src/Detect.gs)
// as detect.js. Only these files are served, so nothing else in the repo is ever exposed.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'public');
const allowed = /\.(html|css|js|ico|png|svg|txt|webmanifest)$/i;

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out);
for (const f of fs.readdirSync(path.join(root, 'web'))) {
  if (!allowed.test(f)) throw new Error('Refusing to publish unexpected file: web/' + f);
  fs.copyFileSync(path.join(root, 'web', f), path.join(out, f));
}
fs.copyFileSync(path.join(root, 'src', 'Detect.gs'), path.join(out, 'detect.js'));
console.log('Built public/: ' + fs.readdirSync(out).sort().join(', '));
