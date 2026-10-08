// Copy the replay bundle (site-dist/, made by node scripts/export-replays.mjs) into a website.
// Usage: node scripts/vendor-into-site.mjs <site>/public/workbench
// Overwrites the bundle's files in the target and drops recorded runs the new bundle no longer
// has (runs/*.json); nothing else in the target is touched.
import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const dist = join(root, 'site-dist');
const target = process.argv[2] && resolve(process.argv[2]);

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!target) fail('Usage: node scripts/vendor-into-site.mjs <site>/public/workbench');
if (!existsSync(join(dist, 'manifest.json'))) {
  fail('No bundle in site-dist/; run node scripts/export-replays.mjs first.');
}
const inside = (child, parent) => {
  const rel = relative(parent, child);
  return !rel.startsWith('..') && !isAbsolute(rel);
};
if (inside(target, dist) || inside(root, target)) {
  fail(`Refusing to vendor into ${target}: pick a folder outside site-dist/ that does not contain this repository.`);
}

const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(relative(dist, p));
  }
})(dist);

const runsDir = join(target, 'runs');
if (existsSync(runsDir)) {
  for (const name of readdirSync(runsDir).filter(n => n.endsWith('.json'))) {
    rmSync(join(runsDir, name));
  }
}
for (const file of files) {
  mkdirSync(resolve(target, file, '..'), { recursive: true });
  copyFileSync(join(dist, file), join(target, file));
}
console.log(`Vendored ${files.length} files from site-dist/ into ${target}`);
