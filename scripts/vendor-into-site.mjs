// Copy the replay bundle into a website, or check whether a website's copy is stale.
//   node scripts/vendor-into-site.mjs <site>/public/workbench                 from site-dist/ (node scripts/export-replays.mjs)
//   node scripts/vendor-into-site.mjs --from-release <site>/public/workbench  from the bundle published from main
//   node scripts/vendor-into-site.mjs --check <site>/public/workbench         exit 0 current, 1 stale, 2 could not tell
// Vendoring overwrites the bundle's files in the target and drops recorded runs the new bundle
// no longer has (runs/*.json); nothing else in the target is touched.
// The published bundle is the rolling replay-bundle pre-release that publish-replay-bundle.yml
// replaces after every green CI run on main. WORKBENCH_RELEASE_URL and WORKBENCH_API_URL point
// the release modes elsewhere (the tests use a local server); GITHUB_TOKEN, when set, is sent to
// the GitHub API only. This script needs nothing but Node 22+ and tar, so a website repository
// can run a copy of it without building this project.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const USAGE = 'Usage: node scripts/vendor-into-site.mjs [--check | --from-release] <site>/public/workbench';
export const RELEASE_URL = 'https://github.com/dflippojr/payer-onboarding-workbench/releases/download/replay-bundle';
export const API_URL = 'https://api.github.com/repos/dflippojr/payer-onboarding-workbench';
export const BUNDLE_ASSET = 'replay-bundle.tar.gz';

const inside = (child, parent) => {
  const rel = relative(parent, child);
  return rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
};

/** Copies every file under dist into target, after removing the target's runs/*.json. Returns the file count. */
export function vendor(dist, target) {
  if (!existsSync(join(dist, 'manifest.json'))) throw new Error(`No bundle in ${dist}: it has no manifest.json.`);
  if (inside(target, dist) || inside(root, target)) {
    throw new Error(`Refusing to vendor into ${target}: pick a folder outside the bundle that does not contain this repository.`);
  }
  const files = [];
  (function walk(dir) {
    if (!lstatSync(dir).isDirectory()) {
      throw new Error(`Refusing ${dir}: bundle may contain only regular files and directories.`);
    }
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const entry = lstatSync(p);
      if (entry.isDirectory()) walk(p);
      else if (entry.isFile()) files.push(relative(dist, p));
      else throw new Error(`Refusing ${p}: bundle may contain only regular files and directories.`);
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
  return files.length;
}

async function get(url, headers = {}) {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`);
  return response;
}

/** The commit a manifest was exported from, without the -dirty suffix, or null when it has none. */
export function manifestCommit(manifest) {
  const commit = typeof manifest?.gitCommit === 'string' ? manifest.gitCommit.replace(/-dirty$/, '') : '';
  return /^[0-9a-f]{7,40}$/.test(commit) ? commit : null;
}

/**
 * Compares the target's manifest.json with the published one. Resolves to { current, published,
 * behind, ahead }: behind is how many main commits the published bundle has that the target's
 * lacks. Throws when either manifest or the comparison can't be read.
 */
export async function checkStaleness(target, { releaseUrl = RELEASE_URL, apiUrl = API_URL, token } = {}) {
  const path = join(target, 'manifest.json');
  if (!existsSync(path)) throw new Error(`No manifest.json in ${target}; nothing has been vendored there.`);
  const current = manifestCommit(JSON.parse(readFileSync(path, 'utf8')));
  const published = manifestCommit(await (await get(`${releaseUrl}/manifest.json`)).json());
  if (!published) throw new Error(`The published manifest at ${releaseUrl}/manifest.json has no gitCommit.`);
  if (!current) return { current, published, behind: null, ahead: 0 };
  if (published.startsWith(current) || current.startsWith(published)) return { current, published, behind: 0, ahead: 0 };
  const headers = { Accept: 'application/vnd.github+json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const compare = await (await get(`${apiUrl}/compare/${current}...${published}`, headers)).json();
  if (!Number.isInteger(compare.ahead_by) || !Number.isInteger(compare.behind_by)) {
    throw new Error(`The comparison of ${current} with ${published} has no commit counts.`);
  }
  return { current, published, behind: compare.ahead_by, ahead: compare.behind_by };
}

/** Downloads the published bundle into a new temporary folder and returns that folder. */
export async function downloadRelease({ releaseUrl = RELEASE_URL } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'pw-replay-bundle-'));
  try {
    const archive = join(dir, BUNDLE_ASSET);
    writeFileSync(archive, Buffer.from(await (await get(`${releaseUrl}/${BUNDLE_ASSET}`)).arrayBuffer()));
    const tar = args => {
      const result = spawnSync('tar', args, { cwd: dir, encoding: 'utf8' });
      if (result.status !== 0) throw new Error(`tar ${args.join(' ')} failed: ${result.error?.message ?? result.stderr.trim()}`);
      return result.stdout;
    };
    for (const entry of tar(['-tzf', BUNDLE_ASSET]).split('\n').filter(Boolean)) {
      if (isAbsolute(entry) || /^[A-Za-z]:/.test(entry) || entry.split(/[\\/]/).includes('..')) {
        throw new Error(`Refusing ${BUNDLE_ASSET}: entry ${entry} would land outside the bundle.`);
      }
    }
    // Both GNU tar and bsdtar prefix verbose entries with the member's type. Check
    // metadata before extraction: safe names alone do not stop links escaping the root.
    for (const entry of tar(['-tvzf', BUNDLE_ASSET]).split('\n').filter(Boolean)) {
      if (!/^[-d]/.test(entry)) {
        throw new Error(`Refusing ${BUNDLE_ASSET}: bundle may contain only regular files and directories.`);
      }
    }
    const bundle = join(dir, 'bundle');
    mkdirSync(bundle);
    tar(['-xzf', BUNDLE_ASSET, '-C', 'bundle']);
    return bundle;
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

async function main(args) {
  const mode = args[0]?.startsWith('--') ? args.shift() : null;
  if (args.length !== 1 || (mode && mode !== '--check' && mode !== '--from-release')) {
    console.error(USAGE);
    return 2;
  }
  const target = resolve(args[0]);
  const releaseUrl = process.env.WORKBENCH_RELEASE_URL || RELEASE_URL;
  if (mode === '--check') {
    const { current, published, behind, ahead } = await checkStaleness(target, {
      releaseUrl, apiUrl: process.env.WORKBENCH_API_URL || API_URL, token: process.env.GITHUB_TOKEN,
    });
    if (!current) {
      console.log(`stale: ${target}/manifest.json names no clean commit; the published bundle is ${published}`);
      return 1;
    }
    if (behind > 0) {
      console.log(`stale by ${behind} commits: ${target} has ${current}, the published bundle is ${published}`);
      return 1;
    }
    console.log(ahead > 0
      ? `current: ${target} has ${current}, ${ahead} commits newer than the published bundle ${published}`
      : `current: ${target} has ${current}, the published bundle`);
    return 0;
  }
  if (mode === '--from-release') {
    const bundle = await downloadRelease({ releaseUrl });
    try {
      const count = vendor(bundle, target);
      const commit = manifestCommit(JSON.parse(readFileSync(join(bundle, 'manifest.json'), 'utf8')));
      console.log(`Vendored ${count} files from the published bundle (${commit}) into ${target}`);
    } finally {
      rmSync(resolve(bundle, '..'), { recursive: true, force: true });
    }
    return 0;
  }
  if (!existsSync(join(root, 'site-dist', 'manifest.json'))) {
    console.error('No bundle in site-dist/; run node scripts/export-replays.mjs first, or use --from-release.');
    return 1;
  }
  console.log(`Vendored ${vendor(join(root, 'site-dist'), target)} files from site-dist/ into ${target}`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = process.argv.includes('--check') ? 2 : 1;
  }
}
