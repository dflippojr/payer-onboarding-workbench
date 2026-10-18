// The release modes of vendor-into-site.mjs (--check and --from-release) against a local
// server that stands in for the GitHub release download and compare API. Needs tar; no
// bundle and no network: node --test scripts/vendor-into-site.test.mjs
// Plain vendoring from site-dist/ is checked in replay/test/bundle.test.mjs.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = join(import.meta.dirname, 'vendor-into-site.mjs');
const PUBLISHED = 'aaaaaaaaaaaa';
const work = mkdtempSync(join(tmpdir(), 'pw-vendor-test-'));

// What the server answers, per path; tests swap entries. A compare entry is keyed by its range.
const routes = new Map();
const requests = [];
let server, base;

function bundle(files) {
  const dir = mkdtempSync(join(work, 'src-'));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  const archive = join(work, `bundle-${requests.length}-${Math.random().toString(16).slice(2)}.tar.gz`);
  execFileSync('tar', ['-czf', archive, '-C', dir, '.']);
  return readFileSync(archive);
}

const manifest = commit => JSON.stringify({ name: 'payer-onboarding-workbench replay bundle', gitCommit: commit, runs: [] });

function site(commit) {
  const dir = mkdtempSync(join(work, 'site-'));
  if (commit !== undefined) writeFileSync(join(dir, 'manifest.json'), manifest(commit));
  return dir;
}

function run(args, env = {}) {
  return new Promise(resolve => {
    execFile(process.execPath, [script, ...args], {
      env: { ...process.env, WORKBENCH_RELEASE_URL: `${base}/download`, WORKBENCH_API_URL: `${base}/api`, GITHUB_TOKEN: '', ...env },
    }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }));
  });
}

before(async () => {
  server = createServer((req, res) => {
    requests.push({ url: req.url, authorization: req.headers.authorization });
    const body = routes.get(req.url);
    if (body === undefined) {
      res.writeHead(404).end('Not Found');
      return;
    }
    res.writeHead(200).end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  routes.set('/download/manifest.json', manifest(PUBLISHED));
});

after(() => {
  server.close();
  rmSync(work, { recursive: true, force: true });
});

test('--check exits 1 and says how many commits the site copy is behind', async () => {
  routes.set(`/api/compare/9c386b11a911...${PUBLISHED}`, JSON.stringify({ status: 'ahead', ahead_by: 187, behind_by: 0 }));
  const { code, stdout } = await run(['--check', site('9c386b11a911')]);
  assert.equal(code, 1, stdout);
  assert.match(stdout, /^stale by 187 commits: .* has 9c386b11a911, the published bundle is aaaaaaaaaaaa$/m);
});

test('--check exits 0 when the site copy is the published commit', async () => {
  const { code, stdout } = await run(['--check', site(PUBLISHED)]);
  assert.equal(code, 0, stdout);
  assert.match(stdout, /^current: .* has aaaaaaaaaaaa, the published bundle$/m);
});

test('--check matches a full SHA against the published short one, without asking the API', async () => {
  const before = requests.length;
  const { code } = await run(['--check', site(`${PUBLISHED}${'b'.repeat(28)}`)]);
  assert.equal(code, 0);
  assert.ok(requests.slice(before).every(r => !r.url.startsWith('/api/')), JSON.stringify(requests.slice(before)));
});

test('--check counts a dirty export by its commit', async () => {
  routes.set(`/api/compare/cccccccccccc...${PUBLISHED}`, JSON.stringify({ status: 'ahead', ahead_by: 3, behind_by: 0 }));
  const { code, stdout } = await run(['--check', site('cccccccccccc-dirty')]);
  assert.equal(code, 1);
  assert.match(stdout, /stale by 3 commits/);
});

test('--check exits 0 when the site copy is newer than the published bundle', async () => {
  routes.set(`/api/compare/dddddddddddd...${PUBLISHED}`, JSON.stringify({ status: 'behind', ahead_by: 0, behind_by: 2 }));
  const { code, stdout } = await run(['--check', site('dddddddddddd')]);
  assert.equal(code, 0);
  assert.match(stdout, /2 commits newer than the published bundle/);
});

test('--check calls a copy on another branch stale by the main commits it lacks', async () => {
  routes.set(`/api/compare/eeeeeeeeeeee...${PUBLISHED}`, JSON.stringify({ status: 'diverged', ahead_by: 4, behind_by: 1 }));
  const { code, stdout } = await run(['--check', site('eeeeeeeeeeee')]);
  assert.equal(code, 1);
  assert.match(stdout, /stale by 4 commits/);
});

test('--check calls a copy with no commit stale', async () => {
  const { code, stdout } = await run(['--check', site('unknown')]);
  assert.equal(code, 1);
  assert.match(stdout, /^stale: .* names no clean commit/m);
});

test('--check sends GITHUB_TOKEN to the API only', async () => {
  routes.set(`/api/compare/ffffffffffff...${PUBLISHED}`, JSON.stringify({ status: 'ahead', ahead_by: 1, behind_by: 0 }));
  const before = requests.length;
  await run(['--check', site('ffffffffffff')], { GITHUB_TOKEN: 'test-token' });
  const seen = requests.slice(before);
  assert.equal(seen.find(r => r.url.startsWith('/api/')).authorization, 'Bearer test-token');
  assert.equal(seen.find(r => r.url.startsWith('/download/')).authorization, undefined);
});

test('--check exits 2 when it cannot tell', async t => {
  await t.test('no manifest in the target', async () => {
    const { code, stderr } = await run(['--check', site()]);
    assert.equal(code, 2);
    assert.match(stderr, /No manifest.json in/);
  });
  await t.test('nothing published', async () => {
    const { code, stderr } = await run(['--check', site(PUBLISHED)], { WORKBENCH_RELEASE_URL: `${base}/missing` });
    assert.equal(code, 2);
    assert.match(stderr, /HTTP 404/);
  });
  await t.test('the comparison fails', async () => {
    const { code, stderr } = await run(['--check', site('012345678901')]);
    assert.equal(code, 2);
    assert.match(stderr, /compare\/012345678901\.\.\.aaaaaaaaaaaa: HTTP 404/);
  });
});

test('--from-release vendors the published bundle and drops stale runs', async () => {
  routes.set('/download/replay-bundle.tar.gz', bundle({
    'manifest.json': manifest(PUBLISHED), 'replay.js': 'export {}', 'runs/new-run.json': '{"new":true}',
  }));
  const target = site('9c386b11a911');
  mkdirSync(join(target, 'runs'));
  writeFileSync(join(target, 'runs', 'stale-run.json'), '{}');
  writeFileSync(join(target, 'keep.txt'), 'site file');
  const { code, stdout, stderr } = await run(['--from-release', target]);
  assert.equal(code, 0, stderr);
  assert.match(stdout, /^Vendored 3 files from the published bundle \(aaaaaaaaaaaa\) into /m);
  assert.equal(JSON.parse(readFileSync(join(target, 'manifest.json'), 'utf8')).gitCommit, PUBLISHED);
  assert.equal(readFileSync(join(target, 'runs', 'new-run.json'), 'utf8'), '{"new":true}');
  assert.equal(readFileSync(join(target, 'keep.txt'), 'utf8'), 'site file');
  assert.ok(!existsSync(join(target, 'runs', 'stale-run.json')));
  assert.equal((await run(['--check', target])).code, 0, 'a fresh copy must check as current');
});

test('--from-release refuses an archive without a manifest', async () => {
  routes.set('/download/replay-bundle.tar.gz', bundle({ 'replay.js': 'export {}' }));
  const target = site('9c386b11a911');
  const { code, stderr } = await run(['--from-release', target]);
  assert.equal(code, 1);
  assert.match(stderr, /has no manifest.json/);
  assert.equal(JSON.parse(readFileSync(join(target, 'manifest.json'), 'utf8')).gitCommit, '9c386b11a911');
});

test('--from-release refuses an archive entry outside the bundle', async () => {
  const outside = join(work, 'escaped.txt');
  writeFileSync(outside, 'x');
  const archive = join(work, 'absolute.tar.gz');
  execFileSync('tar', ['-czPf', archive, outside]);
  routes.set('/download/replay-bundle.tar.gz', readFileSync(archive));
  const { code, stderr } = await run(['--from-release', site('9c386b11a911')]);
  assert.equal(code, 1);
  assert.match(stderr, /would land outside the bundle/);
});

test('an unknown mode or a missing target prints the usage', async () => {
  for (const args of [['--bogus', 'x'], ['--check'], []]) {
    const { code, stderr } = await run(args);
    assert.equal(code, 2, args.join(' '));
    assert.match(stderr, /^Usage: /);
  }
});
