#!/usr/bin/env node
// Regenerates the README screenshots in docs/screenshots/: builds the workbench,
// exports the replay bundle, starts the app on a free port and drives headless
// Edge or Chrome over the DevTools protocol. No dependencies beyond Node 22+
// (for the global WebSocket), JDK 21 and a Chromium-based browser.
//
//   node scripts/capture-screenshots.mjs
//   CAPTURE_SKIP_BUILD=1      reuse workbench-app/target/*.jar
//   CAPTURE_REUSE_REPLAYS=1   reuse an existing site-dist/ instead of re-exporting it
//   CAPTURE_BROWSER=<path>    browser executable (default: Edge, then Chrome or Chromium)
//
// It fails if a run is missing the finding its screenshot is meant to show, and it
// only stops the app and browser processes it started. Synthetic payers only.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'docs', 'screenshots');
const siteDist = join(root, 'site-dist');
const windows = process.platform === 'win32';
const started = [];

function log(message) {
  console.log(message);
}

function run(command, args, env = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...env } });
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`);
}

function javaBin() {
  return process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', windows ? 'java.exe' : 'java') : 'java';
}

function findBrowser() {
  if (process.env.CAPTURE_BROWSER) return process.env.CAPTURE_BROWSER;
  const candidates = windows
    ? [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean).flatMap(base => [
        join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      ])
    : process.platform === 'darwin'
      ? ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
         '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
      : ['microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser'].flatMap(name =>
          (process.env.PATH || '').split(':').map(dir => join(dir, name)));
  const found = candidates.find(path => existsSync(path));
  if (!found) throw new Error('No Edge, Chrome or Chromium found; set CAPTURE_BROWSER');
  return found;
}

/** Starts a process and resolves with the first match of pattern in its output. */
function startAndWait(command, args, pattern, timeoutMs, logFile) {
  const child = spawn(command, args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  started.push(child);
  let output = '';
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`${command} did not start within ${timeoutMs / 1000} s; see ${logFile}`)), timeoutMs);
    const onData = chunk => {
      output += chunk;
      const match = output.match(pattern);
      if (match) {
        clearTimeout(timer);
        resolvePromise({ child, match });
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', code => {
      clearTimeout(timer);
      writeFileSync(logFile, output);
      reject(new Error(`${command} exited with ${code} during startup; see ${logFile}`));
    });
  }).finally(() => writeFileSync(logFile, output));
}

function stopStarted() {
  for (const child of started) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}

/** Serves site-dist/ on a free loopback port. */
function serveSiteDist() {
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = normalize(join(siteDist, path.endsWith('/') ? `${path}index.html` : path));
    if (!file.startsWith(siteDist + sep) || !existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(readFileSync(file));
  });
  return new Promise(resolvePromise => server.listen(0, '127.0.0.1', () => resolvePromise(server)));
}

/** A minimal DevTools protocol client over the browser's WebSocket. */
class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 0;
    this.pending = new Map();
    this.ws.onmessage = event => {
      const message = JSON.parse(event.data);
      const waiter = this.pending.get(message.id);
      if (!waiter) return;
      this.pending.delete(message.id);
      if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message}`));
      else waiter.resolve(message.result);
    };
  }

  open() {
    return new Promise((resolvePromise, reject) => {
      this.ws.onopen = resolvePromise;
      this.ws.onerror = () => reject(new Error('Could not connect to the browser'));
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.nextId;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolvePromise, reject) => this.pending.set(id, { resolve: resolvePromise, reject, method }));
  }

  async newPage({ width, height, dark = false }) {
    const { targetId } = await this.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await this.send('Target.attachToTarget', { targetId, flatten: true });
    const page = new Page(this, sessionId, width);
    await page.resize(height);
    await page.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }],
    });
    return page;
  }
}

class Page {
  constructor(cdp, sessionId, width) {
    this.cdp = cdp;
    this.sessionId = sessionId;
    this.width = width;
  }

  send(method, params) {
    return this.cdp.send(method, params, this.sessionId);
  }

  resize(height) {
    return this.send('Emulation.setDeviceMetricsOverride', { width: this.width, height, deviceScaleFactor: 1, mobile: false });
  }

  async eval(expression) {
    const result = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(`${expression}: ${result.exceptionDetails.exception?.description || result.exceptionDetails.text}`);
    }
    return result.result.value;
  }

  async waitFor(expression, what, timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.eval(`!!(${expression})`)) return;
      await new Promise(r => setTimeout(r, 100));
    }
    throw new Error(`Timed out waiting for ${what}`);
  }

  async goto(url) {
    await this.send('Page.navigate', { url });
    await this.waitFor(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`, url);
    await this.eval('document.fonts.ready.then(() => true)');
  }

  /** Captures the viewport at height px, scrolled so that document y scrollY is at the top. */
  async shot(name, { height, scrollY = 0 }) {
    await this.resize(height);
    await this.eval(`document.activeElement && document.activeElement.blur(), window.scrollTo(0, ${scrollY}),
      new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`);
    const { data } = await this.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(outDir, name), Buffer.from(data, 'base64'));
    log(`    docs/screenshots/${name} (${this.width}x${height})`);
  }

  async fullPageShot(name) {
    const height = await this.eval('document.documentElement.scrollHeight');
    await this.shot(name, { height });
  }

  /** Document y of the first element matching selector, minus offset. */
  top(selector, offset = 0) {
    return this.eval(`Math.max(0, Math.round(document.querySelector(${JSON.stringify(selector)})
      .getBoundingClientRect().top + window.scrollY - ${offset}))`);
  }
}

/** Runs the onboarding flow in the workbench UI and waits for the finding it should produce. */
async function runInUi(page, base, payerId, fault, expectedCheckId) {
  await page.goto(`${base}/`);
  await page.waitFor(`document.querySelector('input[name="payerId"][value="${payerId}"]')`, 'the payer picker');
  await page.eval(`document.querySelector('input[name="payerId"][value="${payerId}"]').click()`);
  await page.waitFor(`document.querySelector('input[name="fault"][value="${fault}"]')`, 'the fault list');
  await page.eval(`document.querySelector('input[name="fault"][value="${fault}"]').click()`);
  await page.eval(`document.getElementById('run-button').click()`);
  await page.waitFor(`document.getElementById('run-status').textContent.startsWith('Done')`, `the ${fault} run`);
  const failing = await page.eval(`[...document.querySelectorAll('#findings article.finding.FAIL code')].map(c => c.textContent)`);
  if (!failing.includes(expectedCheckId)) {
    throw new Error(`${payerId} with ${fault}: expected FAIL ${expectedCheckId}, got ${failing.join(', ') || 'no FAIL'}`);
  }
  log(`    ${payerId} with ${fault}: FAIL ${failing.join(', ')}`);
}

async function main() {
  const java = javaBin();
  if (process.env.CAPTURE_SKIP_BUILD !== '1') {
    log('==> Building (tests skipped; run ./mvnw verify for those)');
    const mvnw = windows ? ['cmd.exe', ['/d', '/c', 'mvnw.cmd']] : ['./mvnw', []];
    run(mvnw[0], [...mvnw[1], '-B', '-q', '-pl', 'workbench-app', '-am', 'package', '-DskipTests']);
  }
  const jarDir = join(root, 'workbench-app', 'target');
  const jar = existsSync(jarDir) && readdirSync(jarDir).find(f => /^workbench-app-.*\.jar$/.test(f));
  if (!jar) throw new Error('No workbench-app jar; run without CAPTURE_SKIP_BUILD');

  if (process.env.CAPTURE_REUSE_REPLAYS !== '1' || !existsSync(join(siteDist, 'manifest.json'))) {
    log('==> Exporting the replay bundle to site-dist/');
    if (windows) {
      run('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\\export-replays.ps1'], { EXPORT_SKIP_BUILD: '1' });
    } else {
      run('bash', ['scripts/export-replays.sh'], { EXPORT_SKIP_BUILD: '1' });
    }
  }

  const work = mkdtempSync(join(tmpdir(), 'workbench-capture-'));
  const site = await serveSiteDist();
  try {
    log('==> Starting the workbench on a free port');
    const app = await startAndWait(java, ['-jar', join(jarDir, jar), '--server.port=0'],
      /started on port (\d+)/, 120000, join(work, 'app.log'));
    const base = `http://127.0.0.1:${app.match[1]}`;
    log(`    ${base}`);

    log('==> Starting a headless browser');
    const browser = await startAndWait(findBrowser(), [
      '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${join(work, 'profile')}`,
      '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--hide-scrollbars',
      '--force-color-profile=srgb', '--lang=en-US', 'about:blank',
    ], /DevTools listening on (ws:\/\/\S+)/, 30000, join(work, 'browser.log'));
    const cdp = new Cdp(browser.match[1]);
    await cdp.open();

    log('==> Capturing');
    // The onboarding flow: a failing Northwind run, the hook exchange and the first FAIL's evidence expanded.
    const failing = await cdp.newPage({ width: 1280, height: 900 });
    await runInUi(failing, base, 'northwind-synthetic', 'expired-token-401', 'auth.clock-skew');
    await failing.eval(`document.querySelector('#steps li.step.failed details').open = true,
      document.querySelector('#findings article.finding.FAIL details').open = true`);
    await failing.fullPageShot('failing-run.png');

    // The Download report control, in dark mode, under Fabrikam's wrong-audience run.
    const dark = await cdp.newPage({ width: 1256, height: 908, dark: true });
    await runInUi(dark, base, 'fabrikam-synthetic', 'wrong-audience-reject', 'auth.jwt-audience');
    await dark.shot('report-download.png', { height: 908, scrollY: await dark.top('section[aria-labelledby="steps-heading"]', 72) });

    // That run's HTML report: the header, then the findings.
    const reportUrl = (await dark.eval(`document.getElementById('report-link').href`)).replace(/format=\w+/, 'format=html');
    const report = await cdp.newPage({ width: 1256, height: 908 });
    await report.goto(reportUrl);
    await report.shot('report-html.png', { height: 908 });
    const findingsY = await report.eval(`(() => {
      const heading = [...document.querySelectorAll('h2')].find(h => h.textContent.trim() === 'Findings');
      return heading ? Math.round(heading.getBoundingClientRect().top + window.scrollY - 8) : -1;
    })()`);
    if (findingsY < 0) throw new Error('No Findings heading in the HTML report');
    await report.shot('report-findings.png', { height: 908, scrollY: findingsY });

    // The replay viewer from site-dist/, on the Fabrikam wrong-audience run.
    const replay = await cdp.newPage({ width: 1000, height: 1750 });
    await replay.goto(`http://127.0.0.1:${site.address().port}/index.html`);
    const scenario = `document.querySelector('#replay input[type="radio"][value="fabrikam-wrong-audience-reject"]')`;
    await replay.waitFor(scenario, 'the replay scenario picker');
    await replay.eval(`${scenario}.click()`);
    await replay.waitFor(`document.getElementById('replay').textContent.includes('auth.jwt-audience')`,
      'the auth.jwt-audience finding in the replay');
    await replay.shot('replay.png', { height: 1750, scrollY: await replay.top('#replay', 18) });

    await cdp.send('Browser.close').catch(() => {});
  } finally {
    site.close();
    stopStarted();
    await new Promise(r => setTimeout(r, 500));
    rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
  log('');
  log('Capture done: docs/screenshots/ updated.');
}

process.on('exit', stopStarted);
main().catch(error => {
  console.error(`Capture FAILED: ${error.message}`);
  stopStarted();
  process.exit(1);
});
