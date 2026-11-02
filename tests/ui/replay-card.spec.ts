import { test, expect, type Page, type Route } from '@playwright/test';
import { readFile } from 'node:fs/promises';

// The replay's scenario cards, in a browser, with no workbench instance. Routes serve the widget from
// the files the export would copy into the bundle: replay/ for replay.css and replay.js, and the app's
// static/shared/present.js for the helpers both import. The host page makes the widget wide enough for
// its full layout and forces four columns, so each card has about 170 px inside.

const HOST = 'https://replay.test';
const MANIFEST = {
  runs: [
    { id: 'fabrikam-healthy', title: 'Fabrikam healthy', payerName: 'Fabrikam Benefits', verdict: 'PASS_WITH_WARNINGS', teaser: 'Healthy connection', file: 'runs/fabrikam-healthy.json' },
    { id: 'northwind-healthy', title: 'Northwind healthy', payerName: 'Northwind Health', verdict: 'PASS', teaser: 'Healthy connection', file: 'runs/northwind-healthy.json' },
    { id: 'fabrikam-wrong-audience', title: 'Fabrikam wrong audience', payerName: 'Fabrikam Benefits', verdict: 'FAIL', teaser: 'Token audience is not the payer audience', file: 'runs/fabrikam-wrong-audience.json' },
    { id: 'northwind-expired', title: 'Northwind expired token', payerName: 'Northwind Health', verdict: 'FAIL', teaser: 'Expired token refused with 401', file: 'runs/northwind-expired.json' },
  ],
};
const RUN = { verdict: { status: 'PASS_WITH_WARNINGS' }, payer: { displayName: 'Synthetic payer' }, steps: [], findings: [] };
const HOST_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/replay.css">
<style>
  #replay { width: var(--host-width, 824px); }
  #replay .pw-choices { grid-template-columns: repeat(4, minmax(0, 1fr)); }
</style></head>
<body><div id="replay"></div>
<script type="module">
  import { mountReplay } from '/replay.js';
  mountReplay(document.getElementById('replay'), { baseUrl: '/' });
</script></body></html>`;

async function serve(route: Route) {
  const path = new URL(route.request().url()).pathname;
  const send = (body: string, contentType: string) => route.fulfill({ status: 200, body, contentType });
  if (path === '/') return send(HOST_PAGE, 'text/html');
  if (path === '/replay.css') return send(await readFile('replay/replay.css', 'utf8'), 'text/css');
  if (path === '/replay.js') return send(await readFile('replay/replay.js', 'utf8'), 'text/javascript');
  if (path === '/shared/present.js') {
    return send(await readFile('workbench-app/src/main/resources/static/shared/present.js', 'utf8'), 'text/javascript');
  }
  if (path === '/manifest.json') return send(JSON.stringify(MANIFEST), 'application/json');
  if (path.startsWith('/runs/')) return send(JSON.stringify(RUN), 'application/json');
  return route.fulfill({ status: 404, body: 'not found' });
}

async function openReplay(page: Page) {
  // The widest host width the cases use is 1200 px, and the widget never outgrows its page.
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.route(`${HOST}/**`, serve);
  await page.goto(`${HOST}/`);
  await expect(page.locator('.pw-choice')).toHaveCount(MANIFEST.runs.length);
  await expect(page.locator('.pw-choice').first()).toContainText('Pass with warnings');
}

async function setHostWidth(page: Page, px: number) {
  await page.evaluate(width => document.documentElement.style.setProperty('--host-width', `${width}px`), px);
  await expect.poll(() => page.locator('#replay').evaluate(el => Math.round(el.getBoundingClientRect().width))).toBe(px);
}

/** The first card: its content width, its row height, and the chip and teaser boxes. */
function measureFirstCard(page: Page) {
  return page.locator('.pw-choice').first().evaluate(card => {
    const rect = (el: Element) => {
      const r = el.getBoundingClientRect();
      return { left: r.left, top: r.top, width: r.width, height: r.height, right: r.right, bottom: r.bottom };
    };
    const style = getComputedStyle(card);
    const contentWidth = card.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    const badge = card.querySelector('.pw-badge') as HTMLElement;
    const teaser = card.querySelector('.pw-choice-teaser') as HTMLElement;
    const longestWord = (teaser.textContent || '').split(/\s+/).reduce((a, b) => (b.length > a.length ? b : a), '');
    // Width of the longest word's first four characters, in the teaser's own font.
    const probe = document.createElement('span');
    const teaserStyle = getComputedStyle(teaser);
    Object.assign(probe.style, {
      position: 'absolute', whiteSpace: 'nowrap', visibility: 'hidden',
      fontFamily: teaserStyle.fontFamily, fontSize: teaserStyle.fontSize, fontWeight: teaserStyle.fontWeight,
      fontStyle: teaserStyle.fontStyle, letterSpacing: teaserStyle.letterSpacing,
    });
    probe.textContent = longestWord.slice(0, 4);
    document.body.append(probe);
    const firstFourCharacters = probe.getBoundingClientRect().width;
    probe.remove();
    const gap = parseFloat(getComputedStyle(badge.parentElement!).columnGap) || 0;
    return {
      contentWidth, cardHeight: rect(card).height, badge: rect(badge), teaser: rect(teaser), gap,
      longestWord, firstFourCharacters, teaserText: teaser.textContent,
    };
  });
}

test('a card about 170 px wide inside keeps its teaser readable beside a Pass with warnings chip', async ({ page }) => {
  await openReplay(page);
  await setHostWidth(page, 1200);
  const normal = await measureFirstCard(page);
  await setHostWidth(page, 824);
  const narrow = await measureFirstCard(page);

  // The reproduction: about 170 px inside the card, and the teaser's word is the one that breaks.
  expect(narrow.contentWidth, 'card content width').toBeGreaterThanOrEqual(160);
  expect(narrow.contentWidth, 'card content width').toBeLessThanOrEqual(180);
  expect(narrow.teaserText).toBe('Healthy connection');
  // The teaser is wider than the first few characters of its longest word, so no word is broken letter by letter.
  expect(narrow.teaser.width, 'teaser width').toBeGreaterThan(narrow.firstFourCharacters);
  // The row stays within one card's normal height above it.
  expect(narrow.cardHeight, 'card height at 170 px').toBeLessThanOrEqual(2 * normal.cardHeight);
});

test('at wider card widths the chip and the teaser stay on one row, as before', async ({ page }) => {
  await openReplay(page);
  await setHostWidth(page, 1200);
  const wide = await measureFirstCard(page);

  expect(wide.badge.top, 'chip and teaser share a row').toBeLessThan(wide.teaser.bottom);
  expect(wide.teaser.top, 'chip and teaser share a row').toBeLessThan(wide.badge.bottom);
  expect(wide.teaser.left, 'teaser sits to the right of the chip').toBeGreaterThan(wide.badge.right);
  expect(wide.teaser.width, 'teaser takes the rest of the row').toBeCloseTo(wide.contentWidth - wide.badge.width - wide.gap, 0);
});
