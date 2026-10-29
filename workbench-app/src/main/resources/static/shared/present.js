// Presentation helpers shared by the workbench page (static/app.js) and the replay bundle
// (replay/replay.js). Plain DOM, no build step. Both import it as ./shared/present.js:
// Spring serves it beside app.js, and scripts/export-replays.mjs copies it into the bundle.

/** Builds an element; children may be strings, nodes, arrays or null. on* attributes add listeners. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  const add = c => {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) c.forEach(add);
    else el.append(c instanceof Node ? c : String(c));
  };
  children.forEach(add);
  return el;
}

const SVG = 'http://www.w3.org/2000/svg';
/** Icon shapes on a 20 px grid. */
export const ICONS = {
  pass: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M6.5 10.2l2.3 2.3 4.7-4.9' }]],
  fail: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M7 7l6 6M13 7l-6 6' }]],
  warn: [['path', { d: 'M10 2.5l8 14.5H2z' }], ['path', { d: 'M10 8v4M10 14.5v.5' }]],
  info: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M10 9v5M10 6v.5' }]],
  skipped: [['circle', { cx: 10, cy: 10, r: 8.5, 'stroke-dasharray': '3 3' }], ['path', { d: 'M6.5 10h7' }]],
  pending: [['circle', { cx: 10, cy: 10, r: 8.5, 'stroke-dasharray': '2.5 2.5' }]],
  running: [['circle', { cx: 10, cy: 10, r: 8.5 }], ['path', { d: 'M10 5.5V10l3 2' }]],
  worse: [['path', { d: 'M10 3v14M4 11l6 6 6-6' }]],
  better: [['path', { d: 'M10 17V3M4 9l6-6 6 6' }]],
  unchanged: [['path', { d: 'M4 7.5h12M4 12.5h12' }]],
  fix: [['path', { d: 'M4 10.5l4 4 8-9' }]],
  play: [['path', { d: 'M6.5 4.5l9 5.5-9 5.5z' }]],
  replay: [['path', { d: 'M16 10a6 6 0 1 1-2-4.5' }], ['path', { d: 'M14.5 2.5v3.5H11' }]],
};

/**
 * A decorative inline SVG icon (aria-hidden); the word beside it carries the meaning. `prefix` is the
 * page's icon class (icon in the app, pw-icon in the replay), so the SVG gets class "<prefix> <kind>".
 */
export function icon(kind, size, prefix) {
  const svg = document.createElementNS(SVG, 'svg');
  const attrs = { class: `${prefix} ${kind}`, width: size, height: size, viewBox: '0 0 20 20', fill: 'none',
    stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    'aria-hidden': 'true', focusable: 'false' };
  for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
  for (const [tag, shape] of ICONS[kind] || ICONS.info) {
    const part = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(shape)) part.setAttribute(k, v);
    svg.append(part);
  }
  return svg;
}

export function formatMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

export function headers(map) {
  return Object.entries(map || {}).map(([k, vs]) => `${k}: ${[].concat(vs).join(', ')}`).join('\n') || '(none)';
}

export function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}
