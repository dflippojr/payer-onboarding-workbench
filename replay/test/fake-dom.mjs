// Just enough DOM for replay.js to render under node:test, with no dependencies.

class FakeNode {
  constructor() { this.childNodes = []; this.parentNode = null; }
  append(...nodes) {
    for (const n of nodes) {
      const node = n instanceof FakeNode ? n : new FakeText(String(n));
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }
  replaceChildren(...nodes) { this.childNodes = []; this.append(...nodes); }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.replaceChildren(String(v)); }
}

class FakeText extends FakeNode {
  constructor(text) { super(); this.text = text; }
  get textContent() { return this.text; }
}

class FakeElement extends FakeNode {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.attributes = {};
    this.listeners = {};
    this.className = '';
    this.checked = false;
    this.classList = { add: c => { this.className = `${this.className} ${c}`.trim(); } };
    this.style = { setProperty: (k, v) => { this.style[k] = String(v); } };
  }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }
  focus() { globalThis.document.activeElement = this; }
  getAttribute(k) { return this.attributes[k] ?? null; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type) { (this.listeners[type] || []).forEach(fn => fn({ target: this })); }
  /** Depth-first list of descendant elements matching `pred`. */
  findAll(pred) {
    const out = [];
    const visit = n => n.childNodes.forEach(c => { if (c instanceof FakeElement) { if (pred(c)) out.push(c); visit(c); } });
    visit(this);
    return out;
  }
}

/**
 * Installs document/Node/fetch/matchMedia globals; `files` maps URL pathnames to response
 * bodies. `reducedMotion` is what prefers-reduced-motion: reduce reports.
 */
export function installFakeDom(files, { reducedMotion = false } = {}) {
  globalThis.Node = FakeNode;
  globalThis.matchMedia = query => ({ matches: query.includes('reduced-motion') && reducedMotion });
  globalThis.document = {
    baseURI: 'https://site.example/page/',
    createElement: tag => new FakeElement(tag),
  };
  globalThis.fetch = async url => {
    const body = files(new URL(url).pathname);
    return body === undefined
      ? { ok: false, status: 404, json: async () => { throw new Error('not found'); } }
      : { ok: true, status: 200, json: async () => JSON.parse(body) };
  };
  return { createRoot: () => new FakeElement('div') };
}
