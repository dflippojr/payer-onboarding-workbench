// Detects credential material that workbench-core's Redactor (and RunReport's field
// masking) would have replaced with [REDACTED]. A hit means something reached the
// bundle unredacted. Keep these in step with Redactor.java.

const MASK = '[REDACTED]';

const SECRET_KEYS = 'client_secret|access_token|refresh_token|id_token|password|api_key|apikey';

/** Field names RunReport always masks, compared lower case without _ and -. */
const SECRET_FIELDS = new Set([
  'clientsecret', 'accesstoken', 'refreshtoken', 'idtoken', 'password', 'apikey', 'privatekey',
  'secret', 'clientassertion', 'assertion']);

/** Headers whose values Redactor masks. */
const SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
  'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret']);

/** Regex checks over raw text. `ok(match)` returning true means the hit is a masked or harmless value. */
const TEXT_CHECKS = [
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // Short all-letter words after the scheme are prose ("a bearer token"), as in Redactor.
  { name: 'Bearer/Basic credential', re: /\b(?:Bearer|Basic)\s+([A-Za-z0-9\-._~+/]+=*)/gi, ok: m => /^[A-Za-z]{1,15}$/.test(m[1]) },
  // Redactor keeps a JWT's header and claims and masks the signature.
  { name: 'signed JWT', re: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/g },
  // JSON secrets, also inside JSON that is itself embedded in a JSON string (\"key\": \"value\").
  {
    name: 'JSON secret field',
    re: new RegExp(`\\\\*"(${SECRET_KEYS})\\\\*"\\s*:\\s*\\\\*"((?:[^"\\\\]|\\\\[^"])*)`, 'gi'),
    ok: m => m[2] === MASK || m[2] === '',
  },
  { name: 'form secret', re: new RegExp(`\\b(${SECRET_KEYS})=([^&\\s"\\\\]*)`, 'gi'), ok: m => m[2] === MASK || m[2] === '' },
];

/** Returns one {check, match} per suspected leak in `text`. */
export function findTextLeaks(text) {
  const leaks = [];
  for (const check of TEXT_CHECKS) {
    for (const m of text.matchAll(check.re)) {
      if (!check.ok || !check.ok(m)) leaks.push({ check: check.name, match: m[0].slice(0, 80) });
    }
  }
  return leaks;
}

/**
 * Walks parsed JSON for secret-named fields and sensitive headers whose values are not
 * masked. String values that are themselves JSON (recorded request/response bodies)
 * are walked too.
 */
export function findJsonLeaks(value, path = '$') {
  const leaks = [];
  const walk = (v, p) => {
    if (typeof v === 'string') {
      const t = v.trim();
      if (t.startsWith('{') || t.startsWith('[')) {
        try { walk(JSON.parse(t), `${p}<json>`); } catch { /* not JSON */ }
      }
      return;
    }
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${p}[${i}]`)); return; }
    if (!v || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      const key = k.toLowerCase();
      if (SECRET_FIELDS.has(key.replace(/[_-]/g, '')) && typeof x === 'string' && x !== MASK && x !== '') {
        leaks.push({ check: 'secret field', match: `${p}.${k}` });
      }
      if (/headers$/i.test(k) && x && typeof x === 'object' && !Array.isArray(x)) {
        for (const [name, values] of Object.entries(x)) {
          if (!SENSITIVE_HEADERS.has(name.toLowerCase())) continue;
          for (const hv of [].concat(values)) {
            if (!/^(?:[A-Za-z]+\s+)?\[REDACTED\]$/.test(String(hv))) {
              leaks.push({ check: 'sensitive header', match: `${p}.${k}.${name}` });
            }
          }
        }
      }
      walk(x, `${p}.${k}`);
    }
  };
  walk(value, path);
  return leaks;
}
