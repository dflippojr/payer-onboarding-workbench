// Detects credential material that workbench-core's Redactor (and RunReport's field
// masking) would have replaced with [REDACTED]. A hit means something reached the
// bundle unredacted. Keep these in step with Redactor.java.

const MASK = '[REDACTED]';

/** Form and query keys Redactor masks. */
const FORM_SECRET_KEYS = 'client_secret|access_token|refresh_token|id_token|password|api_key|apikey|private_key';

/** Field names Redactor and RunReport always mask in JSON, compared lower case without _ and -. */
const SECRET_FIELDS = new Set([
  'clientsecret', 'accesstoken', 'refreshtoken', 'idtoken', 'password', 'apikey', 'privatekey',
  'secret', 'clientassertion', 'assertion']);

const isSecretField = name => SECRET_FIELDS.has(name.toLowerCase().replace(/[_-]/g, ''));

/** Whether a Basic token is the base64 of an RFC 7617 user:pass pair, as Redactor decides. */
function isUserPass(token) {
  const data = token.replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]+$/.test(data) || data.length % 4 === 1) return false;
  let decoded;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(data, 'base64'));
  } catch {
    return false;
  }
  return decoded.includes(':') && !/[\u0000-\u001f\u007f-\u009f]/.test(decoded);
}

/** Redactor keeps one short all-letter word after the scheme as prose, unless it is a Basic user:pass. */
const isAuthProse = m => /^[A-Za-z]{1,15}[.)]*$/.test(m[2] + m[3]) && !(/^basic$/i.test(m[1]) && isUserPass(m[2]));

/** A word boundary, or right after a JSON escape such as \n inside a JSON string, as in Redactor. */
const WORD_START = String.raw`(?:\b|(?<=\\[nrtbf]))`;

/** A JSON value Redactor masks for a secret field: a string, or a number, true or false. */
const JSON_SCALAR = String.raw`-?\d[\d.eE+-]*|true\b|false\b`;

/** Headers whose values Redactor masks. */
const SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
  'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret']);

/** Regex checks over raw text. `ok(match)` returning true means the hit is a masked or harmless value. */
const TEXT_CHECKS = [
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // The credential runs to the next whitespace, quote, comma, semicolon or backslash, as in Redactor.
  {
    name: 'Bearer/Basic credential',
    re: new RegExp(String.raw`${WORD_START}(Bearer|Basic)\s+(?!(?:realm|error|error_description|scope)\s*=\s*[^\s,])([A-Za-z0-9\-._~+/]+=*)([^\s"',;\\]*)`, 'gi'),
    ok: isAuthProse,
  },
  // Redactor keeps a JWT's header and claims and masks the signature.
  { name: 'signed JWT', re: new RegExp(String.raw`${WORD_START}eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`, 'g') },
  // JSON secrets, also inside JSON that is itself embedded in a JSON string (\"key\": \"value\").
  {
    name: 'JSON secret field',
    re: new RegExp(String.raw`\\*"([A-Za-z_-]{1,64})\\*"\s*:\s*(?:\\*"((?:[^"\\]|\\[^"])*)|(${JSON_SCALAR}))`, 'g'),
    ok: m => !isSecretField(m[1]) || m[2] === MASK || m[2] === '',
  },
  { name: 'form secret', re: new RegExp(String.raw`${WORD_START}(${FORM_SECRET_KEYS})=([^&\s"\\]*)`, 'gi'), ok: m => m[2] === MASK || m[2] === '' },
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
      if (isSecretField(key) && (typeof x === 'number' || typeof x === 'boolean' || (typeof x === 'string' && x !== MASK && x !== ''))) {
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
