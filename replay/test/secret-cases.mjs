// Seeded generator for the class-level leak check (#160): the same secret shapes and placements as
// workbench-core's RedactorPropertyTest (random tokens, Basic user:pass, colon-split bearers,
// numeric secrets, PEM private keys; raw or URL-encoded; in headers, bodies and query strings, with
// or without the text quoted inside a JSON string, also by a serializer that escapes / as \/).
// Everything is generated; nothing secret-shaped is committed.

/** Characters of an RFC 6750 b64token, without the = padding. */
const TOKEN_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/';

/** A secret leaks if any run of this many of its characters is still in the output. */
export const PIECE = 8;

const BEFORE = ['', ' ', '\n', '\r\n', '\t', '(', '"', 'Authorization: ', 'debug='];
const AFTER = ['', ' ', '\n', ',', ';', ')', '.', '"', "'", '&next=1', ' and more text'];
const JSON_FIELDS = [
  'client_secret', 'clientSecret', 'client-secret', 'access_token', 'accessToken', 'ACCESS_TOKEN',
  'refresh_token', 'id_token', 'password', 'api_key', 'apiKey', 'private_key', 'secret',
  'client_assertion', 'assertion'];
const FORM_KEYS = [
  'client_secret', 'Client_Secret', 'access_token', 'ACCESS_TOKEN', 'refresh_token', 'id_token',
  'password', 'api_key', 'apikey', 'private_key'];
const PEM_KEYS = ['private_key', 'privateKey', 'Private-Key'];
const CREDENTIAL_HEADERS = ['X-Api-Key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret', 'Cookie', 'Set-Cookie'];
const AUTHORIZATION_HEADERS = ['Authorization', 'authorization', 'Proxy-Authorization'];
const PEM_LABELS = ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'OPENSSH PRIVATE KEY'];
const USER_CHARS = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).filter(c => c !== ':').join('');
const PASS_CHARS = `${Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join('')}éüß€`;

/** The text as it is, quoted inside a JSON string, or quoted by a serializer that escapes / (#211). */
const WRAPS = ['NONE', 'JSON', 'JSON_ESCAPED_SLASHES'];

const TEXT_SLOTS = ['AUTH_TEXT', 'HEADERS_ECHO', 'JSON_FIELD', 'FORM_BODY', 'QUERY_STRING', 'PEM_TEXT'];
const SLOTS = ['AUTHORIZATION_HEADER', 'CREDENTIAL_HEADER', ...TEXT_SLOTS];

/** mulberry32: a small seeded PRNG, so a failure names the seed that reproduces it. */
function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (min, max) => min + Math.floor(next() * (max - min + 1));
  const pick = list => list[int(0, list.length - 1)];
  const string = (chars, min, max) => Array.from({ length: int(min, max) }, () => pick([...chars])).join('');
  return { int, pick, string, bool: () => next() < 0.5 };
}

/** One short all-letter word after a scheme, perhaps ending a sentence, is prose by design (#160). */
function token(r) {
  for (;;) {
    const t = r.string(TOKEN_CHARS, PIECE, 64) + '='.repeat(r.int(0, 2));
    if (!/^[A-Za-z]{1,15}\.*$/.test(t)) return { shape: 'TOKEN', value: t };
  }
}

function secret(r) {
  switch (r.int(0, 4)) {
    case 0: return token(r);
    case 1: return {
      shape: 'BASIC_USER_PASS',
      value: Buffer.from(`${r.string(USER_CHARS, 3, 20)}:${r.string(PASS_CHARS, 3, 30)}`, 'utf8').toString('base64'),
    };
    case 2: return { shape: 'COLON_BEARER', value: `${r.string(TOKEN_CHARS, 4, 32)}:${r.string(`${TOKEN_CHARS}:`, 4, 32)}` };
    case 3: return { shape: 'NUMERIC', value: String(r.int(100000, Number.MAX_SAFE_INTEGER)) };
    default: {
      const label = r.pick(PEM_LABELS);
      const newline = r.pick(['\n', '\r\n']);
      const key = Buffer.from(Array.from({ length: r.int(48, 1200) }, () => r.int(0, 255)));
      const lines = key.toString('base64').match(/.{1,64}/g);
      const truncated = r.bool();
      return {
        shape: 'PEM',
        value: `-----BEGIN ${label}-----${newline}${lines.join(newline)}${newline}${truncated ? '' : `-----END ${label}-----`}`,
        // Redactor keeps the armor lines so the key type stays readable; the base64 lines are the secret.
        pemLines: lines.filter(l => l.length >= PIECE),
      };
    }
  }
}

/** Generates `count` placements of fresh secrets from `seed`. */
export function generateCases(seed, count) {
  const r = rng(seed);
  return Array.from({ length: count }, () => {
    const s = secret(r);
    const slot = r.pick(s.shape === 'PEM'
      ? ['CREDENTIAL_HEADER', 'JSON_FIELD', 'FORM_BODY', 'QUERY_STRING', 'PEM_TEXT']
      : SLOTS.filter(x => x !== 'PEM_TEXT'));
    // Outside a secret-named key, a PEM block is found by its armor, which URL encoding removes.
    const encoding = slot === 'PEM_TEXT' ? 'RAW' : r.pick(['RAW', 'URL']);
    // variant picks a key, header name, scheme spelling or body ending; cut, where a mask stops short.
    return {
      secret: s, slot, encoding, variant: r.int(0, 59), before: r.pick(BEFORE), after: r.pick(AFTER),
      wrap: r.pick(WRAPS), carrier: r.pick(['BODY', 'HEADER']), cut: r.int(0, 1e6),
    };
  });
}

/** The secret as it appears in the text: URL-encoded or not. */
export function placed(c) {
  return c.encoding === 'URL' ? encodeURIComponent(c.secret.value) : c.secret.value;
}

/**
 * Places `value` (the secret as placed, or what a mask left of it) the way case `c` says, and
 * returns {text, record}: the text slot's text (null for a header slot) and the recorded exchange
 * the bundle would hold.
 */
export function build(c, value) {
  const pick = list => list[c.variant % list.length];
  const scheme = pick(c.secret.shape === 'BASIC_USER_PASS' ? ['Basic', 'basic', 'BASIC'] : ['Bearer', 'bearer', 'BEARER']);
  const keys = list => (c.secret.shape === 'PEM' ? ['private_key'] : list);
  if (c.slot === 'AUTHORIZATION_HEADER') {
    return { text: null, record: { requestHeaders: { [pick(AUTHORIZATION_HEADERS)]: [`${scheme} ${value}`] } } };
  }
  if (c.slot === 'CREDENTIAL_HEADER') {
    return { text: null, record: { requestHeaders: { [pick(CREDENTIAL_HEADERS)]: [value] } } };
  }
  let text;
  switch (c.slot) {
    case 'AUTH_TEXT': text = `${c.before}${scheme} ${value}${c.after}`; break;
    case 'HEADERS_ECHO':
      text = `{"headers":{"Host":"payer.example.test","Authorization":${JSON.stringify(`${scheme} ${value}`)}}}`;
      break;
    case 'JSON_FIELD': {
      const name = pick(c.secret.shape === 'PEM' ? PEM_KEYS : JSON_FIELDS);
      const number = c.secret.shape === 'NUMERIC' && c.encoding === 'RAW' && c.variant % 2 === 1 && /^\d+$/.test(value);
      const v = number ? value : JSON.stringify(value);
      text = [
        `{"error":"invalid_client","${name}":${v},"error_description":"Client authentication failed"}`,
        `{"error":"invalid_client","${name}":${v}}`,
        `{"error":"invalid_client","${name}":${number ? v : v.slice(0, -1)}`,
      ][c.variant % 3];
      break;
    }
    case 'FORM_BODY':
      text = `grant_type=client_credentials&${pick(keys(FORM_KEYS))}=${value}${c.variant % 2 === 0 ? '&scope=system%2F*.read' : ''}`;
      break;
    case 'QUERY_STRING':
      text = `GET https://payer.example.test/token?${pick(keys(FORM_KEYS))}=${value}${[' HTTP/1.1', '&state=af0ifjsldkj HTTP/1.1', '', '#frag'][c.variant % 4]}`;
      break;
    default: text = `${c.before}${value}${c.after}`;
  }
  if (c.wrap !== 'NONE') {
    const quoted = JSON.stringify(text);
    text = `{"debug":${c.wrap === 'JSON_ESCAPED_SLASHES' ? quoted.replaceAll('/', '\\/') : quoted}}`;
  }
  return { text, record: c.carrier === 'BODY' ? { responseBody: text } : { responseHeaders: { 'X-Debug-Echo': [text] } } };
}
