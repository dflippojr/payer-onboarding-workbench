// Detects credential material that workbench-core's Redactor (and RunReport's field
// masking) would have replaced with [REDACTED]. A hit means something reached the
// bundle unredacted. Keep these at least as strict as Redactor.java: where Redactor exempts
// something (prose after a scheme, the end of a value), the scanner should exempt less, so it can
// catch the next gap rather than share it.

const MASK = '[REDACTED]';

/** Form and query keys Redactor masks. */
const FORM_SECRET_KEYS = 'client_secret|access_token|refresh_token|id_token|password|api_key|apikey|private_key';

/** Field names Redactor and RunReport always mask in JSON, compared lower case without _ and -. */
const SECRET_FIELDS = new Set([
  'clientsecret', 'accesstoken', 'refreshtoken', 'idtoken', 'password', 'apikey', 'privatekey',
  'secret', 'clientassertion', 'assertion']);

const isSecretField = name => SECRET_FIELDS.has(name.toLowerCase().replace(/[_-]/g, ''));

/** Headers whose values Redactor masks. */
const SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
  'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret']);

/** A field Redactor masks: a secret field, or one named like a sensitive header (any case). */
const isSecretKey = name => isSecretField(name) || SENSITIVE_HEADERS.has(name.toLowerCase());

/** An RFC 9110 token, as Redactor reads an Authorization scheme. */
const SCHEME = "[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*";

/**
 * What Redactor leaves for the value of field or header `name`: the mask, after a scheme for an
 * Authorization-style one (Bearer [REDACTED]), or nothing.
 */
const isMaskedValue = (name, v) => v === '' || v === MASK
  || (/authorization$/i.test(name) && new RegExp(`^${SCHEME} \\[REDACTED\\]$`).test(v));

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

/**
 * Redactor keeps one short all-letter word after the scheme as prose, unless it is a Basic user:pass.
 * The scanner decodes the word without any trailing period or parenthesis, so it also catches a
 * credential at the end of a sentence.
 */
const isAuthProse = m => /^[A-Za-z]{1,15}[.)]*$/.test(m[2] + m[3])
  && !(/^basic$/i.test(m[1]) && isUserPass((m[2] + m[3]).replace(/[.)]+$/, '')));

/** A masked JSON string whose closing quote has more of the value right after it ("[REDACTED]"ssTAIL). */
const maskCutShort = m => /^\\*"[A-Za-z0-9]/.test(m.input.slice(m.index + m[0].length));

/**
 * A masked form value is [REDACTED], optionally followed by the start of a JSON escape (\n, \") where
 * the form body is quoted inside JSON. Anything else after the mask, such as a backslash and more
 * text, is the rest of the secret.
 */
const isMaskedFormValue = v => v === '' || v === MASK
  || (v.startsWith(MASK) && /^\\(?:[nrtbf]|$)/.test(v.slice(MASK.length)));

/** A word boundary, or right after a JSON escape such as \n inside a JSON string, as in Redactor. */
const WORD_START = String.raw`(?:\b|(?<=\\[nrtbf]))`;

/**
 * A JSON escape of a token character, as in Redactor: \/ or the \u escape of a letter, digit or one of
 * -._~+/= (System.Text.Json escapes +), also escaped again. Used with the i flag.
 */
const ESCAPED_TOKEN_CHAR = String.raw`\\+(?:/|u00(?:2[BDEF]|3[0-9D]|[46][1-9A-F]|[57][0-9A]|5F|7E))`;

/** A JSON value Redactor masks for a secret field: a string, or a number, true or false. */
const JSON_SCALAR = String.raw`-?\d[\d.eE+-]*|true\b|false\b`;

/** A scheme, its credential and anything after it to a separator, as in Redactor's AUTH_SCHEME. */
const AUTH_SCHEME = String.raw`(Bearer|Basic)\s+(?!(?:realm|error|error_description|scope)\s*=\s*[^\s,])((?:[A-Za-z0-9\-._~+/%]|${ESCAPED_TOKEN_CHAR})+=*)((?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})*)`;

/** Whether an Authorization-style header line's value is prose that Redactor keeps, as it does anywhere. */
const isAuthLineProse = (name, v) => {
  const m = /authorization$/i.test(name) && new RegExp(`^${AUTH_SCHEME}`, 'i').exec(v);
  return Boolean(m) && isAuthProse(m);
};

/**
 * A list of masked values, each optionally after a scheme, as redactTree leaves a header-named list, or
 * an empty list (redactHeaders keeps one for a header with no values). Any token is a scheme for an
 * authorization list (SCRAM-SHA-256 [REDACTED]); for any other name only letters are, as before #261.
 */
const maskedList = scheme => new RegExp(String.raw`^\s*(?:\]|\\*"(?:${scheme} )?\[REDACTED\]\\*"\s*(?:,\s*\\*"(?:${scheme} )?\[REDACTED\]\\*"\s*)*\])`);
const MASKED_AUTHORIZATION_LIST = maskedList(SCHEME);
const MASKED_LIST = maskedList('[A-Za-z]+');

/**
 * How many backslashes escaped the line break before a header line at `index`, as Redactor counts
 * them (1 in a JSON string, 2 in JSON embedded in one), or 0 where a line starts in plain text. A line
 * at the start of a JSON string is as deep as the string: one more than the backslashes before its quote.
 */
function lineDepth(text, index) {
  if (text[index - 1] === '"') {
    let k = 0;
    while (text[index - 2 - k] === '\\') k++;
    return k + 1;
  }
  if (index < 2 || !/[nr]/i.test(text[index - 1]) || text[index - 2] !== '\\') return 0;
  let i = index - 1;
  while (i > 0 && text[i - 1] === '\\') i--;
  const run = index - 1 - i;
  return run & -run;
}

/**
 * Where a value inside a JSON string escaped to `depth` (1 in a JSON string, 2 in JSON embedded in one)
 * ends, as in Redactor's endOfEscapedLine: c backslashes before a quote end the string when
 * c % 2d < d, and, with `lineBreaks`, before n or r are a line break when c % 2d == d. In plain text
 * (depth 0) only a JSON line-break escape ends it (an odd run before n or r), as in HEADER_LINE.
 */
function valueEnd(value, depth, lineBreaks = true) {
  const d = depth || 1;
  for (let i = 0; i < value.length; i++) {
    if (depth > 0 && value[i] === '"') return i;
    if (value[i] !== '\\') continue;
    const run = i;
    while (value[i] === '\\') i++;
    const escapes = (i - run) % (2 * d);
    if ((lineBreaks && /[nr]/.test(value[i] ?? '') && escapes === d) || (depth > 0 && value[i] === '"' && escapes < d)) {
      return run;
    }
  }
  return value.length;
}

/** Regex checks over raw text. `ok(match)` returning true means the hit is a masked or harmless value. */
const TEXT_CHECKS = [
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // The credential, which may be URL-encoded, runs to the next whitespace, quote, comma, semicolon or
  // backslash, as in Redactor; a JSON escape of a token character (\/, \u002B) is that character, not a
  // backslash, also escaped again (\\/) in a recorded body (#211).
  {
    name: 'Bearer/Basic credential',
    re: new RegExp(String.raw`${WORD_START}${AUTH_SCHEME}`, 'gi'),
    ok: isAuthProse,
  },
  // Redactor masks the credential through to that end, so anything right after the mask is the rest
  // of it (Bearer [REDACTED]:SECRETPART, Bearer [REDACTED]\/PART, Bearer [REDACTED]\u002BPART).
  { name: 'Bearer/Basic credential cut short', re: new RegExp(String.raw`${WORD_START}(?:Bearer|Basic)\s+\[REDACTED\](?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})`, 'gi') },
  // Redactor keeps a JWT's header and claims and masks the signature.
  { name: 'signed JWT', re: new RegExp(String.raw`${WORD_START}eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`, 'g') },
  // JSON secrets, also inside JSON that is itself embedded in a JSON string (\"key\": \"value\").
  {
    name: 'JSON secret field',
    re: new RegExp(String.raw`\\*"([A-Za-z_-]{1,64})\\*"\s*:\s*(?:\\*"((?:[^"\\]|\\[^"])*)|(${JSON_SCALAR}))`, 'g'),
    // The value's closing quote is escaped like the key's opening one (k backslashes, so depth k + 1); the
    // capture alone can stop early at an escaped quote or keep the backslashes of the closing one.
    ok: m => {
      if (!isSecretKey(m[1])) return true;
      if (m[2] === undefined) return false;
      // Counted in the input: an earlier match can end inside the run of backslashes before the key.
      const quote = m.index + m[0].indexOf('"');
      let escaped = 0;
      while (m.input[quote - 1 - escaped] === '\\') escaped++;
      const rest = m.input.slice(m.index + m[0].length - m[2].length);
      return isMaskedValue(m[1], rest.slice(0, valueEnd(rest, escaped + 1, false))) && !maskCutShort(m);
    },
  },
  // Redactor masks a secret field's object or array value (a private JWK) as a string. A list of
  // masked values is a recorded header (X-Api-Key: ["[REDACTED]"]).
  {
    name: 'JSON secret structure',
    re: /\\*"([A-Za-z_-]{1,64})\\*"\s*:\s*([{[])/g,
    ok: m => !isSecretKey(m[1]) || (m[2] === '['
      && (/authorization$/i.test(m[1]) ? MASKED_AUTHORIZATION_LIST : MASKED_LIST).test(m.input.slice(m.index + m[0].length))),
  },
  // The value runs to the next &, whitespace or quote, past any backslash.
  { name: 'form secret', re: new RegExp(String.raw`${WORD_START}(${FORM_SECRET_KEYS})=([^&\s"]*)`, 'gi'), ok: m => isMaskedFormValue(m[2]) },
  // A sensitive header line (Cookie: sid=...) where a line starts, also after an escaped line break in a
  // JSON string, as in Redactor. Redactor masks the value to the end of the line, so only an escaped line
  // break or the closing quote of a JSON string may follow the mask; an Authorization line it keeps as
  // prose is not flagged.
  {
    name: 'sensitive header line',
    // The value is read in a lookahead, so the match ends at the name and a header line on the next
    // escaped line is scanned on its own; valueEnd finds where the value ends.
    // An escaped tab may indent the line or follow the colon, as in Redactor's ESCAPED_HEADER_LINE.
    // A JSON string's start is a line start too: Redactor saw the body before it was serialized.
    re: new RegExp(String.raw`(?:^|(?<=\\[nr])|(?<=[:\[,]\s*\\*"))(?:[ \t]|\\+t)*(${[...SENSITIVE_HEADERS].join('|')}):(?:[ \t]|\\+t)*(?=([^\r\n]*))`, 'gim'),
    ok: m => {
      const v = m[2].slice(0, valueEnd(m[2], lineDepth(m.input, m.index)));
      return v.trim() === '' || isMaskedValue(m[1], v) || isAuthLineProse(m[1], v);
    },
  },
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
 * are walked too. A header list under a *headers map is left to the sensitive-header check.
 */
export function findJsonLeaks(value, path = '$') {
  const leaks = [];
  const walk = (v, p, inHeaders = false) => {
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
      // Redactor.redactTree masks a header-named list item by item (authorization: ["Bearer [REDACTED]"]).
      const maskedHeaderList = SENSITIVE_HEADERS.has(key) && Array.isArray(x)
        && x.every(hv => typeof hv === 'string' && isMaskedValue(key, hv));
      if (isSecretKey(key) && (typeof x === 'number' || typeof x === 'boolean'
          || (x && typeof x === 'object' && !inHeaders && !maskedHeaderList)
          || (typeof x === 'string' && !isMaskedValue(key, x)))) {
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
      walk(x, `${p}.${k}`, /headers$/i.test(k));
    }
  };
  walk(value, path);
  return leaks;
}
