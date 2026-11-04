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

/** The private members of a JWK, which Redactor masks in a JSON object with a kty member (#262). */
const JWK_PRIVATE_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

/** Whitespace in JSON, also escaped (\n, \t) where the JSON is embedded in a JSON string. */
const JSON_SPACE = String.raw`(?:\s|\\+[nrt])*`;

/**
 * A JSON member name as Redactor reads one: letters, _ and -, each character also as a \u escape
 * ("kt\u0079" is kty), its backslash escaped again at any depth. decodeName gives the name compared.
 */
const NAME = String.raw`((?:[A-Za-z_-]|\\+u[0-9A-Fa-f]{4}){1,64})`;

/** The name a NAME match spells, each \u escape decoded. */
const decodeName = name => name.replace(/\\+u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

/** `name` as a regex for a JSON member name: each letter as it is or as its \u escape, in either hex case. */
const spelled = name => [...name].map(c => {
  const hex = [...c.charCodeAt(0).toString(16).padStart(4, '0')].map(h => /[a-f]/.test(h) ? `[${h}${h.toUpperCase()}]` : h);
  return String.raw`(?:${c}|\\+u${hex.join('')})`;
}).join('');

/** A kty member, also spelled with escapes, also in JSON embedded in a JSON string at any depth. */
const JWK_TYPE = new RegExp(String.raw`\\*"${spelled('kty')}\\*"${JSON_SPACE}:`);

/** Whether text has a kty member, searched once per text rather than once per member. */
let jwkTypeText = null;
let jwkTypeFound = false;
const hasJwkType = text => {
  if (text !== jwkTypeText) {
    jwkTypeText = text;
    jwkTypeFound = JWK_TYPE.test(text);
  }
  return jwkTypeFound;
};

/** How many backslashes are right before `text[i]`. */
const backslashesBefore = (text, i) => {
  let k = 0;
  while (text[i - 1 - k] === '\\') k++;
  return k;
};

/**
 * For each member name read at escape depth `run` (r backslashes before its quote, 2^d - 1 at depth d), whether
 * the JSON object holding it has a kty member of its own, as Redactor masks only a JWK's own members: a map
 * from the index of the name's opening quote. One pass over the text: a quote with b backslashes before it
 * delimits a string at that depth when b % (2r + 2) == r, ends the string the JSON is embedded in (and every
 * object open at that depth) when b % (r + 1) != r, and is escaped inside a string otherwise.
 */
function membersInJwks(text, run) {
  const kind = b => {
    if (b % (2 * run + 2) === run) return 'quote';
    return b % (run + 1) === run ? 'escaped' : 'end';
  };
  const result = new Map();
  // The open objects and arrays, innermost last: an object as {kty, names}, an array as null.
  const open = [];
  const close = () => {
    const object = open.pop();
    if (object) object.names.forEach(name => result.set(name, object.kty));
  };
  let inString = false;
  let nameNext = false;
  let name = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') {
      let j = i;
      while (text[j] === '\\') j++;
      if (text[j] !== '"') {
        i = j - 1;
        continue;
      }
      const k = kind(j - i);
      i = j;
      if (k === 'escaped') continue;
      if (k === 'end') {
        while (open.length > 0) close();
        inString = false;
        nameNext = false;
        name = -1;
        continue;
      }
    } else if (c !== '"') {
      if (inString) continue;
      if (c === '{') {
        open.push({ kty: false, names: [] });
        nameNext = true;
      } else if (c === '[') {
        open.push(null);
        nameNext = false;
      } else if ((c === '}' || c === ']') && open.length > 0) {
        close();
        nameNext = false;
      } else if (c === ',') {
        nameNext = open.length > 0 && open[open.length - 1] !== null;
      }
      continue;
    } else if (kind(0) !== 'quote') {
      // A bare quote at depth 1 or deeper ends the embedded JSON.
      while (open.length > 0) close();
      inString = false;
      nameNext = false;
      name = -1;
      continue;
    }
    // A string delimiter at this depth: i is its quote, run backslashes before it.
    if (!inString) {
      inString = true;
      if (nameNext && open.length > 0) {
        name = i - run;
        open[open.length - 1].names.push(name);
      }
      nameNext = false;
    } else {
      inString = false;
      if (name >= 0 && decodeName(text.slice(name + run + 1, i - run)) === 'kty') open[open.length - 1].kty = true;
      name = -1;
    }
  }
  while (open.length > 0) close();
  return result;
}

/** membersInJwks for the text last asked about, one map per escape depth. */
let jwkMembersText = null;
let jwkMembers = new Map();

/**
 * Whether the member whose name's quote is at `quote` is in an object with a kty member of its own. A member
 * the pass did not read as one (no object around it at its depth) counts as in a JWK, the stricter answer.
 */
function inObjectWithKty(text, quote) {
  if (text !== jwkMembersText) {
    jwkMembersText = text;
    jwkMembers = new Map();
  }
  const run = backslashesBefore(text, quote);
  if (!jwkMembers.has(run)) jwkMembers.set(run, membersInJwks(text, run));
  const result = jwkMembers.get(run).get(quote - run);
  return result === undefined ? true : result;
}

/** Whether a field whose name's quote is at `quote` holds a JWK's own private member. */
const isJwkMember = (name, text, quote) => JWK_PRIVATE_MEMBERS.has(name) && hasJwkType(text) && inObjectWithKty(text, quote);

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
 * Redactor keeps one short all-letter word after the scheme as prose, unless it is a Basic user:pass;
 * after Token, which is also an ordinary word, the word may end with a colon (token endpoint: <url>).
 * So is an arrow after Token (POST /oauth/token -> 200), and only there: any other punctuation may be a
 * credential (Bearer -._~+/=).
 * The scanner decodes the word without any trailing period or parenthesis, so it also catches a
 * credential at the end of a sentence.
 */
const isAuthProse = m => {
  if (/^token$/i.test(m[1]) && m[2] + m[3] === '->') return true;
  const word = /^token$/i.test(m[1]) ? (m[2] + m[3]).replace(/:$/, '') : m[2] + m[3];
  return /^[A-Za-z]{1,15}[.)]*$/.test(word) && !(/^basic$/i.test(m[1]) && isUserPass(word.replace(/[.)]+$/, '')));
};

/**
 * A masked JSON string whose closing quote has more of the value right after it ("[REDACTED]"ssTAIL,
 * "[REDACTED]"-tail): only whitespace, a comma or close bracket, or the quote or backslash of an enclosing
 * string may follow the value.
 */
const maskCutShort = m => /^\\*"[^\s,}\]\\"]/.test(m.input.slice(m.index + m[0].length));

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

/**
 * A scheme, its credential and anything after it to a separator, as in Redactor's AUTH_SCHEME. After
 * Bearer the space may be URL-encoded (Bearer%20, Bearer+); after Token and DPoP it may not be a line break.
 */
const AUTH_SCHEME = String.raw`(Bearer|Basic|Token|DPoP)(?:[ \t]+|(?<=Bearer|Basic)\s+|(?<=Bearer)(?:%20|\+))(?!(?:realm|error|error_description|scope)\s*=\s*[^\s,])((?:[A-Za-z0-9\-._~+/%]|${ESCAPED_TOKEN_CHAR})+=*)((?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})*)`;

/** Where a scheme starts, as in Redactor: also right after a URL escape (%3A%20Bearer%20). */
const AUTH_START = String.raw`(?:${WORD_START}|(?<=%[0-9A-F]{2})(?=Bearer))`;

/**
 * Whether an Authorization-style header line's value is prose that Redactor keeps, as it does anywhere:
 * only after Bearer or Basic (Authorization: Token abc is a credential).
 */
const isAuthLineProse = (name, v) => {
  const m = /authorization$/i.test(name) && new RegExp(`^${AUTH_SCHEME}`, 'i').exec(v);
  return Boolean(m) && /^(?:bearer|basic)$/i.test(m[1]) && isAuthProse(m);
};

/**
 * A list of masked values, as redactTree leaves a header-named list, or an empty list (redactHeaders
 * keeps one for a header with no values). An authorization list item may have any token as a scheme in
 * front of the mask (SCRAM-SHA-256 [REDACTED]); Redactor masks any other header's values whole, so
 * their items are bare masks (#292).
 */
const maskedList = item => new RegExp(String.raw`^\s*(?:\]|\\*"${item}\\*"\s*(?:,\s*\\*"${item}\\*"\s*)*\])`);
const MASKED_AUTHORIZATION_LIST = maskedList(String.raw`(?:${SCHEME} )?\[REDACTED\]`);
const MASKED_LIST = maskedList(String.raw`\[REDACTED\]`);

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

/** A unicode escape: a backslash, then u and four hex digits. */
const UNICODE_ESCAPE = /\\u[0-9A-Fa-f]{4}/;

/**
 * `text` with each unicode escape of its outermost JSON string decoded, as Redactor reads one level of nested
 * JSON: an odd run of backslashes ends in an escape of its own, and a quote or backslash stays escaped.
 */
const decodedUnicode = text => text.replace(/(\\+)u([0-9A-Fa-f]{4})/g, (m, run, hex) => {
  if (run.length % 2 === 0) return m;
  const c = String.fromCharCode(parseInt(hex, 16));
  return run.slice(1) + (c === '"' ? '\\"' : c === '\\' ? '\\\\' : c);
});

/** `text` with one level of JSON string escaping taken off (\\ to \, \" to "), any other escape kept. */
const unescapedOnce = text => text.replace(/(\\+)("?)/g, (m, run, quote) =>
  '\\'.repeat(run.length >> 1) + (run.length % 2 === 1 ? (quote ? '"' : '\\') : quote));

/** Regex checks over raw text. `ok(match)` returning true means the hit is a masked or harmless value. */
const TEXT_CHECKS = [
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // The credential, which may be URL-encoded, runs to the next whitespace, quote, comma, semicolon or
  // backslash, as in Redactor; a JSON escape of a token character (\/, \u002B) is that character, not a
  // backslash, also escaped again (\\/) in a recorded body (#211).
  // The match ends at the scheme (the rest is read in a lookahead), so a scheme kept as prose does not
  // hide one right after it (token DPoP <credential>), as in Redactor.
  {
    name: 'Bearer/Basic credential',
    re: new RegExp(String.raw`${AUTH_START}(?=${AUTH_SCHEME})(Bearer|Basic|Token|DPoP)`, 'gi'),
    ok: isAuthProse,
  },
  // Redactor masks the credential through to that end, so anything right after the mask is the rest
  // of it (Bearer [REDACTED]:SECRETPART, Bearer [REDACTED]\/PART, Bearer [REDACTED]\u002BPART).
  { name: 'Bearer/Basic credential cut short', re: new RegExp(String.raw`${AUTH_START}(?:Bearer|Basic|Token|DPoP)(?:[ \t]+|(?<=Bearer|Basic)\s+|(?<=Bearer)(?:%20|\+))\[REDACTED\](?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})`, 'gi') },
  // Redactor keeps a JWT's header and claims and masks the signature.
  { name: 'signed JWT', re: new RegExp(String.raw`${WORD_START}eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`, 'g') },
  // JSON secrets, also inside JSON that is itself embedded in a JSON string (\"key\": \"value\").
  {
    name: 'JSON secret field',
    re: new RegExp(String.raw`\\*"${NAME}\\*"${JSON_SPACE}:${JSON_SPACE}(?:\\*"((?:[^"\\]|\\[^"])*)|(${JSON_SCALAR}))`, 'g'),
    // The value's closing quote is escaped like the key's opening one (k backslashes, so depth k + 1); the
    // capture alone can stop early at an escaped quote or keep the backslashes of the closing one.
    ok: m => {
      const name = decodeName(m[1]);
      // Counted in the input: an earlier match can end inside the run of backslashes before the key.
      const quote = m.index + m[0].indexOf('"');
      if (!isSecretKey(name) && !isJwkMember(name, m.input, quote)) return true;
      if (m[2] === undefined) return false;
      let escaped = 0;
      while (m.input[quote - 1 - escaped] === '\\') escaped++;
      const rest = m.input.slice(m.index + m[0].length - m[2].length);
      return isMaskedValue(name, rest.slice(0, valueEnd(rest, escaped + 1, false))) && !maskCutShort(m);
    },
  },
  // Redactor masks a secret field's object or array value (a private JWK) as a string. A list of
  // masked values is a secret-named list redactTree masked item by item (X-Api-Key: ["[REDACTED]"]);
  // it masks a JWK private member's list whole, so no list of masks is left there.
  {
    name: 'JSON secret structure',
    re: new RegExp(String.raw`\\*"${NAME}\\*"${JSON_SPACE}:${JSON_SPACE}([{[])`, 'g'),
    ok: m => isSecretKey(decodeName(m[1]))
      ? m[2] === '[' && (/authorization$/i.test(decodeName(m[1])) ? MASKED_AUTHORIZATION_LIST : MASKED_LIST).test(m.input.slice(m.index + m[0].length))
      : !isJwkMember(decodeName(m[1]), m.input, m.index + m[0].indexOf('"')),
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
  const scan = view => {
    for (const check of TEXT_CHECKS) {
      for (const m of view.matchAll(check.re)) {
        if (!check.ok || !check.ok(m)) leaks.push({ check: check.name, match: m[0].slice(0, 80) });
      }
    }
  };
  scan(text);
  // The text checks find embedded JSON by its literal quotes, colons and braces. A JSON string may spell any of
  // them as a unicode escape (a backslash and u0022, u003A, u0020..., as .NET's default encoder writes a quote),
  // so text with one is also scanned level by level as Redactor reads it: decoded, then one level of escaping
  // taken off, for as many levels as Redactor reads. No parsing, so cut-off JSON and repeated members count.
  let view = text;
  for (let level = 0; level < 16 && UNICODE_ESCAPE.test(view); level++) {
    const decoded = decodedUnicode(view);
    if (decoded !== view) scan(decoded);
    view = unescapedOnce(decoded);
  }
  // Redactor masks whole each string that still holds escapes after the levels it reads, so any left is a leak.
  if (UNICODE_ESCAPE.test(view)) leaks.push({ check: 'escapes nested past 16 levels', match: view.slice(0, 80) });
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
      const before = leaks.length;
      if (t.startsWith('{') || t.startsWith('[')) {
        try { walk(JSON.parse(t), `${p}<json>`); } catch { /* not JSON as a whole */ }
      }
      // JSON in the string read as text when parsing found nothing: after prose (payer said: {...}), cut off,
      // or repeating a member, which parsing drops.
      if (leaks.length === before && /[{[]/.test(v)) {
        for (const leak of findTextLeaks(v)) leaks.push({ check: leak.check, match: `${p}: ${leak.match}` });
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
      if ('kty' in v && JWK_PRIVATE_MEMBERS.has(k) && x !== MASK && x != null) {
        leaks.push({ check: 'JWK private member', match: `${p}.${k}` });
      }
      if (/headers$/i.test(k) && x && typeof x === 'object' && !Array.isArray(x)) {
        for (const [name, values] of Object.entries(x)) {
          if (!SENSITIVE_HEADERS.has(name.toLowerCase())) continue;
          // Only an authorization value keeps a scheme in front of the mask, as in redactHeaders.
          const masked = /authorization$/i.test(name) ? /^(?:[A-Za-z]+\s+)?\[REDACTED\]$/ : /^\[REDACTED\]$/;
          for (const hv of [].concat(values)) {
            if (!masked.test(String(hv))) {
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
