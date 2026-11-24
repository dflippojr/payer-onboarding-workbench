// The bundle check (#425, stage 3 of #377): judges recorded text by the invariants of the Redactor's canonical output
// instead of reading every escape spelling as the Redactor might. A bundle file is parsed with JSON.parse, each string
// in it that parses as JSON is parsed again, and what comes out must hold:
//
//   1. A secret-named member's value is exactly a form the Redactor writes: the mask, null, for an
//      Authorization-style name a listed scheme and the mask, or a list of such strings.
//   2. In an object with a kty member (a JWK), a private member's value is the mask or null.
//   3. No decoded string holds a scheme credential, key armor, a JWT signature (or a JWT whose header or payload
//      holds a secret), a form secret, a credential header line, a quoted secret name whose value is not such a form,
//      or text right behind a mask.
//   4. No string holds secret vocabulary next to a spelling the Redactor does not write: a JSON-looking start that
//      does not parse, JSON whose member names repeat, or a quote or backslash that only a decoding of the string's
//      escapes shows.
//
// A string that is not JSON is text: each JSON value embedded in it is judged by 1 and 2, and the text around those
// values by 3 and 4, as it is spelled and again at each decoding of its JSON escapes (a plain left-to-right unescape,
// repeated until nothing decodes). No rule reads an escape spelling: a quote or backslash spelled as an escape is a
// plain one in the next decoding, where the same rules read it.
//
// Independent of workbench-core's Redactor on purpose (#360): nothing here is generated from it or shared with it,
// and this file imports nothing. The name lists below are the contract, as
// workbench-core/src/test/resources/redaction-corpus.json is.

const MASK = '[REDACTED]';

/** Field names whose values are always masked, compared lower case without _ and -. */
const SECRET_FIELDS = ['clientsecret', 'accesstoken', 'refreshtoken', 'idtoken', 'password', 'apikey', 'privatekey',
  'secret', 'clientassertion', 'assertion'];

/** Header names whose values are always masked, compared lower case. */
const SENSITIVE_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'api-key',
  'apikey', 'x-auth-token', 'x-access-token', 'x-client-secret'];

/** The private members of a JWK, secret in an object with a kty member. */
const JWK_PRIVATE_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

/** The schemes an Authorization-style value may keep in front of the mask, lower case. */
const AUTH_SCHEMES = new Set(['basic', 'bearer', 'concealed', 'digest', 'dpop', 'gnap', 'hoba', 'mutual', 'negotiate',
  'oauth', 'privatetoken', 'scram-sha-1', 'scram-sha-256', 'vapid', 'token', 'ntlm', 'aws4-hmac-sha256']);

const SECRET_FIELD_SET = new Set(SECRET_FIELDS);
const SENSITIVE_HEADER_SET = new Set(SENSITIVE_HEADERS);

/** Whether a member, key or header named `name` holds a secret. */
const isSecretName = name => SECRET_FIELD_SET.has(name.toLowerCase().replace(/[_-]/g, ''))
  || SENSITIVE_HEADER_SET.has(name.toLowerCase());

/** Whether a value named `name` may keep its scheme in front of the mask. */
const keepsScheme = name => name.toLowerCase().endsWith('authorization');

/** The deepest JSON-in-string nesting read as JSON; a string past it is read as text. */
const MAX_LEVELS = 8;

/** The deepest nesting of objects and arrays in one JSON value that is read; the Redactor writes none deeper. */
const MAX_DEPTH = 128;

/** The most decodings of a text's JSON escapes that are read; a text that still decodes after them is flagged. */
const MAX_DECODINGS = 32;

/** The most JWTs nested in one another's claims that are decoded; a deeper one is flagged. */
const MAX_TOKEN_DEPTH = 8;

/** The most leaks one scan keeps. */
const MAX_LEAKS = 64;

/** The whitespace characters the JVM's regex \s reads, for use in a character class. */
const WS = ' \\t\\n\\x0B\\f\\r';

/** Whether the character at `at` ends a value: the end of the text, a comma, a closing bracket or whitespace. */
const endsValue = (text, at) => at >= text.length
  || /[,}\] \t\n\x0B\f\r\x1C-\x1F\u1680\u2000-\u2006\u2008-\u200A\u2028\u2029\u205F\u3000]/.test(text[at]);

/** Whether `value`, a string under the secret name `name`, is a form the Redactor writes. */
function isMaskedString(name, value) {
  if (value === MASK) return true;
  if (!keepsScheme(name) || !value.endsWith(` ${MASK}`)) return false;
  return AUTH_SCHEMES.has(value.slice(0, -MASK.length - 1).toLowerCase());
}

const SHORT_ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

/** `text` with each JSON escape decoded once, left to right; any other backslash is kept. */
function unescaped(text) {
  if (!text.includes('\\')) return text;
  return text.replace(/\\(?:(["\\/bfnrt])|u([0-9A-Fa-f]{4}))/g, (_, short, hex) => (hex === undefined
    ? SHORT_ESCAPES[short]
    : String.fromCharCode(Number.parseInt(hex, 16))));
}

/** `text` and each decoding of its JSON escapes until one decodes nothing; `more` if it still decodes after the bound. */
function decodings(text) {
  const passes = [text];
  let current = text;
  for (let level = 0; level < MAX_DECODINGS; level++) {
    const next = unescaped(current);
    if (next === current) return { passes, more: false };
    passes.push(next);
    current = next;
  }
  return { passes, more: unescaped(current) !== current };
}

/** The leaks of one scan, and what it has already decided about each JWT segment. */
class Scan {
  leaks = [];

  /** Whether each JWT segment judged so far holds a secret. */
  segments = new Map();

  /** How many JWTs deep the text being judged sits in other JWTs' claims. */
  tokenDepth = 0;

  flag(check, match) {
    if (this.leaks.length < MAX_LEAKS) this.leaks.push({ check, match: String(match).slice(0, 80) });
  }
}

/** Whether `text`, valid JSON, repeats a member name in one object: JSON.parse keeps only the last of them. */
function repeatsAName(text) {
  const open = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') open.push(new Set());
    else if (c === '[') open.push(null);
    else if (c === '}' || c === ']') open.pop();
    else if (c === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      let after = end + 1;
      while (after < text.length && ' \t\n\r'.includes(text[after])) after++;
      const names = open[open.length - 1];
      if (names && text[after] === ':') {
        const name = JSON.parse(text.slice(i, end + 1));
        if (names.has(name)) return true;
        names.add(name);
      }
      i = end;
    }
  }
  return false;
}

/** How deep the objects and arrays of `text`, valid JSON, nest. */
function nestingDepth(text) {
  let depth = 0;
  let deepest = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++;
    } else if (c === '{' || c === '[') deepest = Math.max(deepest, ++depth);
    else if (c === '}' || c === ']') depth--;
  }
  return deepest;
}

/** Whether a string holds the letters kty at any decoding of its escapes. */
const spellsKty = text => decodings(text).passes.some(pass => pass.includes('kty'));

/**
 * Whether a string anywhere in the object or array `value` spells kty, or a member name other than a kty member's
 * own: such a string may hold the object's own members, so the object is judged as a JWK. Each container is asked once.
 */
function mentionsKty(value, known) {
  if (known.has(value)) return known.get(value);
  let mentions = false;
  for (const [name, member] of Object.entries(value)) {
    if (!Array.isArray(value) && name !== 'kty' && spellsKty(name)) mentions = true;
    else if (typeof member === 'string') mentions = spellsKty(member);
    else if (member !== null && typeof member === 'object') mentions = mentionsKty(member, known);
    if (mentions) break;
  }
  known.set(value, mentions);
  return mentions;
}

/**
 * Whether `member`, the value of the secret name `name`, is a form the Redactor writes (invariant 1). `recorded`: in
 * a bundle file's own header map, where each item of a list is masked on its own; in a recorded text a list holds
 * scheme forms only. `inToken`: in a JWT's claims an empty list is no written form either, as the Redactor masks a
 * token for it.
 */
function isMaskedMember(name, member, recorded, inToken) {
  if (member === null) return true;
  if (typeof member === 'string') return isMaskedString(name, member);
  return Array.isArray(member) && !(inToken && member.length === 0)
    && member.every(item => typeof item === 'string' && isMaskedString(name, item) && (recorded || item !== MASK));
}

/**
 * Judges a parsed JSON value by invariants 1 and 2, and each other string and each member name in it as text.
 * `recorded`: the value is a bundle file's own structure, not JSON a recorded string holds.
 */
function judgeValue(value, scan, level, recorded, known = new Map()) {
  if (typeof value === 'string') {
    judgeText(value, scan, level + 1);
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) judgeValue(item, scan, level, recorded, known);
    return;
  }
  const names = Object.keys(value);
  const jwk = names.includes('kty') || mentionsKty(value, known);
  for (const name of names) {
    const member = value[name];
    if (isSecretName(name)) {
      if (!isMaskedMember(name, member, recorded, scan.tokenDepth > 0)) scan.flag('secret-named member', `${name}: ${JSON.stringify(member)}`);
    } else if (jwk && JWK_PRIVATE_MEMBERS.has(name)) {
      if (member !== null && member !== MASK) scan.flag('JWK private member', `${name}: ${JSON.stringify(member)}`);
    } else {
      judgeValue(member, scan, level, recorded, known);
    }
    judgeText(name, scan, level + 1);
  }
}

/** Whether the bracket at `at` looks like the start of JSON: a name, a string, a value or its own end follows it. */
function looksLikeJson(text, at) {
  let i = at + 1;
  while (i < text.length && ' \t\r\n'.includes(text[i])) i++;
  if (i === text.length) return true;
  const c = text[i];
  if (c === '"' || c === "'" || c === '\\') return true;
  return text[at] === '{' ? c === '}' : c === ']' || c === '[' || c === '{';
}

/**
 * The JSON values embedded in `text`: for each bracket no earlier value holds, the text to its matching bracket,
 * quotes respected, if JSON.parse reads it, it nests no deeper than MAX_DEPTH and no member name repeats in it.
 * Returns their spans and values, and
 * where the first JSON-looking start that does not read is (-1 if none). The walks for candidates that do not read
 * stop after about four times the text's length; past that every start counts as one that does not read.
 */
function embeddedValues(text) {
  const values = [];
  let failed = -1;
  let budget = 4 * text.length + 4096;
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '{' && text[i] !== '[') continue;
    let end = -1;
    let depth = 0;
    let deepest = 0;
    let inString = false;
    for (let k = i; k < text.length && budget > 0; k++, budget--) {
      const c = text[k];
      if (inString) {
        if (c === '\\') k++;
        else if (c === '"') inString = false;
      } else if (c === '"') inString = true;
      else if (c === '{' || c === '[') deepest = Math.max(deepest, ++depth);
      else if ((c === '}' || c === ']') && --depth === 0) {
        end = k + 1;
        break;
      }
    }
    let value;
    if (end > 0 && deepest <= MAX_DEPTH) {
      const json = text.slice(i, end);
      try {
        const read = JSON.parse(json);
        if (!repeatsAName(json)) value = { from: i, to: end, value: read };
      } catch {
        // Not JSON: a start that does not read.
      }
    }
    if (value) {
      values.push(value);
      i = end - 1;
    } else if (failed < 0 && looksLikeJson(text, i)) {
      failed = i;
    }
  }
  return { values, failed };
}

/** Stands for an embedded JSON value in the text the rules read: a name in front of it has a value that is no mask. */
const HOLE = '\uE000';

/**
 * Judges a decoded string at JSON-in-string level `level`: JSON by invariants 1 and 2, any other text by 3 and 4. A
 * string at level 0 is one the workbench recorded whole, so it is also judged as written out ({@link judgeWritten}).
 */
function judgeText(text, scan, level) {
  if (text.length === 0) return;
  const read = level < MAX_LEVELS;
  if (read && /^[ \t\n\r]*[[{"]/.test(text)) {
    let json;
    try {
      json = { value: JSON.parse(text) };
    } catch {
      // Not one JSON value: read as text below.
    }
    if (json) {
      if (nestingDepth(text) > MAX_DEPTH) {
        scan.flag('JSON nested deeper than the Redactor reads', text);
        return;
      }
      if (repeatsAName(text)) scan.flag('JSON that repeats a member name', text);
      judgeValue(json.value, scan, level, false);
      if (level === 0) judgeWritten(JSON.stringify(json.value), scan);
      return;
    }
  }
  const { values, failed } = read ? embeddedValues(text) : { values: [], failed: text.search(/[[{]/) };
  let prose = '';
  let written = '';
  let copied = 0;
  for (const { from, to, value } of values) {
    judgeValue(value, scan, level, false);
    prose += text.slice(copied, from) + HOLE;
    written += text.slice(copied, from) + JSON.stringify(value);
    copied = to;
  }
  prose += text.slice(copied);
  const { passes, more } = decodings(prose);
  if (more) scan.flag('escapes deeper than the check decodes', text);
  passes.forEach((pass, depth) => judgeProse(pass, scan, depth > 0));
  if (failed >= 0 && decodings(text.slice(failed)).passes.some((pass, depth) => holdsVocabulary(pass, depth > 0))) {
    scan.flag('JSON-looking start that does not parse, before secret vocabulary', text.slice(failed));
  }
  if (level === 0 && values.length > 0) judgeWritten(written + text.slice(copied), scan);
}

/**
 * Invariant 4 for a recorded string as it is written out, each JSON value in it in JSON's own spelling: at each
 * decoding of its escapes, where the quotes and backslashes of every level are plain, no quoted secret name has a
 * value that is not a written form at a strict value end, and no JSON value that reads there is a JWK with a private
 * member that is not the mask. This is where a member name that a decoding reads as a secret name, or as more than
 * one member, shows, and a masked value that ends at its string's own closing quote.
 */
function judgeWritten(written, scan) {
  const { passes } = decodings(written);
  for (let depth = 1; depth < passes.length; depth++) {
    const pass = passes[depth];
    judgeMembers(pass, scan, true, false);
    if (!pass.includes('"kty"')) continue;
    let whole;
    try {
      whole = [{ value: JSON.parse(pass) }];
    } catch {
      whole = embeddedValues(pass).values;
    }
    for (const { value } of whole) judgeJwks(value, scan);
  }
}

/** Flags each private member that is not the mask in each object with a kty member in `value`. */
function judgeJwks(value, scan) {
  if (value === null || typeof value !== 'object') return;
  const jwk = !Array.isArray(value) && Object.hasOwn(value, 'kty');
  for (const [name, member] of Object.entries(value)) {
    if (jwk && JWK_PRIVATE_MEMBERS.has(name) && member !== null && member !== MASK) {
      scan.flag('JWK private member in a decoding', `${name}: ${JSON.stringify(member)}`);
    } else {
      judgeJwks(member, scan);
    }
  }
}

/**
 * A scheme (1), its separator, its token68 part (2) and the rest up to whitespace, a quote, a comma, a semicolon or
 * a backslash (3). After Bearer the space may be URL-encoded; after Token and DPoP only spaces and tabs separate.
 */
const SCHEME_CREDENTIAL = new RegExp(String.raw`(?:\b|(?<=%[0-9A-Fa-f]{2})(?=Bearer))(Bearer|Basic|Token|DPoP)`
  + String.raw`(?:[ \t]+|(?<=Bearer|Basic)[${WS}]+|(?<=Bearer)(?:%20|\+))`
  + String.raw`(?!(?:realm|error|error_description|scope)[${WS}]*=[${WS}]*[^${WS},])`
  + String.raw`([A-Za-z0-9\-._~+/%]+=*)([^${WS}"',;\\]*)`, 'gi');

/** Whether base64 `token` decodes to a user:pass pair, which may be all letters. */
function isUserPass(token) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(token) || token.replace(/=+$/, '').length % 4 === 1) return false;
  let decoded;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(token, 'base64'));
  } catch {
    return false;
  }
  return decoded.includes(':') && !/[\u0000-\u001f\u007f-\u009f]/.test(decoded);
}

/**
 * Whether a scheme match is prose ("missing bearer token"): one short all-letter word, for Basic not the base64 of a
 * user:pass pair, and after Token also an arrow or a word a colon ends.
 */
function isProse(scheme, token, rest) {
  let word = token + rest;
  const isToken = scheme.toLowerCase() === 'token';
  if (isToken && word === '->') return true;
  if (isToken && word.endsWith(':')) word = word.slice(0, -1);
  return /^[A-Za-z]{1,15}[.)]*$/.test(word) && !(scheme.toLowerCase() === 'basic' && isUserPass(token.replace(/\.+$/, '')));
}

/** A scheme in front of the mask, and what follows the mask: anything but where a credential ends is the rest of one. */
const MASKED_SCHEME = new RegExp(String.raw`\b(?:Bearer|Basic|Token|DPoP)[${WS}]+\[REDACTED\]([^${WS}"',;\\&)\]}<]?)`, 'gi');

/** The mask with a letter, a digit, _ or - right behind it: the mask stands for a whole value, so that is the rest of one. */
const MASK_THEN_MORE = /\[REDACTED\][A-Za-z0-9_-]/;

/** A run of token characters and dots, the unit a JWT is read from. */
const TOKEN_RUN = /(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]+/g;

/** Any armor header. */
const ARMOR = /-----BEGIN [A-Z0-9 ]*-----/;

/** A lower-case name as a pattern for every spelling that lower-cases to it: KELVIN SIGN lower-cases to k. */
const lowerCasedTo = lower => lower.replaceAll('k', '[k\u212A]');

/** A secret field name with any number of _ or - around and between its letters. */
const FIELD_KEY = `[_-]*(?:${SECRET_FIELDS.map(name => lowerCasedTo(name.split('').join('[_-]*'))).join('|')})[_-]*`;

/** A credential header name. */
const HEADER_NAME = lowerCasedTo(SENSITIVE_HEADERS.join('|'));

/**
 * A form or query key (1) at a word start and its value (2), which runs to an ampersand, whitespace, a quote or a
 * backslash that starts a JSON escape.
 */
const FORM_SECRET = new RegExp(String.raw`(?<![_-])(?=[_-]*?\b)(${FIELD_KEY})=((?:[^&${WS}"\\]|\\\\|\\(?![nrtbf"]))*)`, 'gi');

/**
 * A credential header line: its name (1) at the start of a line, and its value (2), which runs to the end of the line
 * or to a backslash that starts an escaped line break.
 */
const HEADER_LINE = new RegExp(String.raw`(?:^|(?<=[\n\r\u0085\u2028\u2029]))[ \t]*(${HEADER_NAME}):[ \t]*((?:[^\r\n\\]|\\\\|\\(?![nr]))*)`, 'gi');

/**
 * A quoted member name (1) and its colon. A secret name holds only letters, _ and -, each also as a \u escape; the
 * whitespace around the colon may be an escaped line break or tab.
 */
const MEMBER_SPACE = String.raw`(?:[${WS}]|\\[nrt])*`;
const MEMBER_NAME = new RegExp(String.raw`"((?:[A-Za-z\u212A_-]|\\u[0-9A-Fa-f]{4})+)"${MEMBER_SPACE}:${MEMBER_SPACE}`, 'g');

/** What may lie between a name and its key separator, and between that and its value: quotes, whitespace and escapes. */
const GAP = String.raw`(?:[\s\p{Z}\u0085"']|\\+(?:u[0-9A-Fa-f]{4}|[A-Za-z"]))*`;

/** A secret name used as a key, loosely: the name, a gap, a colon or an equals sign, a gap. */
const KEY_NAME = new RegExp(`(?<![_-])(?:${FIELD_KEY}|${HEADER_NAME.replaceAll('-', '[_-]?')})${GAP}[:=]${GAP}`, 'giu');

/** A JWK private member's quoted name used as a key, loosely. */
const PRIVATE_KEY_NAME = new RegExp(`"(?:${[...JWK_PRIVATE_MEMBERS].join('|')})\\\\*"${GAP}[:=]${GAP}`, 'gu');

/** The mask, a scheme in front of it or not, where a value ends: the end, a delimiter or a quote, also an escaped one. */
const MASKED_VALUE = /(?:[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]* )?\[REDACTED\](?=$|["',}\]\s]|(?:\\\\)*\\(?:"|u0022))/y;

/** Whether a name `names` finds in `text` is used as a key whose value is not already the mask or, `evenMasked`, any value. */
function namesAKey(names, text, evenMasked) {
  names.lastIndex = 0;
  for (let m = names.exec(text); m; m = names.exec(text)) {
    if (evenMasked) return true;
    MASKED_VALUE.lastIndex = m.index + m[0].length;
    if (!MASKED_VALUE.test(text)) return true;
  }
  return false;
}

/**
 * Whether `text`, from a JSON-looking start that does not parse, holds secret vocabulary (invariant 4): armor, a
 * secret name used as a key, or with a kty a JWK private member's name used as one. As spelled, a key whose value
 * already is the mask is redacted text read again; in a decoding, where quotes of several levels meet, every key counts.
 */
function holdsVocabulary(text, decoded) {
  return text.includes('-----BEGIN') || namesAKey(KEY_NAME, text, decoded)
    || (text.includes('kty') && namesAKey(PRIVATE_KEY_NAME, text, decoded));
}

/** A JSON list of strings, each part read one way only. */
const STRING_LIST = /\[[ \t\n\r]*(?:"(?:[^"\\]|\\.)*"[ \t\n\r]*(?:,[ \t\n\r]*"(?:[^"\\]|\\.)*"[ \t\n\r]*)*)?\]/y;

/** Whether the value at `at`, after a secret name's colon, is a form the Redactor writes, at a strict value end. */
function readsAsMasked(text, at, name) {
  if (text.startsWith('null', at)) return endsValue(text, at + 4);
  if (text[at] === '[') {
    STRING_LIST.lastIndex = at;
    const list = STRING_LIST.exec(text);
    if (!list) return false;
    let items;
    try {
      items = JSON.parse(list[0]);
    } catch {
      return false;
    }
    return items.every(item => item !== MASK && isMaskedString(name, item)) && endsValue(text, at + list[0].length);
  }
  if (text[at] !== '"') return false;
  const close = text.indexOf('"', at + 1);
  return close > 0 && isMaskedString(name, text.slice(at + 1, close)) && endsValue(text, close + 1);
}

/** The text rules (invariant 3) on text that holds no JSON value, as spelled or, `decoded`, at a decoding of its escapes. */
function judgeProse(text, scan, decoded) {
  const armor = ARMOR.exec(text);
  if (armor) scan.flag('key armor', text.slice(armor.index));
  SCHEME_CREDENTIAL.lastIndex = 0;
  for (let m = SCHEME_CREDENTIAL.exec(text); m; m = SCHEME_CREDENTIAL.exec(text)) {
    if (isProse(m[1], m[2], m[3])) {
      // Read again from the end of the scheme: the word after it may be a scheme itself ("token DPoP <credential>").
      SCHEME_CREDENTIAL.lastIndex = m.index + m[1].length;
    } else {
      scan.flag('scheme credential', m[0]);
    }
  }
  for (const m of text.matchAll(MASKED_SCHEME)) {
    if (m[1]) scan.flag('credential behind the mask', text.slice(m.index, m.index + 60));
  }
  const more = MASK_THEN_MORE.exec(text);
  if (more) scan.flag('text right behind the mask', text.slice(more.index, more.index + 60));
  if (text.includes('eyJ')) judgeTokens(text, scan);
  for (const m of text.matchAll(FORM_SECRET)) {
    if (m[2] !== MASK) scan.flag('form secret', m[0]);
  }
  for (const m of text.matchAll(HEADER_LINE)) {
    if (!keepsLine(m[1], m[2])) scan.flag('credential header line', m[0]);
  }
  judgeMembers(text, scan, decoded, text.includes('"kty"'));
}

/**
 * Whether a credential header line's value is one the Redactor leaves: blank, the form it writes, or after an
 * Authorization-style name a Bearer or Basic the scheme rule reads as prose ("Bearer access token required").
 */
function keepsLine(name, value) {
  if (value.trim() === '' || isMaskedString(name, value)) return true;
  if (!keepsScheme(name)) return false;
  SCHEME_CREDENTIAL.lastIndex = 0;
  const scheme = SCHEME_CREDENTIAL.exec(value);
  return scheme !== null && scheme.index === 0 && /^(?:bearer|basic)$/i.test(scheme[1]) && isProse(scheme[1], scheme[2], scheme[3]);
}

/**
 * Flags each quoted secret name in `text` whose value is not a form the Redactor writes at a strict value end; with
 * `jwk`, a JWK's private member names are secret too.
 */
function judgeMembers(text, scan, decoded, jwk) {
  for (const m of text.matchAll(MEMBER_NAME)) {
    const name = m[1].replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
    if ((isSecretName(name) || (jwk && JWK_PRIVATE_MEMBERS.has(name))) && !readsAsMasked(text, m.index + m[0].length, name)) {
      scan.flag(decoded ? 'secret-named member in a decoding' : 'secret-named member in text', text.slice(m.index, m.index + 80));
      // One is enough, and keeps the work linear: only a value that is flagged is read past its first characters.
      return;
    }
  }
}

/** Whether the base64url `segment` of a JWT holds a secret once decoded, decided once per scan. */
function holdsASecret(segment, scan) {
  if (segment === '') return false;
  if (scan.tokenDepth >= MAX_TOKEN_DEPTH) return true;
  let known = scan.segments.get(segment);
  if (known === undefined) {
    const inner = new Scan();
    inner.segments = scan.segments;
    inner.tokenDepth = scan.tokenDepth + 1;
    judgeText(Buffer.from(segment, 'base64url').toString('utf8'), inner, 0);
    known = inner.leaks.length > 0;
    scan.segments.set(segment, known);
  }
  return known;
}

/**
 * Flags each JWT in `text` that keeps a signature, or whose header or payload holds a secret once decoded. In each
 * run of token characters and dots, a token starts at the first eyJ at a word start of each dot-separated piece: its
 * header runs to the next dot, its payload to the one after, and a signature is whatever follows that dot.
 */
function judgeTokens(text, scan) {
  for (const run of text.matchAll(TOKEN_RUN)) {
    if (!run[0].includes('eyJ')) continue;
    const pieces = run[0].split('.');
    for (let i = 0; i < pieces.length; i++) {
      const at = pieces[i].search(/\beyJ/);
      if (at < 0) continue;
      const header = pieces[i].slice(at);
      const payload = pieces[i + 1] ?? '';
      if (pieces[i + 2]) {
        scan.flag('JWT signature', `${header.slice(0, 24)}.${payload.slice(0, 24)}.${pieces[i + 2].slice(0, 24)}`);
      } else if (holdsASecret(header, scan) || holdsASecret(payload, scan)) {
        scan.flag('JWT that holds a secret', `${header.slice(0, 36)}.${payload.slice(0, 36)}`);
      }
    }
  }
}

/**
 * The leaks in `text`, a recorded string (a body, a header value, a line of evidence) as the workbench stores it:
 * `[{check, match}]`, empty when the text holds only what the Redactor writes.
 */
export function findTextLeaks(text) {
  return judged(scan => judgeText(text, scan, 0));
}

/**
 * The leaks in `value`, a bundle file as JSON.parse reads it: its members by name, and each string and member name
 * in it as {@link findTextLeaks} reads a recorded string.
 */
export function findJsonLeaks(value) {
  return judged(scan => judgeValue(value, scan, -1, true));
}

/** The leaks `judge` finds; a value nested too deep to walk is a leak itself (fail closed). */
function judged(judge) {
  const scan = new Scan();
  try {
    judge(scan);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    scan.flag('nesting deeper than the check can walk', error.message);
  }
  return scan.leaks;
}
