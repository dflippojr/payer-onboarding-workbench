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

/**
 * Whether a member name is a JWK private member's. A decoded name is compared exactly ("\\k" is the extension
 * member \k); only a malformed one (it did not decode, or a stray backslash precedes its quote) is compared with
 * its quotes and backslashes taken out.
 */
const isPrivateName = (name, malformed) => JWK_PRIVATE_MEMBERS.has(name)
  || (malformed && JWK_PRIVATE_MEMBERS.has(name.replace(/["\\]/g, '')));

/**
 * A kty name, each letter as itself or as a \\u escape, after any backslashes or \\u005c escapes (one escape level
 * each). Quotes are not required, so it finds every kty name Redactor reads, and more. An escape whose own characters
 * are escapes (\\u005c\\u0075\\u0030\\u0030\\u0036\\u0062, escaped twice over) is found a level down, decoded once.
 */
const KTY_SPELLING = /(?:k|u006[bB])(?:\\|u005[cC])*(?:t|u0074)(?:\\|u005[cC])*(?:y|u0079)/g;

/** How many kty names {@link KTY_SPELLING} finds in `text`. */
const ktyCount = text => {
  let count = 0;
  for (const _ of text.matchAll(KTY_SPELLING)) count++;
  return count;
};

/**
 * Where each character JSON.parse decodes from the string content `body` starts in `body`: a \\u escape takes 6
 * characters, any other escape 2, any other character 1. Returns a function from an index in the decoded string to
 * that offset (the end of `body` past its last character), building the map only as far as the indexes asked for,
 * charged to the scan's work. Index 0 needs no map, nor, given the decoded string's `length`, an index past its end: a
 * view's start and end are asked for once per view, and building the whole map for its end cost a pass over the view at
 * every level of a long string read from several places (Codex security round 1 at 0ab5aeb).
 */
const sourceOffsets = (body, ctx, length = Infinity) => {
  const offsets = [];
  let i = 0;
  return j => {
    if (j === 0) return 0;
    if (j >= length) return body.length;
    // The map is built only as far as the characters asked for.
    const from = i;
    while (offsets.length <= j && i < body.length) {
      offsets.push(i);
      if (body[i] === '\\') i += body[i + 1] === 'u' ? 6 : 2;
      else i++;
    }
    ctx.work += i - from;
    return j < offsets.length ? offsets[j] : body.length;
  };
};

/**
 * Whether Redactor's JWK search may spend its budget on a text of length `n` when the kty names the scanner finds at
 * one level start at `positions` in that text: then it masks every private member name, in an object or not, so the
 * scanner flags each one left unmasked (Codex round 7).
 *
 * The search reads a view of the text of length m <= n: the text, or the text with escape levels taken off, which only
 * takes characters out, so a character's position m' in the view is at most its position in the text. Each kty name it
 * finds at m' costs it at most 2m' + m characters: the backslashes before the name and the read back to its object, at
 * most m' each, and that object read forward, at most m. Its budget there is 4m + 1024, so for the k names in the view
 * it is spent only when (k - 4)m + 2 * sum(m') > 1024. KTY_SPELLING finds each of them, in the texts the scanner reads d
 * levels down for a view with d escape levels taken off (d + 1 in a report), at a position p in the text at or after
 * the name's (scanJson maps a name found in a decoded string back to where its characters start in the text), so
 * m' <= min(p, m). The bound f(m) = (k - 4)m + 2 * sum(min(p, m)) is linear between the positions, so its most over
 * 0 <= m <= n is at one of them or at n; with k < 2 it is below 0. Each level is judged on its own, as each view has its
 * own budget, and a name found at several levels is not counted twice in one. Nor is a name the scanner reads twice at
 * one level (in a literal scanJson decodes and in the whole string readUnread reads around it, #342): it starts at one
 * position in the text, one character of that level's view, so positions are counted once each. The read after the key
 * blocks are masked spends the rest of the same budget, at most 4m + 1024 for the shortened text, and needs a PEM
 * header in the text, which the PEM block check flags.
 */
const mayExhaustJwkSearch = (n, positions) => {
  const distinct = [...new Set(positions)];
  const k = distinct.length;
  if (k < 2) return false;
  const p = distinct.map(x => Math.min(x, n)).sort((a, b) => a - b);
  // The sum of the positions below the i-th: those are min(p, m) for m = p[i]; the rest are m.
  let below = 0;
  for (let i = 0; i <= k; i++) {
    const m = i < k ? p[i] : n;
    if ((k - 4) * m + 2 * (below + (k - i) * m) > 1024) return true;
    if (i < k) below += p[i];
  }
  return false;
};

/**
 * The most levels of JSON in JSON strings the scanner reads: the top level and 16 below it, as Redactor reads.
 * JSON nested deeper is a leak (Redactor masks whole the string that holds it).
 */
const MAX_LEVELS = 17;

/** How many characters the JSON scan has read, so tests can bound its work without a clock. */
export const scanWork = { characters: 0 };

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

/**
 * A JSON escape of a space, tab, line feed, vertical tab, form feed or carriage return (the whitespace Java's \s takes),
 * also escaped again: \t, \n, \f, \r, or the six-character escape of one (u0020, u0009 to u000D). After a scheme it
 * is the whitespace it stands for, as in Redactor (#212). Used with the i flag.
 */
const ESCAPED_WHITESPACE = String.raw`\\+(?:[nrtf]|u00(?:20|0[9A-D]))`;

/** ESCAPED_WHITESPACE of a space or tab only: all that separates Token or DPoP from a credential. */
const ESCAPED_SPACE_OR_TAB = String.raw`\\+(?:t|u00(?:20|09))`;

/**
 * What separates a scheme from its credential, as in Redactor: spaces and tabs, also written as JSON escapes; after
 * Bearer and Basic any whitespace, also escaped; after Bearer a URL-encoded space (Bearer%20, Bearer+).
 */
const AUTH_SEPARATOR = String.raw`(?:(?:[ \t]|${ESCAPED_SPACE_OR_TAB})+|(?<=Bearer|Basic)(?:\s|${ESCAPED_WHITESPACE})+|(?<=Bearer)(?:%20|\+))`;

/** A JSON value Redactor masks for a secret field: a string, or a number, true or false. */
const JSON_SCALAR = String.raw`-?\d[\d.eE+-]*|true\b|false\b`;

/**
 * A scheme, its credential and anything after it to a separator, as in Redactor's AUTH_SCHEME. After
 * Bearer the space may be URL-encoded (Bearer%20, Bearer+); after Token and DPoP it may not be a line break. Any
 * of them may be a JSON escape (AUTH_SEPARATOR).
 */
const AUTH_SCHEME = String.raw`(Bearer|Basic|Token|DPoP)${AUTH_SEPARATOR}(?!(?:realm|error|error_description|scope)\s*=\s*[^\s,])((?:[A-Za-z0-9\-._~+/%]|${ESCAPED_TOKEN_CHAR})+=*)((?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})*)`;

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
 * An item Redactor leaves in a secret-named list: redactTree masks a header-named list item by item, an
 * authorization item keeping any token as a scheme in front of the mask (SCRAM-SHA-256 [REDACTED]); any
 * other item is a bare mask (#292).
 */
const isMaskedItem = (name, item) => typeof item === 'string'
  && (item === MASK || (/authorization$/i.test(name) && new RegExp(`^${SCHEME} \\[REDACTED\\]$`).test(item)));

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
 * Where a header line's value that starts at `start` ends, at a JSON string escaped to `depth` (1 in a JSON
 * string, 2 in JSON embedded in one), as in Redactor's endOfEscapedLine: c backslashes before a quote end the
 * string when c % 2d < d, and before n or r are a line break when c % 2d == d. In plain text (depth 0) only a
 * JSON line-break escape ends it (an odd run before n or r), as in HEADER_LINE; a raw line break always does.
 * It reads only the value, so header lines that follow each other on one raw line cost their own length each.
 */
function valueEndAt(text, start, depth, ctx) {
  const d = depth || 1;
  let i = start;
  while (i < text.length) {
    const c = text[i];
    if (c === '\n' || c === '\r' || (depth > 0 && c === '"')) break;
    if (c !== '\\') {
      i++;
      continue;
    }
    const run = i;
    while (text[i] === '\\') i++;
    const escapes = (i - run) % (2 * d);
    if (((text[i] === 'n' || text[i] === 'r') && escapes === d) || (depth > 0 && text[i] === '"' && escapes < d)) {
      i = run;
      break;
    }
    if (text[i] === '\n' || text[i] === '\r') break;
    i++;
  }
  ctx.work += i - start;
  return Math.min(i, text.length);
}

/** Whether a character can be in a JWT part (base64url). */
const isTokenChar = c => c !== undefined && /[A-Za-z0-9_-]/.test(c);

/** Where the run of token characters from `start` ends. */
const runEnd = (text, start) => {
  let i = start;
  while (i < text.length && isTokenChar(text[i])) i++;
  return i;
};

/**
 * Where the first eyJ at a word start (or right after a JSON escape such as \n) in the run [start, end) is, or
 * -1. Only the run is read, and it is charged to the scan's work.
 */
function jwtStart(text, start, end, ctx) {
  for (let j = start; j + 3 <= end; j++) {
    if (text[j] !== 'e' || text[j + 1] !== 'y' || text[j + 2] !== 'J') continue;
    const before = text[j - 1];
    if (j === 0 || !/\w/.test(before) || (text[j - 2] === '\\' && 'nrtbf'.includes(before))) {
      ctx.work += j - start;
      return j;
    }
  }
  ctx.work += end - start;
  return -1;
}

/**
 * A quote as some escape level spells it: a run of backslashes, each also spelled \ by the level above, then a
 * quote or a " escape, as Redactor's ANY_QUOTE reads it (#339, Codex round 5).
 */
const ANY_QUOTE = String.raw`(?:\\|(?<=\\)u005[cC])*(?:"|(?<=\\)u0022)`;

/**
 * From just after a name's opening quote: the name, its closing quote spelled any way, whitespace written plainly or
 * escaped at any level, and the colon, which may be a : escape (Redactor's ANY_SECRET_NAME).
 */
const SECRET_NAME_REST = new RegExp(String.raw`((?:[A-Za-z_-]|\\+u[0-9A-Fa-f]{4}){1,64}?)(${ANY_QUOTE})`
  + String.raw`(?:\s|(?:\\|u005[cC])+(?:[nrt]|u00(?:20|09|0[aAdD])))*(?::|(?:\\(?!u003[aA])|u005[cC])*\\u003[aA])`, 'y');

/** A name with each \u escape decoded, however many backslashes come before it, as Redactor's decodeName reads it. */
const decodedEscapedName = name => name.replace(/\\+u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));

/** What a Decoder reads at the end of its level, and where its level is not JSON string content. */
const END = -1;
const BAD = -2;

/**
 * The text at one escape level, read from a position where every level above is inside a string: level 0 is the text,
 * each level the content of a JSON string of the level above, decoded; a quote of the level above ends it (Redactor's
 * Decoder).
 */
class Decoder {
  constructor(text, from, level) {
    this.text = text;
    this.outer = level === 0 ? null : new Decoder(text, from, level - 1);
    this.pos = from;
    this.peeked = null;
    this.peekedAt = 0;
    this.ended = false;
  }

  at() {
    if (this.peeked !== null) return this.peekedAt;
    return this.outer === null ? this.pos : this.outer.at();
  }

  peek() {
    if (this.peeked === null) {
      this.peekedAt = this.at();
      this.peeked = this.read();
      if (this.peeked === END) this.ended = true;
    }
    return this.peeked;
  }

  next() {
    const c = this.peek();
    if (c >= 0) this.peeked = null;
    return c;
  }

  read() {
    if (this.outer === null) return this.pos < this.text.length ? this.text.charCodeAt(this.pos++) : END;
    const c = this.outer.next();
    if (c === 34 || c < 0) return c === 34 ? END : c;
    if (isRawControl(c)) return BAD;
    return c === 92 ? escapeAfterBackslash(this.outer) : c;
  }
}

/** A control character a JSON string may not hold raw; a tab, line feed or carriage return is let through, as in Redactor. */
const isRawControl = c => c >= 0 && c < 0x20 && c !== 9 && c !== 10 && c !== 13;

const SINGLE_ESCAPES = new Map([[34, 34], [92, 92], [47, 47], [98, 8], [102, 12], [110, 10], [114, 13], [116, 9]]);

/** The character the escape after a backslash in `d` stands for, or BAD. */
function escapeAfterBackslash(d) {
  const e = d.next();
  if (SINGLE_ESCAPES.has(e)) return SINGLE_ESCAPES.get(e);
  if (e !== 117) return BAD;
  let code = 0;
  for (let i = 0; i < 4; i++) {
    const h = d.next();
    const digit = h < 0 ? -1 : Number.parseInt(String.fromCharCode(h), 16);
    if (Number.isNaN(digit) || digit < 0) return BAD;
    code = code * 16 + digit;
  }
  return code;
}

const skipJsonSpace = d => {
  for (let c = d.peek(); c === 32 || c === 9 || c === 10 || c === 13; c = d.peek()) d.next();
};

/** Reads a JSON string from `d` at its opening quote: whether it is whole; its place goes to `strings`, if given. */
function readStrictString(d, strings) {
  const open = d.at();
  d.next();
  const content = d.at();
  for (;;) {
    const close = d.at();
    const c = d.next();
    if (c === 34) {
      if (strings) strings.push([open, content, close, d.at()]);
      return true;
    }
    if (c < 0 || isRawControl(c) || (c === 92 && escapeAfterBackslash(d) === BAD)) return false;
  }
}

function readStrictScalar(d) {
  const c = d.peek();
  if (c === 116 || c === 102 || c === 110) {
    for (const ch of c === 116 ? 'true' : c === 102 ? 'false' : 'null') if (d.next() !== ch.charCodeAt(0)) return false;
    return true;
  }
  const digits = () => {
    let any = false;
    while (d.peek() >= 48 && d.peek() <= 57) {
      d.next();
      any = true;
    }
    return any;
  };
  if (c === 45) d.next();
  if (d.peek() === 48) d.next();
  else if (!digits()) return false;
  if (d.peek() === 46) {
    d.next();
    if (!digits()) return false;
  }
  if (d.peek() === 101 || d.peek() === 69) {
    d.next();
    if (d.peek() === 43 || d.peek() === 45) d.next();
    return digits();
  }
  return true;
}

const readStrictName = (d, strings) => {
  skipJsonSpace(d);
  if (d.peek() !== 34 || !readStrictString(d, strings)) return false;
  skipJsonSpace(d);
  return d.next() === 58;
};

/** Reads one JSON value from `d`, strictly, with a stack of open brackets instead of recursion (Redactor's readValue). */
function readStrictValue(d, strings) {
  const open = [];
  let value = true;
  for (;;) {
    skipJsonSpace(d);
    if (value) {
      const c = d.peek();
      if (c === 123 || c === 91) {
        d.next();
        skipJsonSpace(d);
        if (d.peek() === (c === 123 ? 125 : 93)) {
          d.next();
        } else {
          open.push(c);
          if (c === 123 && !readStrictName(d, strings)) return false;
          continue;
        }
      } else if (c === 34 ? !readStrictString(d, strings) : !readStrictScalar(d)) {
        return false;
      }
      value = false;
      continue;
    }
    if (open.length === 0) return true;
    const top = open[open.length - 1];
    const c = d.next();
    if (c === 44) {
      value = true;
      if (top === 123 && !readStrictName(d, strings)) return false;
    } else if (c === (top === 123 ? 125 : 93)) {
      open.pop();
    } else {
      return false;
    }
  }
}

/** The escape level at which `spelling` is one quote, or -1 (Redactor's quoteLevel). */
function quoteLevelOf(spelling) {
  let s = spelling;
  for (let level = 0; level <= MAX_LEVELS - 1 && s !== null; level++) {
    if (s === '"') return level;
    const d = new Decoder(`${s}"`, 0, 1);
    let out = '';
    for (let c = d.next(); c !== END; c = d.next()) {
      if (c === BAD) {
        out = null;
        break;
      }
      out += String.fromCharCode(c);
    }
    s = out !== null && d.at() === s.length ? out : null;
  }
  return -1;
}

/**
 * The value of a name when the strict reading of the name's level consumes it, or null: both quotes are quotes of one
 * level, the name a whole string there, then a colon, a whole value and the rest of its object (Redactor's
 * consumedValueEnd). Gives where the value ends, and whether it is the mask Redactor leaves for a secret field
 * (isMaskedItem: an empty value or null is left to the other readings, as before).
 */
function strictValue(text, open, name, close, end, secretName, read = { end: 0 }, proven = new Map()) {
  const level = quoteLevelOf(text.slice(open, name));
  if (level < 0 || level !== quoteLevelOf(text.slice(close, end))) return null;
  const d = new Decoder(text, open, level);
  if (d.peek() !== 34 || !readStrictString(d, null) || d.at() !== end) return null;
  skipJsonSpace(d);
  if (d.next() !== 58) return null;
  skipJsonSpace(d);
  const first = d.peek();
  const strings = [];
  if (!readStrictValue(d, strings)) return null;
  const valueEnd = d.at();
  // Redactor's ProvenObjects: a span of this level already read as the valid rest of an object is not read again.
  const span = proven.get(level);
  if (!(span && span[0] <= valueEnd && valueEnd <= span[1])) {
    const rest = readRestOfObject(d);
    read.end = Math.max(read.end, d.at());
    if (!rest) return null;
    proven.set(level, [valueEnd, d.at()]);
  }
  let masked = false;
  if (first === 34 && strings.length === 1) {
    // The string's content, read as the content of a string of this level: it ends at the string's closing quote.
    const content = new Decoder(text, strings[0][1], level + 1);
    let value = '';
    for (let c = content.next(); c >= 0; c = content.next()) value += String.fromCharCode(c);
    masked = isMaskedItem(secretName, value);
  }
  return { end: valueEnd, masked };
}

/**
 * Reads the rest of the object a member's value was read in: whether it is valid JSON up to the object's close bracket,
 * or up to the end of the text, as in a cut body (Redactor's readRestOfObject).
 */
function readRestOfObject(d) {
  const atTextEnd = () => d.ended && d.at() >= d.text.length;
  for (;;) {
    skipJsonSpace(d);
    const c = d.next();
    if (c === 125 || c === END) return c === 125 || atTextEnd();
    if (c !== 44 || !readStrictName(d, null) || !readStrictValue(d, null)) return atTextEnd();
  }
}

/**
 * Where the text's strings are certain: in the JSON value the text starts with, when it is valid, and, level by level,
 * inside each such string whose content is valid JSON too (Redactor's Certainty). maskEnd gives where Redactor's mask of
 * a candidate ends, or -1 when it leaves the candidate to its other passes.
 */
class Certainty {
  constructor(text, ctx) {
    this.text = text;
    this.ctx = ctx;
    this.inside = new Map();
    const strings = [];
    const d = new Decoder(text, 0, 0);
    const valid = readStrictValue(d, strings);
    ctx.work += text.length;
    this.top = valid ? strings : null;
    this.certainEnd = valid ? d.at() : 0;
  }

  /**
   * For a candidate from `open` to `end` the strict reading does not read: where its mask may end, or null when Redactor
   * leaves it alone. Redactor ends it at the end of the outermost string holding it, or of the text; a report or bundle
   * that quotes Redactor's output in a string of its own holds that string one level down, so the end of any string
   * holding the candidate at a level that is certain is accepted: nothing past it can be the value's.
   */
  maskEnds(open, end) {
    if (this.top === null || open >= this.certainEnd) return [this.text.length];
    let strings = this.top;
    const ends = [];
    for (let level = 1; ; level++) {
      const holder = Certainty.holding(strings, open, end);
      if (holder === null) return null;
      ends.push(holder[2]);
      strings = level >= MAX_LEVELS ? null : this.stringsInside(holder, level);
      if (strings === null) return ends;
    }
  }

  static holding(strings, from, to) {
    let low = 0;
    let high = strings.length - 1;
    let found = null;
    while (low <= high) {
      const mid = (low + high) >>> 1;
      if (strings[mid][1] <= from) {
        found = strings[mid];
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return found !== null && to <= found[2] ? found : null;
  }

  stringsInside(string, level) {
    if (!this.inside.has(string[0])) {
      const strings = [];
      const d = new Decoder(this.text, string[1], level);
      const valid = readStrictValue(d, strings);
      skipJsonSpace(d);
      this.ctx.work += string[2] - string[1];
      this.inside.set(string[0], valid && d.peek() === END && d.at() === string[2] ? strings : null);
    }
    return this.inside.get(string[0]);
  }
}

/** The next " escape's u in `text` from `from`, or -1. */
const unicodeQuoteAt = (text, from) => {
  for (let i = text.indexOf('u0022', from); i >= 0; i = text.indexOf('u0022', i + 1)) if (i > 0 && text[i - 1] === '\\') return i;
  return -1;
};

/** Where the quote whose " or u0022 is at `quote` starts: its whole run of backslashes, each also \. */
const quoteRunStartAt = (text, quote) => {
  let i = quote;
  for (;;) {
    if (i > 0 && text[i - 1] === '\\') i--;
    else if (i >= 6 && text[i - 6] === '\\' && text.slice(i - 5, i).toLowerCase() === 'u005c') i -= 6;
    else return i;
  }
};

/**
 * Redactor's fail-closed rule (#339, Codex round 5): a secret name, with its quotes spelled any way at any level, whose
 * value no strict reading of its own level consumes is masked from just after its colon to the end of the outermost
 * string holding it, or to the end of the text when no valid JSON around it says where that is, quoted with the name's
 * closing quote. The scanner uses the same trigger: such a name flags unless exactly that mask follows its colon, up to
 * the end of a string holding it at a certain level (maskEnds) or of the text.
 */
function unconsumedSecretNames(text, ctx) {
  let certainty = null;
  const proven = new Map();
  let skipTo = 0;
  let plain = text.indexOf('"');
  let unicode = unicodeQuoteAt(text, 0);
  while (plain >= 0 || unicode >= 0) {
    const isPlain = unicode < 0 || (plain >= 0 && plain < unicode);
    const quote = isPlain ? plain : unicode;
    const name = quote + (isPlain ? 1 : 5);
    if (isPlain) plain = text.indexOf('"', quote + 1);
    else unicode = unicodeQuoteAt(text, quote + 1);
    if (name >= text.length || !/[A-Za-z_\\-]/.test(text[name])) continue;
    const open = quoteRunStartAt(text, quote);
    if (open < skipTo) continue;
    SECRET_NAME_REST.lastIndex = name;
    const m = SECRET_NAME_REST.exec(text);
    if (m === null || !isSecretKey(decodedEscapedName(m[1]))) continue;
    const close = name + m[1].length;
    const read = { end: close + m[2].length };
    const value = strictValue(text, open, name, close, close + m[2].length, decodedEscapedName(m[1]), read, proven);
    ctx.work += Math.max(read.end, value?.end ?? 0) - open;
    if (value !== null) {
      // A value the strict reading of the name's level consumes and finds masked is judged there:
      // the looser readings, which may read the name's quotes at two levels, leave that name alone.
      // Any other value is left to them, as before.
      if (value.masked) ctx.strictNames.add(name);
      skipTo = Math.max(skipTo, value.end);
      continue;
    }
    certainty ??= new Certainty(text, ctx);
    const ends = certainty.maskEnds(open, close + m[2].length);
    if (ends === null) continue;
    const colon = name + m[0].length;
    const mask = m[2] + MASK + m[2];
    if (text.startsWith(mask, colon) && ends.includes(colon + mask.length)) {
      skipTo = colon + mask.length;
    } else {
      ctx.leaks.push({ check: 'secret field no strict reading reads', match: text.slice(open, open + 80) });
      skipTo = ends[0];
    }
  }
}

/**
 * Checks over raw text: a regex whose `ok(match)` returning true means the hit is a masked or harmless value, or
 * a `scan(text, ctx)` that reads the text procedurally, in linear work, and records its own leaks.
 */
const TEXT_CHECKS = [
  // Redactor masks a secret field no strict reading of its level reads from its colon to the end of the outermost
  // string, or of the text (#339, Codex round 5); anything else after such a name's colon is a leak.
  { name: 'secret field no strict reading reads', scan: unconsumedSecretNames },
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // The credential, which may be URL-encoded, runs to the next whitespace, quote, comma, semicolon or
  // backslash, as in Redactor; a JSON escape of a token character (\/, \u002B) is that character, not a
  // backslash, also escaped again (\\/) in a recorded body (#211), and a JSON escape of whitespace after the
  // scheme (\t, \n) is a separator (#212).
  // As in Redactor, a credential is consumed and the search goes on after it, and a match kept as prose is
  // read again from after its scheme, so it does not hide a scheme right after it (token DPoP <credential>).
  {
    name: 'Bearer/Basic credential',
    scan: (text, ctx) => {
      const word = new RegExp(String.raw`${AUTH_START}(?:Bearer|Basic|Token|DPoP)`, 'gi');
      const credential = new RegExp(AUTH_SCHEME, 'iy');
      for (let m = word.exec(text); m !== null; m = word.exec(text)) {
        credential.lastIndex = m.index;
        const c = credential.exec(text);
        if (c === null) continue;
        ctx.work += c[0].length;
        if (isAuthProse(c)) continue;
        ctx.leaks.push({ check: 'Bearer/Basic credential', match: c[0].slice(0, 80) });
        word.lastIndex = c.index + c[0].length;
      }
    },
  },
  // Redactor masks the credential through to that end, so anything right after the mask is the rest
  // of it (Bearer [REDACTED]:SECRETPART, Bearer [REDACTED]\/PART, Bearer [REDACTED]\u002BPART).
  { name: 'Bearer/Basic credential cut short', re: new RegExp(String.raw`${AUTH_START}(?:Bearer|Basic|Token|DPoP)${AUTH_SEPARATOR}\[REDACTED\](?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})`, 'gi') },
  // Redactor keeps a JWT's header and claims and masks the signature.
  // Each run of token characters is read once: it is a JWT's header from its first eyJ at a word start when two
  // dots follow it with a signature after the second (eyJ-eyJ-... is not retried at each eyJ, as in #310).
  { name: 'signed JWT', scan: (text, ctx) => {
    let i = 0;
    while (i < text.length) {
      if (!isTokenChar(text[i])) {
        i++;
        continue;
      }
      const end = runEnd(text, i);
      ctx.work += end - i;
      if (text[end] === '.') {
        const claims = runEnd(text, end + 1);
        if (text[claims] === '.' && runEnd(text, claims + 1) > claims + 1 && jwtStart(text, i, end, ctx) >= 0) {
          ctx.leaks.push({ check: 'signed JWT', match: text.slice(i, Math.min(claims + 40, i + 80)) });
        }
      }
      i = end;
    }
  } },
  // The value runs to the next &, whitespace or quote, past any backslash.
  { name: 'form secret', re: new RegExp(String.raw`${WORD_START}(${FORM_SECRET_KEYS})=([^&\s"]*)`, 'gi'), ok: m => isMaskedFormValue(m[2]) },
  // A sensitive header line (Cookie: sid=...) where a line starts, also after an escaped line break in a
  // JSON string, as in Redactor. Redactor masks the value to the end of the line, so only an escaped line
  // break or the closing quote of a JSON string may follow the mask; an Authorization line it keeps as
  // prose is not flagged.
  {
    name: 'sensitive header line',
    // The match ends at the name and valueEndAt reads the value from there, so a header line on the next
    // escaped line is scanned on its own.
    // An escaped tab may indent the line or follow the colon, as in Redactor's ESCAPED_HEADER_LINE.
    // A JSON string's start is a line start too: Redactor saw the body before it was serialized.
    scan: (text, ctx) => {
      const re = new RegExp(String.raw`(?:^|(?<=\\[nr])|(?<=[:\[,]\s*\\*"))(?:[ \t]|\\+t)*(${[...SENSITIVE_HEADERS].join('|')}):(?:[ \t]|\\+t)*`, 'gim');
      for (const m of text.matchAll(re)) {
        const start = m.index + m[0].length;
        const v = text.slice(start, valueEndAt(text, start, lineDepth(text, m.index), ctx));
        if (!(v.trim() === '' || isMaskedValue(m[1], v) || isAuthLineProse(m[1], v))) {
          ctx.leaks.push({ check: 'sensitive header line', match: m[0].slice(0, 80) });
        }
      }
    },
  },
];

/** A JSON string's raw control characters escaped, so JSON.parse reads a string a serializer would have escaped. */
const escapeControls = body => body.replace(/[\u0000-\u001f]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

/**
 * Where the first quote no backslash escapes is in `text`, or -1: JSON.parse reads no string's content past it. Charges
 * the characters read to the scan's work.
 */
const firstBareQuote = (text, ctx) => {
  let backslashes = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"' && backslashes % 2 === 0) {
      ctx.work += i + 1;
      return i;
    }
    backslashes = text[i] === '\\' ? backslashes + 1 : 0;
  }
  ctx.work += text.length;
  return -1;
};

/**
 * The text `body` holds read as a string's content, as JSON.parse reads it. When it is not one, as when quoted prose
 * follows text copied from inside a string twice over (Codex narrow check at 3c47acc), it is the unicode escapes
 * outside its quoted strings decoded, as Redactor's normalized view decodes them, so the names its JWK search reads
 * there are counted. The quoted strings JSON reads are left out, as scanJson reads them where they are; one it cannot
 * read (a stray quote before an escape JSON has not, such as \') is decoded as the text around it is. An escape that
 * is not a unicode one is kept. With no such escape to decode, `body` itself is returned: there is no other view.
 * Returns the decoded text, a function from an index in it to where that character starts in `body`, and `unread`:
 * the spans [from, to) of the strings it left out that no literal scanJson decoded in `body` (`read`) holds, which
 * nothing else decodes, and the content of each such string as a whole, with that content decoded (readUnread). A
 * quote no backslash escapes means JSON.parse cannot read `body`, so the scan reads only up to it to know.
 */
const decodeString = (body, ctx, read = []) => {
  const quote = firstBareQuote(body, ctx);
  if (quote < 0) {
    ctx.work += body.length;
    try {
      const decoded = JSON.parse(`"${escapeControls(body)}"`);
      return { decoded, at: sourceOffsets(body, ctx, decoded.length), unread: [] };
    } catch { /* not the content of a string: its unicode escapes outside strings are decoded below */ }
  }
  ctx.work += body.length;
  const parts = [];
  const offsets = [];
  let decodedAny = false;
  // Decodes the unicode escapes of body from `from` to `to`, keeping any other escape whole.
  const decodeSpan = (from, to) => {
    for (let i = from; i < to;) {
      offsets.push(i);
      const hex = body[i] === '\\' && body[i + 1] === 'u' && i + 6 <= to ? body.slice(i + 2, i + 6) : '';
      if (/^[0-9a-fA-F]{4}$/.test(hex)) {
        parts.push(String.fromCharCode(Number.parseInt(hex, 16)));
        decodedAny = true;
        i += 6;
      } else if (body[i] === '\\' && i + 1 < to) {
        // Any other escape, an escaped backslash among them, is kept whole: the u after one starts no escape.
        parts.push(body[i], body[i + 1]);
        offsets.push(i + 1);
        i += 2;
      } else {
        parts.push(body[i++]);
      }
    }
  };
  const leftOut = [];
  const gaps = [];
  let afterLineBreak = false;
  let from = 0;
  for (let i = 0; i < body.length;) {
    if (body[i] === '\\') {
      i += 2;
      continue;
    }
    if (body[i] !== '"') {
      i++;
      continue;
    }
    decodeSpan(from, i);
    if (afterLineBreak) gaps.push([from, i]);
    // A quoted string, to its closing quote or the end of the text; a backslash takes the next character with it.
    let end = i + 1;
    while (end < body.length && body[end] !== '"') end += body[end] === '\\' ? 2 : 1;
    const content = body.slice(i + 1, Math.min(end, body.length));
    ctx.work += content.length;
    afterLineBreak ||= content.includes('\n') || content.includes('\r');
    try {
      // A string the end of the text cuts off may end in half an escape, which is dropped (withoutPartialEscape).
      const decodedContent = JSON.parse(`"${escapeControls(end >= body.length ? withoutPartialEscape(content) : content)}"`);
      // scanJson decodes a string JSON reads, where it is: unless it read the string otherwise (unread).
      leftOut.push([i, Math.min(end + 1, body.length), Math.min(end, body.length), decodedContent]);
    } catch {
      // A string JSON cannot read (a stray quote before an escape JSON has not) is decoded as the text around it is.
      decodeSpan(i + 1, Math.min(end, body.length));
    }
    i = end + 1;
    from = Math.min(i, body.length);
  }
  decodeSpan(from, body.length);
  if (afterLineBreak) gaps.push([from, body.length]);
  ctx.work += read.length + leftOut.length;
  const unread = unreadSpans(leftOut, read);
  // The text between strings after one paired across a raw line break, where it holds a backslash: scanJson and
  // Redactor cut that string at the line break, so from there their quotes paired otherwise, and a copy may be in no
  // string here, where decodeSpan keeps its escapes: after two stray quotes and line breaks (automated review on
  // 5173e8e), or after "<line break>","body": with every quote of the copy escaped (automated review on 4175db6). The
  // spans do not overlap, and a copy is read once here rather than also from each line break (automated review on
  // 5ca573a: that read the copy twice per level and spent the budget at depth 3).
  for (const [from, to] of gaps) {
    if (to - from > 1 && body.slice(from, to).includes('\\')) unread.push([from, to]);
  }
  if (!decodedAny) return { decoded: body, at: sourceOffsets(body, ctx, body.length), unread };
  return { decoded: parts.join(''), at: j => (j < offsets.length ? offsets[j] : body.length), unread };
};

/**
 * The parts of the strings `leftOut` ([from, to) with their quotes, and where the content ends) that none of the spans
 * `read` holds, in a text of length `n`: where decodeString left out a string that scanJson read otherwise. scanJson
 * ends a string that is no member's value at a raw line break, and reads the text after it as bare text, which it does
 * not decode (#342). Such a string's content is returned whole too: scanJson may have read part of it as a literal of
 * its own (from a copied \" on), so neither the literal nor the parts around it hold an object that spans both, as a
 * JWK whose kty is quoted with \u0022 and whose k with \" (automated review on 925a782). A whole content carries the
 * decoded text decodeString parsed it to, so it is not parsed twice. The spans read are merged in order rather than
 * marked character by character, so the work is in the number of spans, not the length of the text.
 */
const unreadSpans = (leftOut, read) => {
  if (leftOut.length === 0) return [];
  // The spans read, merged in order. leftOut is in order and its strings do not overlap.
  const merged = [];
  for (const [from, to] of [...read].sort((a, b) => a[0] - b[0])) {
    const last = merged[merged.length - 1];
    if (last && from <= last[1]) last[1] = Math.max(last[1], to);
    else if (from < to) merged.push([from, to]);
  }
  const spans = [];
  let r = 0;
  for (const [from, to, contentEnd, content] of leftOut) {
    const parts = spans.length;
    while (r < merged.length && merged[r][1] <= from) r++;
    let i = from;
    for (let k = r; k < merged.length && merged[k][0] < to; k++) {
      if (merged[k][0] > i) spans.push([i, merged[k][0]]);
      i = Math.max(i, merged[k][1]);
    }
    if (i < to) spans.push([i, to]);
    if (spans.length > parts) spans.push([from + 1, contentEnd, true, content]);
  }
  return spans;
};

/**
 * How a view was reached. MAIN: a view main reads, read as main reads it: a kty member in an object scanJson parses
 * makes it a JWK. UNREAD: a view only readUnread reaches (#342), or one below such a view, and WHOLE: a string's whole
 * content readUnread reads. In both, which objects are JWKs and which members are theirs is decided as Redactor's JWK
 * search decides it (jwkLeaks): such views hold text main never read, often malformed by the decoding that reached it,
 * where scanJson's own pairing of quotes and members differed from Redactor's both ways (automated reviews on c4ffeef,
 * 39dd7ff, 0ab5aeb, 380cf7c, 9a3e247, fa4fd1d, 223512b and 65e1e7f). WHOLE differs from UNREAD only in which views
 * cover which (readNested): a view read in a mode before covers it.
 */
const MAIN = 0;
const UNREAD = 1;
const WHOLE = 2;
/**
 * FLAT: the copy of a MAIN view readFlattened reads, with its quotes spelled \u0022 by one backslash written as
 * quotes. It is read in place only, for secret-named fields only: the strings it holds and the loose decodes of its
 * text are the views of the MAIN view it was copied from, and the JWKs are judged where Redactor's JWK search finds
 * them. A value there that opens with a quote spelled \u0022 behind more backslashes, a quote of a deeper level, is left
 * to the deeper view that reads it. So a FLAT copy only adds to what the other views flag, and each MAIN view adds
 * one read of its own length (#339).
 */
const FLAT = 3;

/** A \u escape without four hex digits after it, with an even run of backslashes before it (kept, as group 1). */
const MALFORMED_UNICODE = /(?<!\\)((?:\\\\)*)\\u(?![0-9A-Fa-f]{4})/g;

/**
 * `body` without half an escape at its end, as Redactor leaves a cut: an odd run of backslashes, then a \u with fewer
 * than four hex digits (and nothing after them). Every malformed \u left (\uZ, \u00G) loses its backslash, so JSON
 * reads the copy and keeps the text after the escape, which may be the end of a secret value (automated reviews on
 * 92f3ad6 and 058e89a). decodeLiteral repairs a cut literal the same way, so both read one copy (automated review on
 * c5a0b7f: when they differed, each level of a nest was read twice).
 */
const withoutPartialEscape = body => {
  let out = body;
  if (backslashesBefore(out, out.length) % 2 === 1) out = out.slice(0, -1);
  const partial = halfEscapeAt(out);
  if (partial >= 0) out = out.slice(0, partial);
  return out.includes('\\u') ? out.replace(MALFORMED_UNICODE, '$1u') : out;
};

/**
 * Where half a \u escape (a \u with zero to three hex digits, an even run of backslashes before it) ends `body`, before
 * any lone backslash after it, or -1. Cutting it loses bytes of whatever value is still open there, which Redactor masks
 * with the rest of that value and closes, so a value open at the end of a view such a cut made is judged unmasked
 * (Codex security round 2 at 8a06f7e: \\u005 cut off left the bare mask, which the scanner accepted).
 */
const halfEscapeAt = body => {
  const end = backslashesBefore(body, body.length) % 2 === 1 ? body.length - 1 : body.length;
  const from = Math.max(0, end - 5);
  const partial = /\\u[0-9A-Fa-f]{0,3}$/.exec(body.slice(from, end));
  return partial !== null && backslashesBefore(body, from + partial.index) % 2 === 0 ? from + partial.index : -1;
};

/**
 * sourceOffsets for the text JSON read in place of `span`, withoutPartialEscape(span): where each decoded character
 * starts in `span` itself. A repair that only cut the end keeps every index; one that removed a backslash before it
 * shifts those after it, so a walk of both texts maps each kept character back, built on the first look-up only
 * (automated review on a7d0f8f: every index past a repaired escape pointed one character off, and the check of a \f
 * escape read the wrong character; on c5a0b7f: building it for every view spent the scan budget).
 */
const repairedOffsets = (span, ctx, length) => {
  const repaired = withoutPartialEscape(span);
  if (repaired === span || span.startsWith(repaired)) return sourceOffsets(repaired, ctx, length);
  const at = sourceOffsets(repaired, ctx, length);
  let kept = null;
  return j => {
    if (kept === null) {
      ctx.work += span.length;
      kept = new Int32Array(repaired.length + 1);
      for (let i = 0, k = 0; i < span.length && k < repaired.length; i++) {
        if (span[i] === repaired[k]) kept[k++] = i;
      }
      kept[repaired.length] = span.length;
    }
    const r = at(j);
    return r < repaired.length ? kept[r] : span.length;
  };
};

/**
 * Reads the spans of `text` that decodeString left out and scanJson did not decode (`unread`), each as the content of
 * one more string, one level down: decoded whole if JSON reads it as one, else its unicode escapes. A string's whole
 * content is read as such (WHOLE); every other span, as a view main does not read (UNREAD).
 */
function readUnread(text, unread, level, ctx, toRoot, cut = false) {
  for (const [from, to, whole = false, content] of unread) {
    const span = text.slice(from, to);
    if (!span.includes('\\')) continue;
    let decoded;
    let at;
    if (whole) {
      // decodeString decoded a string's whole content already.
      decoded = content;
      at = repairedOffsets(span, ctx, decoded.length);
      const wholeCut = to >= text.length && (cut || halfEscapeAt(span) >= 0);
      if (decoded !== span) readNested(decoded, level, ctx, j => toRoot(from + at(j)), WHOLE, wholeCut ? cutOf(span, decoded) : 0);
      continue;
    }
    ctx.work += span.length;
    // A view that ends where this one was cut, or one that cut half an escape off its own end, ends inside whatever
    // value is open there.
    let spanCut = cut && to >= text.length;
    try {
      // A span cut off at the end of the text may end in half an escape (a lone backslash, or a \u with fewer than four
      // hex digits), which Redactor's parser stops at and JSON cannot read: it is dropped (automated review on 5ca573a).
      decoded = JSON.parse(`"${escapeControls(withoutPartialEscape(span))}"`);
      at = repairedOffsets(span, ctx, decoded.length);
      spanCut ||= halfEscapeAt(span) >= 0;
    } catch {
      const parts = [];
      const offsets = [];
      for (let i = 0; i < span.length;) {
        offsets.push(i);
        const hex = span[i] === '\\' && span[i + 1] === 'u' ? span.slice(i + 2, i + 6) : '';
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          parts.push(String.fromCharCode(Number.parseInt(hex, 16)));
          i += 6;
        } else {
          parts.push(span[i++]);
        }
      }
      decoded = parts.join('');
      at = j => (j < offsets.length ? offsets[j] : span.length);
    }
    if (decoded !== span) readNested(decoded, level, ctx, j => toRoot(from + at(j)), UNREAD, spanCut ? cutOf(span, decoded) : 0);
  }
}

/**
 * The JSON string literal whose opening quote is at `start`: where it ends (its closing quote, or the end of
 * the text or of a line, for a string cut off there, as Redactor writes a truncated body) and its content. A
 * backslash always takes the next character with it, so no run of backslashes is counted. A raw line break
 * inside it means the quote opens no JSON string: then only where that line break is ({aborted, end}). A
 * member's value (`value`) is read through raw line breaks to its closing quote, or to the end of the text, as
 * Redactor reads and masks it, so no part of it goes unjudged.
 */
function readLiteral(text, start, ctx, value = false) {
  let i = start + 1;
  let terminated = false;
  let escaped = false;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      terminated = true;
      break;
    }
    if ((c === '\n' || c === '\r') && !value) {
      ctx.work += i - start;
      return { aborted: true, start, end: i, terminated: false, escaped, body: text.slice(start + 1, i) };
    }
    if (c === '\\') {
      escaped = true;
      // A backslash before a line break: a value cut there, before a note appended to the cut body.
      if (!value && (text[i + 1] === '\n' || text[i + 1] === '\r')) {
        i++;
        break;
      }
      i += 2;
    } else {
      i++;
    }
  }
  const end = Math.min(i, text.length);
  ctx.work += end - start + 1;
  return { start, end, terminated, escaped, body: text.slice(start + 1, end) };
}

/**
 * A literal's content decoded with JSON.parse, or null if it does not decode. A string cut off by the end of
 * the text may end in half an escape, which is dropped first, as Redactor leaves such a cut. A malformed last \u
 * within six characters of the end (\uZ, \u00G) loses only its backslash, as the loose decode repairs the same
 * string: so both read one copy (automated review on c5a0b7f), and the text after it, which may end a secret value,
 * is kept (automated review on 058e89a). Any other malformed escape leaves the literal undecodable, which fails closed.
 */
function decodeLiteral(literal, ctx) {
  let body = literal.body;
  // With no backslash (readLiteral saw none) and no quote, JSON.parse would return the content as it is.
  if (!literal.escaped) return body;
  if (!literal.terminated) {
    if (backslashesBefore(body, body.length) % 2 === 1) body = body.slice(0, -1);
    const partial = body.lastIndexOf('\\u');
    if (partial >= 0 && partial > body.length - 6 && backslashesBefore(body, partial) % 2 === 0
        && !/^[0-9A-Fa-f]{4}/.test(body.slice(partial + 2))) {
      // Half an escape cut off loses bytes of the value open there (halfEscapeAt): the literal is judged unmasked.
      literal.cutEscape = /^[0-9A-Fa-f]{0,3}$/.test(body.slice(partial + 2));
      body = literal.cutEscape ? body.slice(0, partial) : body.slice(0, partial) + body.slice(partial + 1);
    }
  }
  ctx.work += body.length;
  try {
    return JSON.parse(`"${escapeControls(body)}"`);
  } catch {
    return null;
  }
}

/** Records a leak the scan found, or a reason it could not read on (failing closed). */
const failClosed = (ctx, check, text) => ctx.leaks.push({ check, match: text.slice(0, 80) });

/**
 * Judges the members a JSON object (or array, or the text around any) held, once it closes or the text ends:
 * a secret-named field's value must be what Redactor leaves for it, and in an object with its own kty member,
 * so must a private member's. Each member is judged, a repeated one too. An unmasked private member in no such
 * object is kept for textLeaks, which flags it if Redactor's JWK search may spend its budget on the text. With
 * `secretOnly` (a FLAT copy, read for secret-named fields only), private members are not judged: the views that
 * read JWKs judge them as Redactor's JWK search finds them (#339).
 */
function judge(owner, ctx, secretOnly = false) {
  for (const value of owner.values) {
    if (isSecretKey(value.name)) {
      const masked = value.kind === 'string' ? value.value !== null && isMaskedValue(value.name, value.value) && !value.cutShort
        : value.kind === 'scalar' ? value.value === 'null'
          : value.kind === 'array' && !value.nested && value.items.every(item => isMaskedItem(value.name, item));
      if (!masked) failClosed(ctx, value.kind === 'object' || value.kind === 'array' ? 'JSON secret structure' : 'JSON secret field', value.text);
    } else if (!secretOnly && isPrivateName(value.name, value.malformed)) {
      const masked = value.kind === 'string' ? (value.value === MASK || value.value === '') && !value.cutShort
        : value.kind === 'scalar' && value.value === 'null';
      const check = value.kind === 'object' || value.kind === 'array' ? 'JSON secret structure' : 'JSON secret field';
      if (masked) continue;
      if (owner.kty) failClosed(ctx, check, value.text);
      else ctx.unowned.push({ check, text: value.text });
    }
  }
}

/** Whether a character can follow a JSON string: what Redactor leaves after a mask, or a stray quote's sign. */
const endsValue = c => c === undefined || c === ',' || c === '}' || c === ']' || c === ':' || c === '\\' || c === '"'
  || c === ' ' || c === '\t' || c === '\n' || c === '\r';

/**
 * Whether a character ends a scalar token: a delimiter, or a quote or open bracket, where scanning resumes, so
 * malformed JSON after a scalar ({"x":0"password":...}) is read as the members it holds.
 */
const endsScalar = c => isSpace(c) || c === ',' || c === '}' || c === ']' || c === '"' || c === '{' || c === '[';

/** Whether a character is JSON whitespace. */
const isSpace = c => c === ' ' || c === '\t' || c === '\n' || c === '\r';

/** A quote spelled \u0022 (either hex case) by one backslash: no backslash before it escapes that one. */
const LONE_UNICODE_QUOTE = /(?<!\\)\\u0022/gi;

/** A quote spelled \u0022 behind backslashes, where a value opens in a FLAT copy: a quote of a deeper level. */
const BACKSLASHED_UNICODE_QUOTE = /^\\+u0022/i;

/** A mask with an Authorization-style value's scheme kept in front of it, as isMaskedValue accepts one. */
const SCHEME_MASK = new RegExp(`^${SCHEME} \\[REDACTED\\]`);

/**
 * Whether the value text from `i` is a value of the member `name` as Redactor masks it: the mask, or, for an
 * Authorization-style name, a scheme and the mask (Bearer [REDACTED]), then its closing quote if it has one, and then
 * what can follow a value: a separator before a quote (plain, or escaped as \" or \u0022) or bracket, a quote, a
 * bracket, or the end. A bare word after it ("[REDACTED]\u0022,TAIL\u0022) is part of the value the mask stops short
 * of (review on 92c40cb), and so is any other escape (,\u0054AIL, review on 0e14a36).
 */
const opensMask = (name, text, i) => {
  let p = text.startsWith(MASK, i) ? i + MASK.length : -1;
  if (p < 0 && /authorization$/i.test(name)) {
    const scheme = SCHEME_MASK.exec(text.slice(i, i + 80));
    if (scheme) p = i + scheme[0].length;
  }
  if (p < 0) return false;
  if (/^\\u0022/i.test(text.slice(p, p + 6))) p += 6;
  else if (text[p] === '"') p++;
  while (p < text.length && isSpace(text[p])) p++;
  if (text[p] === ',') {
    p++;
    while (p < text.length && isSpace(text[p])) p++;
  }
  // A backslash may follow only as a quote escape, the next member's: any other escape (,\u0054AIL) is more of the
  // value (review on 0e14a36).
  const quoteEscape = text[p] === '\\' && (text[p + 1] === '"' || /^\\u0022/i.test(text.slice(p, p + 6)));
  return p >= text.length || text[p] === '"' || quoteEscape || text[p] === '}' || text[p] === ']';
};

/** Whether a quote spelled \u0022 by one backslash starts at index `i` of `text`. */
const opensLoneUnicodeQuote = (text, i) => text[i] === '\\' && (text[i + 1] === 'u' || text[i + 1] === 'U')
  ? /^\\u0022/i.test(text.slice(i, i + 6)) && backslashesBefore(text, i) === 0 : false;

/**
 * Reads `text`, a MAIN view, once more with each quote it spells \u0022 by one backslash written as a quote: the
 * plain view Redactor reaches by decoding that escape to \" and taking that level of escaping off, where it masks a
 * secret field whose name and value quotes are spelled differently ({"client_secret":\u0022...\u0022},
 * {\u0022client_secret\u0022:"..."}) (#339). A second copy keeps each \u0022 inside a plain-quoted string as the escape
 * it is there (keepingPlainStrings), so a value such as "pre\u0022TAIL" after a name quoted with it is judged whole
 * (review on 96428f9). The copies are views main does not read (FLAT), so they are never flattened again: each MAIN
 * view adds at most two reads of its own length.
 */
function readFlattened(text, level, ctx, toRoot, cut) {
  if (!text.includes('\\')) return;
  // matchAll copies lastIndex, so the test must leave it at 0.
  LONE_UNICODE_QUOTE.lastIndex = 0;
  const found = LONE_UNICODE_QUOTE.test(text);
  LONE_UNICODE_QUOTE.lastIndex = 0;
  if (!found) return;
  ctx.budget += text.length;
  ctx.work += text.length;
  const parts = [];
  const at = [];
  let from = 0;
  for (const m of text.matchAll(LONE_UNICODE_QUOTE)) {
    parts.push(text.slice(from, m.index), '"');
    for (let k = from; k <= m.index; k++) at.push(k);
    from = m.index + 6;
  }
  parts.push(text.slice(from));
  for (let k = from; k <= text.length; k++) at.push(k);
  const flat = parts.join('');
  readFlatCopy(flat, at, level, ctx, toRoot, cut);
  ctx.budget += text.length;
  ctx.work += text.length;
  const kept = keepingPlainStrings(text);
  if (kept.copy !== flat) readFlatCopy(kept.copy, kept.at, level, ctx, toRoot, cut);
}

/**
 * Reads a FLAT copy of a MAIN view (readFlattened), `at` mapping each of its characters to the view's. The copy is read
 * on top of what the other views may spend: the budget grows by what reading it spends, up to FLAT_ALLOWANCE times its
 * length, so text the other views read within the budget is not failed closed for the copy (review on 806a28c). Each
 * MAIN view has at most two copies, so the budget stays linear in the text.
 */
function readFlatCopy(copy, at, level, ctx, toRoot, cut) {
  const allowance = FLAT_ALLOWANCE * copy.length;
  ctx.budget += allowance;
  const before = ctx.work;
  readNested(copy, level, ctx, j => toRoot(at[Math.min(j, at.length - 1)]), FLAT, cut);
  ctx.budget -= Math.max(0, allowance - (ctx.work - before));
}

/**
 * `text` with each quote it spells \u0022 written as a quote, as readFlattened's first copy, except inside a string a
 * plain quote opens after a colon, a member's value: there a \u0022 is the string's own escape, and only a plain quote
 * closes it. Any other string, a name included, closes at the next quote of either spelling, as in the first copy, so
 * a name may open and close with different spellings. Escapes are read in pairs, so a \u0022 after an escaped backslash
 * is a quote too. Returns the copy and, for each of its characters, where it starts in `text`.
 */
function keepingPlainStrings(text) {
  const parts = [];
  const at = [];
  let from = 0;
  let string = OUTSIDE;
  let last = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const quote = c === '\\' && /^\\u0022/i.test(text.slice(i, i + 6));
    if (quote && string !== PLAIN_VALUE) {
      parts.push(text.slice(from, i), '"');
      for (let k = from; k <= i; k++) at.push(k);
      from = i + 6;
      i += 5;
      string = string === OUTSIDE ? LOOSE : OUTSIDE;
    } else if (c === '\\') {
      i++;
    } else if (c === '"') {
      if (string === OUTSIDE) string = last === ':' ? PLAIN_VALUE : LOOSE;
      else string = OUTSIDE;
    } else if (string === OUTSIDE && !isSpace(c)) {
      last = c;
    }
  }
  parts.push(text.slice(from));
  for (let k = from; k <= text.length; k++) at.push(k);
  return { copy: parts.join(''), at };
}

/** keepingPlainStrings: outside any string, in a member's plain-quoted value, or in any other string. */
const OUTSIDE = 0;
const PLAIN_VALUE = 1;
const LOOSE = 2;

/** The most a FLAT copy may spend reading, per character of the view it was copied from (readFlattened). */
const FLAT_ALLOWANCE = 8;

/**
 * Reads a decoded string as the JSON it may hold, `level` levels down. A string with a quote is read as JSON. A
 * string that still holds escapes is also read as the content of one more string, decoded once more (decodeString,
 * loosely when prose quotes around it make it no string's content), as Redactor
 * reads JSON escaped twice over; a chain of such escapes (u005c after u005c) therefore reaches the level cap.
 * Past the cap, a string with anything left to read is a leak (Redactor masks it whole). A view read before (the same
 * text at the same level, from the same place in the scanned text) is not read again: readUnread reads a string whole
 * and scanJson reads the literal inside it, and a level down both may decode to the same view, so without this the
 * views would double at each level of such strings (#342). The views are told apart by level, where they start in the
 * scanned text and their length, then compared: views of the same text from the same place hold the same names, and
 * a name read twice at one level counts once (mayExhaustJwkSearch). Where a view ends is not mapped back, as that read
 * the scanned text up to it again for each view (Codex security round 1 at 0ab5aeb). A string with no quote and no
 * escape holds nothing to read, so it is neither compared nor kept.
 */
function readNested(decoded, level, ctx, toRoot, mode = MAIN, cut = 0) {
  const quoted = decoded.includes('"');
  if (!quoted && !decoded.includes('\\')) return;
  const span = `${level}:${toRoot(0)}:${decoded.length}`;
  const views = ctx.read.get(span) ?? [];
  ctx.work += views.length * decoded.length;
  // A view read in a mode finds no more than the same view read in a mode before it (MAIN, UNREAD, WHOLE), so such a
  // read covers it.
  // A view cut inside a value (cut) finds more than the same view not cut there.
  if (views.some(view => view.decoded === decoded && view.mode <= mode && view.cut >= cut)) return;
  const view = { decoded, mode, cut, read: null };
  views.push(view);
  ctx.read.set(span, views);
  // scanJson reads the string first, so decodeString knows which strings it decoded.
  if (quoted && level >= MAX_LEVELS) {
    failClosed(ctx, 'JSON nested past 17 levels', decoded);
    return;
  }
  const read = quoted ? scanJson(decoded, level, ctx, toRoot, mode, cut) : [];
  view.read = read;
  if (mode === MAIN) readFlattened(decoded, level, ctx, toRoot, cut);
  // What a view main does not read holds is not read by main either.
  const below = mode === MAIN ? MAIN : UNREAD;
  // A FLAT copy is read in place only (see FLAT).
  if (!decoded.includes('\\') || mode === FLAT) return;
  const { decoded: unescaped, at: inDecoded, unread } = decodeString(decoded, ctx, read);
  if (unescaped !== decoded && (unescaped.includes('"') || unescaped.includes('\\'))) {
    if (level >= MAX_LEVELS) {
      failClosed(ctx, 'JSON nested past 17 levels', decoded);
      return;
    }
    readNested(unescaped, level + 1, ctx, j => toRoot(inDecoded(j)), below, cut !== 0 ? cutOf(decoded, unescaped) : 0);
  }
  // Only a string with a quote has strings to leave unread, and one at the level cap has failed closed above.
  readUnread(decoded, unread, level + 1, ctx, toRoot, cut !== 0);
}

/**
 * A JWK private member's name and colon, each letter also as a \u escape, as Redactor matches a field's name. Its
 * whitespace is Java's \s, ASCII only: JavaScript's also takes a no-break space (automated review on 7050fef).
 */
const PRIVATE_FIELD = /"((?:[A-Za-z_-]|\\u[0-9A-Fa-f]{4}){1,64})"[ \t\n\x0B\f\r]*:[ \t\n\x0B\f\r]*/y;

/** A kty name and colon, as Redactor finds a JWK's type member, with Java's whitespace. */
const KTY_TYPE = /"(?:k|\\u006[bB])(?:t|\\u0074)(?:y|\\u0079)"[ \t\n\x0B\f\r]*:/g;

/** A kty name at a member's name, as Redactor checks each name of an object it read. */
const KTY_AT = /"(?:k|\\u006[bB])(?:t|\\u0074)(?:y|\\u0079)"/y;

/** Whether `root` spells the line break at `lineBreak` as backslashes and an n or r: neither raw nor a \u escape. */
const escapedLineBreak = (root, lineBreak) => {
  let r = lineBreak;
  while (root[r] === '\\') r++;
  return r > lineBreak && (root[r] === 'n' || root[r] === 'r');
};

/**
 * The cut a view carries (readNested): none; CUT_ESCAPED, a cut after a lone backslash its source spells as an escaped
 * one (\\ before the half escape), where Redactor matches no value and keeps the text (automated review on b9d6038);
 * or CUT, any other. Each finds at least what the one before it finds.
 */
const CUT_ESCAPED = 1;
const CUT = 2;

/**
 * The cut a view `decoded` from `source` carries, where `source` was cut at its end: CUT_ESCAPED if the view ends in a
 * lone backslash that `source` spells as an escaped one, else CUT. A backslash spelled as a \u005c escape is CUT,
 * which Redactor masks (automated review on 73e4411). Only the end of each text is read, at each level as its view is
 * made, so no offsets are mapped back (automated review on d79595f: mapping them spent the budget at depth 3).
 */
const cutOf = (source, decoded) => {
  if (backslashesBefore(decoded, decoded.length) % 2 === 0) return CUT;
  const half = halfEscapeAt(source);
  const end = half >= 0 ? half : source.length - (backslashesBefore(source, source.length) % 2);
  const unicode = /\\u005[cC]$/.test(source.slice(Math.max(0, end - 6), end)) && backslashesBefore(source, end - 6) % 2 === 0;
  return unicode ? CUT : CUT_ESCAPED;
};

/** The line breaks Java's regex dot does not match: Redactor's escape takes any character but these. */
const LINE_BREAKS = '\n\r\u0085\u2028\u2029';

/**
 * Whether `text` from `from` to `to` holds a form feed the scanned text spells as a \f escape. Redactor's whitespace
 * in an escaped copy is a raw one or an escaped line break or tab, so such a form feed ends a name's whitespace there,
 * and the member is not one; a raw one, or a \u000c, Redactor reads as whitespace (automated review on e2487e1).
 */
const escapedFormFeed = (text, from, to, ctx, toRoot) => {
  // Only the name and whitespace are looked at, and charged: a search to the end of the view for each member made the
  // work grow with the square of the members in it, uncharged (Codex security round 2 at 8a06f7e, finding 2).
  ctx.work += to - from;
  for (let i = from; i < to; i++) {
    if (text[i] !== '\f') continue;
    let r = toRoot(i);
    while (ctx.text[r] === '\\') r++;
    if (ctx.text[r] === 'f') return true;
  }
  return false;
};

/** A name with its \u escapes decoded. */
const decodedName = name => name.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));

/** How many backslashes come right before index `i`. */
const backslashesBefore = (text, i) => {
  let run = 0;
  while (i - 1 - run >= 0 && text[i - 1 - run] === '\\') run++;
  return run;
};

/**
 * The private member fields in `text` whose value Redactor would have masked and did not: from a name's opening quote
 * (one no backslash escapes), the name and colon, then an object or array, a number, true or false, or a string that is
 * neither the mask nor empty: to its closing quote through any line break, or to the end of the text or a backslash
 * before a line break no raw line break in the scanned text spells, where it was cut, as Redactor reads a field (automated review on 7050fef: a value that starts with
 * a line break read as empty). Each comes as [where its name starts, text to report, check].
 */
function unmaskedPrivateFields(text, ctx, toRoot, cut) {
  const fields = [];
  ctx.work += text.length;
  for (let at = text.indexOf('"'); at >= 0; at = text.indexOf('"', at + 1)) {
    PRIVATE_FIELD.lastIndex = at;
    const m = PRIVATE_FIELD.exec(text);
    // A backslash before the name's opening quote does not stop it: Redactor matches an escaped copy's field from the
    // last backslash before its quote, so a quote escaped one level more than the copy's others still opens a member,
    // and whether it is one of a JWK is jwkLeaks' to decide (automated review on 32194d8).
    if (m === null || !JWK_PRIVATE_MEMBERS.has(decodedName(m[1]))) continue;
    const v = PRIVATE_FIELD.lastIndex;
    if (escapedFormFeed(text, at, v, ctx, toRoot)) continue;
    if (text[v] === '{' || text[v] === '[') {
      fields.push([at, text.slice(at, v + 40), 'JSON secret structure']);
    } else if (text[v] === '"') {
      // Redactor's escape takes any character but a line break, so a backslash before one, or at the end, ends the value
      // (automated review on 5173e8e). Only where the scanned text spells the line break as an \n or \r escape is that
      // the form Redactor reads: a raw line break, any of Java's (automated review on e2487e1: a raw U+0085),
      // or one spelled as a \u escape (automated review on 4175db6), Redactor reads past, so the value goes on,
      // which fails safe.
      let end = v + 1;
      while (end < text.length && text[end] !== '"') {
        if (text[end] !== '\\') {
          end++;
        } else if (end + 1 >= text.length
            || (LINE_BREAKS.includes(text[end + 1]) && escapedLineBreak(ctx.text, toRoot(end + 1)))) {
          break;
        } else {
          end += 2;
        }
      }
      const content = text.slice(v + 1, Math.min(end, text.length));
      let value;
      try {
        value = JSON.parse(`"${escapeControls(content)}"`);
      } catch {
        value = content;
      }
      ctx.work += content.length;
      // In a view cut inside a value (readNested), a value open at its end lost bytes there. One that ends in a lone
      // backslash Redactor does not match (automated review on b9d6038), so the loop above stops before it, at a mask.
      const open = cut && end >= text.length;
      if (open || (value !== MASK && value !== '')) fields.push([at, text.slice(at, end + 1), 'JSON secret field']);
    } else if (/^(?:-?\d|true\b|false\b)/.test(text.slice(v, v + 6))) {
      fields.push([at, text.slice(at, v + 40), 'JSON secret field']);
    }
  }
  return fields;
}

/** startOfObject's results that are no object's start, as in Redactor. */
const NOT_IN_BRACKETS = -1;
const IN_ARRAY = -2;
const OUT_OF_TIME = -3;

/**
 * The leaks in a view main does not read: each private member field unmasked in a JWK as Redactor's JWK search finds
 * JWKs, or every unmasked private member field once that search would spend its budget of 4m + 1024 for a view of
 * length m, as Redactor then masks every private member name. The search, written apart from Redactor's code: from each
 * kty name (and colon) whose quote no backslash escapes, it reads back to the open bracket of the object holding it,
 * turning in and out of strings at each quote no backslash escapes and skipping bracket pairs matched before; it then
 * reads that object forward, and every object in it, taking as an object's member names the first string after its open
 * bracket or after a comma in it. An object one of whose names is kty is a JWK, and all its names are its members. It
 * runs only when the view has an unmasked private member field, so it costs a pass over the view otherwise.
 */
function jwkLeaks(text, ctx, toRoot, cut) {
  const fields = unmaskedPrivateFields(text, ctx, toRoot, cut);
  if (fields.length === 0) return;
  let budget = 4 * text.length + 1024;
  const spentAt = budget;
  const matching = new Map();
  const startOfObject = member => {
    const closes = [];
    let inString = false;
    for (let i = member - 1; i >= 0; i--) {
      if (--budget < 0) return OUT_OF_TIME;
      const c = text[i];
      if (c === '"') {
        const run = backslashesBefore(text, i);
        budget -= run;
        if (budget < 0) return OUT_OF_TIME;
        if (run % 2 === 0) inString = !inString;
        i -= run;
      } else if (!inString && (c === '}' || c === ']') && matching.has(i)) {
        i = matching.get(i);
      } else if (!inString && (c === '}' || c === ']')) {
        closes.push(i);
      } else if (!inString && (c === '{' || c === '[')) {
        if (closes.length === 0) return c === '{' ? i : IN_ARRAY;
        matching.set(closes.pop(), i);
      }
    }
    return NOT_IN_BRACKETS;
  };
  const objects = (start, found) => {
    const open = [];
    let inString = false;
    let escaped = false;
    let nameNext = false;
    let i = start;
    while (i < text.length) {
      if (--budget < 0) return OUT_OF_TIME;
      const at = i;
      const c = text[i++];
      if (inString) {
        inString = escaped || c !== '"';
        escaped = !escaped && c === '\\';
      } else if (c === '"') {
        inString = true;
        if (nameNext) open[open.length - 1].names.push(at);
        nameNext = false;
      } else if (c === '{' && at > start && matching.has(at)) {
        i = matching.get(at) + 1;
        nameNext = false;
      } else if (c === '{') {
        const object = { start: at, names: [] };
        found.push(object);
        open.push(object);
        nameNext = true;
      } else if (c === '[') {
        open.push(null);
        nameNext = false;
      } else if (c === ',') {
        nameNext = open[open.length - 1] !== null;
      } else if (c === '}' || c === ']') {
        const object = open.pop();
        if (object) {
          matching.set(at, object.start);
          matching.set(object.start, at);
        }
        nameNext = false;
        if (open.length === 0) break;
      }
    }
    return i;
  };
  const names = new Set();
  let readEnd = 0;
  let spent = false;
  for (const m of text.matchAll(KTY_TYPE)) {
    const member = m.index;
    if (member < readEnd || escapedFormFeed(text, member, member + m[0].length, ctx, toRoot)) continue;
    const run = backslashesBefore(text, member);
    budget -= run;
    if (run % 2 !== 0) continue;
    const start = startOfObject(member);
    if (start === OUT_OF_TIME) {
      spent = true;
      break;
    }
    if (start < 0) continue;
    const found = [];
    const end = objects(start, found);
    if (end === OUT_OF_TIME) {
      spent = true;
      break;
    }
    readEnd = end;
    for (const object of found) {
      if (object.names.some(name => {
        KTY_AT.lastIndex = name;
        return KTY_AT.test(text);
      })) {
        for (const name of object.names) names.add(name);
      }
    }
  }
  ctx.work += spentAt - Math.max(budget, 0);
  for (const [at, report, check] of fields) {
    if (spent || names.has(at)) failClosed(ctx, check, report);
  }
}

/**
 * Reads `text` as JSON at nesting `level` (0 for the text itself, n for JSON in a string n levels down) in one
 * pass, tolerating prose and cut-off JSON around it, and judges every member it finds. Each string literal is
 * decoded with JSON.parse, so every spelling of its escapes is read as JSON reads it; a decoded string that may
 * hold JSON (it has a quote) is read the same way one level down. A stray quote (one whose string is followed by
 * something no string is) is read again from the character after it, so it cannot shift which quotes open
 * strings for the rest of the text.
 */
function scanJson(text, level, ctx, toRoot = j => j, mode = MAIN, cut = 0) {
  // Where the scan stops: the end of the text, or where the rest of it is a view already scanned (coveredFrom).
  let stopAt = text.length;
  // Only a JSON object can be a JWK: kty in the text around any JSON, or in an array, makes nothing private, as in
  // Redactor, unless its JWK search may spend its budget (textLeaks).
  const newOwner = object => ({ object, kty: false, values: [] });
  const top = newOwner(false);
  // The open objects and arrays, innermost last; a secret-named member's array also collects its items.
  const stack = [];
  // The member whose name and colon were just read, waiting for its value.
  let member = null;
  const owner = () => (stack.length > 0 ? stack[stack.length - 1].owner : top);
  // The literals decoded here, each [start, end) with its quotes (decodeString's `read`).
  const read = [];
  // In a view main does not read, the literals of the rest of the text from `at` on, if that rest is a view already
  // scanned at this level from the same place, in a mode that finds as much (MAIN, or this view's mode), else null.
  // Scanning resumes there as that view's scan began: no open object or array, no member waiting for its value, no
  // quote held back, and no name expected, so the rest would read the same literals and find no more. Its kty names
  // start at the same places, already counted. A string read whole after a stray quote and a raw line break is mostly
  // such a view (Codex security round 1 and the automated review on feb555e: a long pad spent the budget).
  const coveredFrom = at => {
    const views = ctx.read.get(`${level}:${toRoot(at)}:${text.length - at}`);
    if (!views) return null;
    ctx.work += text.length - at;
    const rest = text.slice(at);
    const view = views.find(v => v.read !== null && v.mode <= mode && v.cut >= cut && v.decoded === rest);
    return view ? view.read : null;
  };
  // Whether a literal's value lost bytes to a cut: half an escape decodeLiteral cut off its end, or, in a view cut inside
  // a value (readNested), the literal is still open at the view's end, unless the view ends in a lone backslash its
  // source spells as an escaped one (CUT_ESCAPED).
  const pending = literal => literal.cutEscape === true
    || (cut !== 0 && !literal.terminated && literal.end >= text.length
      && (cut === CUT || backslashesBefore(text, text.length) % 2 === 0));
  const nested = (decoded, literal) => {
    if (decoded === null) {
      // A string that does not decode but may hold JSON cannot be read: a leak, failing closed.
      if (literal.body.includes('\\"') || literal.body.includes('{')) failClosed(ctx, 'undecodable JSON string', literal.body);
      return;
    }
    read.push([literal.start, literal.terminated ? literal.end + 1 : literal.end]);
    // A FLAT copy is read in place only (see FLAT).
    if (mode === FLAT) return;
    const inBody = sourceOffsets(literal.body, ctx, literal.terminated ? decoded.length : Infinity);
    readNested(decoded, level + 1, ctx, j => toRoot(literal.start + 1 + inBody(j)), mode === MAIN ? MAIN : UNREAD, pending(literal) ? cutOf(literal.body, decoded) : 0);
  };
  let i = 0;
  // Quotes before this index were read as escaped ones inside a string a stray quote opened: a string opened at
  // any of them would end where that one did, so they open none when its span is read again.
  let quotesFrom = 0;
  while (i < text.length) {
    ctx.work++;
    if (ctx.work > ctx.budget) {
      if (!ctx.spent) failClosed(ctx, 'scan budget spent', text);
      ctx.spent = true;
      return read;
    }
    const c = text[i];
    if (c === '"' && i >= quotesFrom) {
      const literal = readLiteral(text, i, ctx, member !== null);
      if (literal.aborted) {
        // A string (no member's value: that reads through line breaks) cut off at a line break: JSON in it is
        // read like any other.
        nested(decodeLiteral(literal, ctx), literal);
        // Every quote before the line break would open a string that runs into it too.
        member = null;
        i = literal.end;
        const covered = mode !== MAIN && stack.length === 0 && i >= quotesFrom ? coveredFrom(i) : null;
        if (covered) {
          for (const [from, to] of covered) read.push([from + i, to + i]);
          stopAt = i;
          break;
        }
        continue;
      }
      const decoded = decodeLiteral(literal, ctx);
      let next = literal.end + 1;
      while (next < text.length && isSpace(text[next])) next++;
      ctx.work += next - literal.end;
      if (literal.terminated && text[next] === ':') {
        // A value with a colon after it is still the member's value (Redactor masks it and keeps the colon).
        if (member) {
          member.owner.values.push({
            name: member.name, malformed: member.malformed, kind: 'string', value: decoded, text: text.slice(literal.start, literal.end + 1), cutShort: false,
          });
        }
        const name = decoded ?? literal.body;
        // A name inside an array is no list item a mask could be: the list is judged as a structure, as Redactor masks
        // it whole ({"client_secret":["x":"..."]}).
        if (stack.length > 0 && stack[stack.length - 1].list) stack[stack.length - 1].list.nested = true;
        const o = owner();
        // In a view main does not read, jwkLeaks decides the JWKs.
        if (name === 'kty' && o.object && mode === MAIN) o.kty = true;
        member = { name, owner: o, malformed: decoded === null || text[literal.start - 1] === '\\' };
        // A secret name whose value the strict reading of its level consumed and found masked (unconsumedSecretNames)
        // is judged there: here its quotes may be read at two levels.
        // Mapping a position back builds offset maps, charged to the work, so only a secret name is looked up.
        if (ctx.strictNames?.size > 0 && isSecretKey(name) && ctx.strictNames.has(toRoot(literal.start + 1))) member = null;
        // A name is a string too: JSON serialized into one is read like any other.
        nested(decoded, literal);
        i = next + 1;
        continue;
      }
      const stray = literal.terminated && !endsValue(text[next]);
      if (member) {
        member.owner.values.push({
          name: member.name, malformed: member.malformed, kind: 'string', value: decoded, text: text.slice(literal.start, literal.end + 1),
          cutShort: (literal.terminated && !endsValue(text[literal.end + 1])) || pending(literal),
        });
        member = null;
      } else if (stack.length > 0 && stack[stack.length - 1].list) {
        stack[stack.length - 1].list.items.push(decoded);
      }
      nested(decoded, literal);
      // Outside any JSON, or after something no string is followed by, the quote may be a stray one: read its
      // span again for structure. A string cut off by the end of the text leaves nothing after it to resync.
      if ((stray || stack.length === 0) && literal.terminated) {
        quotesFrom = literal.end;
        i = literal.start + 1;
      } else {
        i = literal.end + 1;
      }
      continue;
    }
    if (c === '{' || c === '[') {
      const container = { owner: newOwner(c === '{'), list: null };
      if (member) {
        const value = { name: member.name, malformed: member.malformed, kind: c === '{' ? 'object' : 'array', items: [], nested: false, text: text.slice(i, i + 80) };
        member.owner.values.push(value);
        if (c === '[') container.list = value;
        member = null;
      } else if (stack.length > 0 && stack[stack.length - 1].list) {
        stack[stack.length - 1].list.nested = true;
      }
      stack.push(container);
    } else if (c === '}' || c === ']') {
      if (stack.length > 0) judge(stack.pop().owner, ctx, mode === FLAT);
      member = null;
    } else if (!member && stack.length > 0 && stack[stack.length - 1].list && !isSpace(c) && c !== ',' && c !== ':') {
      // A number, true, false or null in a secret-named list is no mask.
      let end = i;
      while (end < text.length && !endsScalar(text[end])) end++;
      stack[stack.length - 1].list.items.push({ scalar: text.slice(i, end) });
      ctx.work += end - i;
      i = Math.max(end, i + 1);
      continue;
    } else if (member && !isSpace(c)) {
      // A secret-named member's value that opens with a quote spelled \u0022 by one backslash and then the mask (with
      // an Authorization-style value's scheme in front of it, review on 3c5ddac) is Redactor's output, a string the flattened copy of a MAIN view reads and judges whole (readFlattened), as
      // Redactor reads it (#339). Any other value so opened, an empty one included, is judged here as main judges it
      // (security round 3: deferring every such value accepted {"client_secret":\u0022\u0022}, which main flags). Any
      // other member's value, a JWK private member's included, is judged here: the copy judges secret-named fields
      // only (review on 47c938e).
      if (isSecretKey(member.name) && ((mode === MAIN && opensLoneUnicodeQuote(text, i) && opensMask(member.name, text, i + 6))
        || (mode === FLAT && BACKSLASHED_UNICODE_QUOTE.test(text.slice(i, i + 64))))) {
        member = null;
        i++;
        continue;
      }
      // A scalar value runs to the next delimiter.
      let end = i;
      while (end < text.length && !endsScalar(text[end])) end++;
      if (end > i) member.owner.values.push({ name: member.name, malformed: member.malformed, kind: 'scalar', value: text.slice(i, end), text: text.slice(i, end) });
      member = null;
      ctx.work += end - i;
      i = Math.max(end, i + 1);
      continue;
    }
    i++;
  }
  while (stack.length > 0) judge(stack.pop().owner, ctx, mode === FLAT);
  judge(top, ctx, mode === FLAT);
  // A FLAT copy is read for secret-named fields only: its JWKs, and their kty names, are the other views' to judge.
  if (mode === FLAT) {
    ctx.work += stopAt;
    return read;
  }
  if (mode !== MAIN) jwkLeaks(text, ctx, toRoot, cut);
  ctx.kty[level] ??= [];
  for (const m of text.matchAll(KTY_SPELLING)) {
    if (m.index >= stopAt) break;
    ctx.kty[level].push({ toRoot, index: m.index });
  }
  ctx.work += stopAt;
  return read;
}

/**
 * The leaks in `text` read as JSON nested `level` levels down: the regex checks over the text itself, then
 * the JSON scan, which shares one budget linear in the text's length.
 */
function textLeaks(text, level) {
  // kty: where in the text each kty name the texts read at each level hold starts (scanJson).
  // read: the views readNested has read, by level and span in the text.
  const ctx = { leaks: [], work: 0, budget: 40 * text.length + 4096, spent: false, unowned: [], kty: [], read: new Map(), text, strictNames: new Set() };
  if (level === 0) {
    for (const check of TEXT_CHECKS) {
      if (check.scan) {
        check.scan(text, ctx);
        continue;
      }
      for (const m of text.matchAll(check.re)) {
        if (!check.ok || !check.ok(m)) ctx.leaks.push({ check: check.name, match: m[0].slice(0, 80) });
      }
    }
  }
  const read = scanJson(text, level, ctx);
  readFlattened(text, level, ctx, j => j, 0);
  // Text with escapes may be the content of a JSON string: text copied from inside one ({\"kty\":...}) has
  // no bare quotes, and an escape chain (u005c after u005c) decodes one level at a time. Read it decoded too, loosely
  // when quoted prose around it makes it no string's content (decodeString).
  if (text.includes('\\')) {
    const { decoded, at, unread } = decodeString(text, ctx, read);
    if (decoded !== text) readNested(decoded, level + 1, ctx, at);
    readUnread(text, unread, level + 1, ctx, j => j);
  }
  // Where each kty name starts in the text is mapped back only at a level with two or more of them: with fewer,
  // mayExhaustJwkSearch is false whatever the positions. Mapping a name after a long value walked that value again at
  // every level it was read at (automated review on feb555e).
  const positions = names => (names.length < 2 ? [] : names.map(name => name.toRoot(name.index)));
  if (ctx.kty.some(names => mayExhaustJwkSearch(text.length, positions(names)))) {
    for (const value of ctx.unowned) failClosed(ctx, value.check, value.text);
  }
  scanWork.characters += ctx.work;
  return ctx.leaks;
}

/** Returns one {check, match} per suspected leak in `text`. */
export function findTextLeaks(text) {
  return textLeaks(text, 0);
}

/**
 * Walks parsed JSON for secret-named fields and sensitive headers whose values are not
 * masked. String values that are themselves JSON (recorded request/response bodies)
 * are walked too, up to the levels the text scan reads. A header list under a *headers map
 * is left to the sensitive-header check.
 */
export function findJsonLeaks(value, path = '$') {
  const leaks = [];
  const walk = (v, p, inHeaders, level) => {
    if (typeof v === 'string') {
      const t = v.trim();
      const before = leaks.length;
      if (t.startsWith('{') || t.startsWith('[')) {
        if (level + 1 >= MAX_LEVELS) {
          leaks.push({ check: 'JSON nested past 17 levels', match: `${p}` });
          return;
        }
        try { walk(JSON.parse(t), `${p}<json>`, false, level + 1); } catch { /* not JSON as a whole */ }
      }
      // JSON in the string read as text when parsing found nothing: after prose (payer said: {...}), cut off,
      // or repeating a member, which parsing drops; also loose members after kty names, which Redactor may mask
      // all of (mayExhaustJwkSearch), spelled in the string or in escapes it holds.
      if (leaks.length === before && (/[{[\\]/.test(v) || ktyCount(v) > 0)) {
        for (const leak of textLeaks(v, level)) leaks.push({ check: leak.check, match: `${p}: ${leak.match}` });
      }
      return;
    }
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${p}[${i}]`, false, level)); return; }
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
      walk(x, `${p}.${k}`, /headers$/i.test(k), level);
    }
  };
  walk(value, path, false, 0);
  return leaks;
}
