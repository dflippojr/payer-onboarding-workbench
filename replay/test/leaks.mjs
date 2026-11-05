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
 * that offset (the end of `body` past its last character), building the map, charged to the scan's work, on first use.
 */
const sourceOffsets = (body, ctx) => {
  let offsets = null;
  return j => {
    if (offsets === null) {
      offsets = [];
      for (let i = 0; i < body.length; i += body[i] !== '\\' ? 1 : body[i + 1] === 'u' ? 6 : 2) offsets.push(i);
      ctx.work += body.length;
    }
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
 * own budget, and a name found at several levels is not counted twice in one. The read after the key blocks are masked
 * spends the rest of the same budget, and needs a PEM header in the text, which the PEM block check flags.
 */
const mayExhaustJwkSearch = (n, positions) => {
  const k = positions.length;
  if (k < 2) return false;
  const p = positions.map(x => Math.min(x, n)).sort((a, b) => a - b);
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
 * Checks over raw text: a regex whose `ok(match)` returning true means the hit is a masked or harmless value, or
 * a `scan(text, ctx)` that reads the text procedurally, in linear work, and records its own leaks.
 */
const TEXT_CHECKS = [
  // Redactor replaces whole PEM blocks, so any PEM header left over is a leak.
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/g },
  // The credential, which may be URL-encoded, runs to the next whitespace, quote, comma, semicolon or
  // backslash, as in Redactor; a JSON escape of a token character (\/, \u002B) is that character, not a
  // backslash, also escaped again (\\/) in a recorded body (#211).
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
  { name: 'Bearer/Basic credential cut short', re: new RegExp(String.raw`${AUTH_START}(?:Bearer|Basic|Token|DPoP)(?:[ \t]+|(?<=Bearer|Basic)\s+|(?<=Bearer)(?:%20|\+))\[REDACTED\](?:[^\s"',;\\]|${ESCAPED_TOKEN_CHAR})`, 'gi') },
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
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      terminated = true;
      break;
    }
    if ((c === '\n' || c === '\r') && !value) {
      ctx.work += i - start;
      return { aborted: true, start, end: i, terminated: false, body: text.slice(start + 1, i) };
    }
    if (c === '\\') {
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
  return { start, end, terminated, body: text.slice(start + 1, end) };
}

/**
 * A literal's content decoded with JSON.parse, or null if it does not decode. A string cut off by the end of
 * the text may end in half an escape, which is dropped first, as Redactor leaves such a cut.
 */
function decodeLiteral(literal, ctx) {
  let body = literal.body;
  if (!literal.terminated) {
    let backslashes = 0;
    while (backslashes < body.length && body[body.length - 1 - backslashes] === '\\') backslashes++;
    if (backslashes % 2 === 1) body = body.slice(0, -1);
    const partial = body.lastIndexOf('\\u');
    if (partial >= 0 && partial > body.length - 6 && !/^[0-9A-Fa-f]{4}/.test(body.slice(partial + 2))) {
      body = body.slice(0, partial);
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
 * object is kept for textLeaks, which flags it if Redactor's JWK search may spend its budget on the text.
 */
function judge(owner, ctx) {
  for (const value of owner.values) {
    if (isSecretKey(value.name)) {
      const masked = value.kind === 'string' ? value.value !== null && isMaskedValue(value.name, value.value) && !value.cutShort
        : value.kind === 'scalar' ? value.value === 'null'
          : value.kind === 'array' && !value.nested && value.items.every(item => isMaskedItem(value.name, item));
      if (!masked) failClosed(ctx, value.kind === 'object' || value.kind === 'array' ? 'JSON secret structure' : 'JSON secret field', value.text);
    } else if (isPrivateName(value.name, value.malformed)) {
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

/**
 * Reads a decoded string as the JSON it may hold, `level` levels down. A string with a quote is read as JSON. A
 * string that still holds escapes is also read as the content of one more string, decoded once more, as Redactor
 * reads JSON escaped twice over; a chain of such escapes (u005c after u005c) therefore reaches the level cap.
 * Past the cap, a string with anything left to read is a leak (Redactor masks it whole).
 */
function readNested(decoded, level, ctx, toRoot) {
  const quoted = decoded.includes('"');
  let unescaped = null;
  if (decoded.includes('\\')) {
    ctx.work += decoded.length;
    try {
      unescaped = JSON.parse(`"${escapeControls(decoded)}"`);
    } catch { /* not the content of a string: a backslash of its own */ }
  }
  const deeper = unescaped !== null && unescaped !== decoded && (unescaped.includes('"') || unescaped.includes('\\'));
  if (!quoted && !deeper) return;
  if (level >= MAX_LEVELS) {
    failClosed(ctx, 'JSON nested past 17 levels', decoded);
    return;
  }
  if (quoted) scanJson(decoded, level, ctx, toRoot);
  if (deeper) {
    const inDecoded = sourceOffsets(decoded, ctx);
    readNested(unescaped, level + 1, ctx, j => toRoot(inDecoded(j)));
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
function scanJson(text, level, ctx, toRoot = j => j) {
  ctx.kty[level] ??= [];
  for (const m of text.matchAll(KTY_SPELLING)) ctx.kty[level].push(toRoot(m.index));
  ctx.work += text.length;
  // Only a JSON object can be a JWK: kty in the text around any JSON, or in an array, makes nothing private, as in
  // Redactor, unless its JWK search may spend its budget (textLeaks).
  const newOwner = object => ({ object, kty: false, values: [] });
  const top = newOwner(false);
  // The open objects and arrays, innermost last; a secret-named member's array also collects its items.
  const stack = [];
  // The member whose name and colon were just read, waiting for its value.
  let member = null;
  const owner = () => (stack.length > 0 ? stack[stack.length - 1].owner : top);
  const nested = (decoded, literal) => {
    if (decoded === null) {
      // A string that does not decode but may hold JSON cannot be read: a leak, failing closed.
      if (literal.body.includes('\\"') || literal.body.includes('{')) failClosed(ctx, 'undecodable JSON string', literal.body);
      return;
    }
    const inBody = sourceOffsets(literal.body, ctx);
    readNested(decoded, level + 1, ctx, j => toRoot(literal.start + 1 + inBody(j)));
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
      return;
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
        if (name === 'kty' && o.object) o.kty = true;
        member = { name, owner: o, malformed: decoded === null || text[literal.start - 1] === '\\' };
        // A name is a string too: JSON serialized into one is read like any other.
        nested(decoded, literal);
        i = next + 1;
        continue;
      }
      const stray = literal.terminated && !endsValue(text[next]);
      if (member) {
        member.owner.values.push({
          name: member.name, malformed: member.malformed, kind: 'string', value: decoded, text: text.slice(literal.start, literal.end + 1),
          cutShort: literal.terminated && !endsValue(text[literal.end + 1]),
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
      if (stack.length > 0) judge(stack.pop().owner, ctx);
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
  while (stack.length > 0) judge(stack.pop().owner, ctx);
  judge(top, ctx);
}

/**
 * The leaks in `text` read as JSON nested `level` levels down: the regex checks over the text itself, then
 * the JSON scan, which shares one budget linear in the text's length.
 */
function textLeaks(text, level) {
  // kty: where in the text each kty name the texts read at each level hold starts (scanJson).
  const ctx = { leaks: [], work: 0, budget: 40 * text.length + 4096, spent: false, unowned: [], kty: [] };
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
  scanJson(text, level, ctx);
  // Text with escapes may be the content of a JSON string: text copied from inside one ({\"kty\":...}) has
  // no bare quotes, and an escape chain (u005c after u005c) decodes one level at a time. Read it decoded too.
  if (text.includes('\\')) {
    ctx.work += text.length;
    let decoded = null;
    try {
      decoded = JSON.parse(`"${escapeControls(text)}"`);
    } catch { /* bare quotes in it: not a string's content */ }
    if (decoded !== null && decoded !== text) readNested(decoded, level + 1, ctx, sourceOffsets(text, ctx));
  }
  if (ctx.kty.some(positions => mayExhaustJwkSearch(text.length, positions))) {
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
