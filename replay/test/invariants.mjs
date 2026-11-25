// The bundle check (#425, stage 3 of #377): judges recorded text by the invariants of the Redactor's canonical output
// instead of reading every escape spelling as the Redactor might. A bundle file is parsed with JSON.parse, each string
// in it that parses as JSON is parsed again, and what comes out must hold:
//
//   1. A secret-named member's value is exactly a form the Redactor writes: the mask, null, for an
//      Authorization-style name a listed scheme and the mask, or a list of such strings.
//   2. In an object with a kty member (a JWK), a private member's value is the mask or null.
//   3. No decoded string holds a scheme credential, key armor, a JWT signature (or a JWT whose header or payload
//      holds a secret), a form secret, a credential header line, or a quoted secret name whose value is not such a
//      form.
//   4. No string holds secret vocabulary next to a spelling the Redactor does not write: a JSON-looking start that
//      does not parse, JSON whose member names repeat, or a quote or backslash that only a decoding of the string's
//      escapes shows.
//
// A string that is not JSON is text: each JSON value embedded in it is judged by 1 and 2, and the text around those
// values by 3 and 4, as it is spelled and again at each decoding of its JSON escapes (a plain left-to-right unescape,
// repeated until nothing decodes). A string the workbench recorded whole is also judged as it is written out, each
// JSON value in JSON's own spelling, at each decoding (judgeWritten): there the quotes and backslashes of every level
// are plain. So the rules read plain spellings: a quote or backslash spelled as an escape is a plain one in the next
// decoding, where the same rules read it. Two rules also read an escape in place, as the Redactor's do: a member
// name's quotes may be escaped once (JSON held in a JSON string) and its letters spelled \u, and a scheme's
// separator and credential may be JSON escapes.
//
// The check is at least as strict as the Redactor on every text the tests hold (the corpus, the committed grids,
// generated secrets), and stricter on purpose where the decisions on #425 say a miss blocks and an over-flag is
// acceptable: text behind any mask is flagged (one terminator check over every mask, whichever rule wrote it), though
// the Redactor leaves a broken mask as it finds it; and in a decoding that is not JSON as a whole, a kty member
// anywhere means every private member anywhere must be the mask, with no reading of which braces hold which member
// (only values that read as JSON whole, when no kty member stands outside them, are still read as JSON; in one
// recorded string, only the one value that holds every kty member of the string).
// It is not a second Redactor. Three kinds of text the Redactor masks whole, fail closed, hold no credential bytes and
// are accepted here: masks right behind a value that already is the mask, up to a terminator; cut JSON that repeats a
// member name and names no secret; and a masked header line that ends at its JSON string's own closing quote two or
// more decodings down.
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

/** Whitespace that ends a value, as the JVM's Character.isWhitespace reads it. */
const VALUE_SPACE = ' \\t\\n\\x0B\\f\\r\\x1C-\\x1F\\u1680\\u2000-\\u2006\\u2008-\\u200A\\u2028\\u2029\\u205F\\u3000';

/**
 * What may stand right behind a masked value, by the kind of rule that read it; the end of the text always may.
 * `value`: a JSON value's end. `decoded`: the same, also behind the closing quote of the string that held the value.
 * `credential`: where a scheme's credential ends, or the period that ends a sentence. `loose`: a delimiter or a
 * quote, also an escaped one, for a key read loosely. `end`: nothing (a form value or a header line, already cut at
 * its own end). `mask`: behind any mask at all, whichever rule wrote it ({@link judgeMasks}).
 */
const TERMINATORS = {
  value: new RegExp(`[,}\\]${VALUE_SPACE}]`, 'y'),
  decoded: new RegExp(`"?(?:$|[,}\\]${VALUE_SPACE}])`, 'y'),
  credential: /[ \t\n\x0B\f\r"',;\\&)\]}<]|\.(?:$|[ \t\n\x0B\f\r"')\]}])/y,
  loose: /["',}\]\s]|(?:\\\\)*\\(?:"|u0022)/y,
  end: /(?!)/y,
  // Behind any mask: anything but a character a credential is spelled with (a dot may start the next piece of a
  // token), or a colon in front of one (the rest of a pair of credentials).
  mask: /(?!:[A-Za-z0-9_~+/=%-])[^A-Za-z0-9_~+/=%-]/y,
};

/**
 * The one rule for where a masked value ends (owner decision 3 on #425): at `at`, right behind the value's own mask
 * or closing quote, any further masks (the mask the Redactor writes to the end of a text it stops reading may stand
 * there) must themselves run to the end of the text or to a terminator of the rule's `kind`. Every rule asks here.
 */
function endsMasked(text, at, kind = 'value') {
  let end = at;
  while (text.startsWith(MASK, end)) end += MASK.length;
  if (end >= text.length) return true;
  const terminator = TERMINATORS[kind];
  terminator.lastIndex = end;
  return terminator.test(text);
}

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

/** Whether a member name, at any decoding of its escapes, holds a quote that a colon follows: one member ending, the next starting. */
function spellsAMember(name) {
  if (!name.includes('"') && !name.includes('\\')) return false;
  const { passes, more } = decodings(name);
  return more || passes.some(pass => /"[ \t\r\n]*:/.test(pass));
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
    // A string of a bundle file's own structure is one the workbench recorded whole: judged as it is on its own.
    judgeText(value, scan, recorded ? 0 : level + 1);
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
    } else if (jwk && spellsAMember(name)) {
      // Which part of such a name a private value belongs to is not established; the Redactor masks the text.
      scan.flag('JWK member name that reads as more than one member', name);
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
  if (text[at] !== '{') return c === ']' || c === '[' || c === '{';
  if (c === '}') return true;
  // Object-literal spelling (decisions 8 and 9 on #425): a secret name without quotes, first after the brace, used as
  // a key with a quoted value. The whitespace around it is what the loose-key rule accepts around a separator.
  LITERAL_KEY.lastIndex = at + 1;
  return LITERAL_KEY.test(text);
}

/**
 * The JSON values embedded in `text`: for each bracket no earlier value holds, the text to its matching bracket,
 * quotes respected, if JSON.parse reads it, it nests no deeper than MAX_DEPTH and no member name repeats in it.
 * Returns their spans and values, and
 * where the first JSON-looking start that does not read is (-1 if none). The walks for candidates that do not read
 * stop after about four times the text's length; past that every start counts as one that does not read.
 */
function embeddedValues(text, shared) {
  const values = [];
  let failed = -1;
  let budget = shared ? shared.left : 4 * text.length + 4096;
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
  if (shared) shared.left = budget;
  return { values, failed };
}

/** Stands for an embedded JSON value in the text the rules read: a name in front of it has a value that is no mask. */
const HOLE = '\uE000';

/**
 * Judges a decoded string at JSON-in-string level `level`: JSON by invariants 1 and 2, any other text by 3 and 4. A
 * string at level 0 is one the workbench recorded whole, so it is also judged as written out ({@link judgeWritten}).
 * `recorded`: the text is a bundle file, whose own structure may hold a header's list of masked values. The written
 * form is read only when nothing else is flagged: it adds a verdict, not a second report of the same member.
 */
function judgeText(text, scan, level, recorded = false) {
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
      judgeValue(json.value, scan, level, recorded);
      // A text that is one JSON string: no object or array bounds it, so the quote that closes it is part of a
      // header line that ends it, and the quote that opens it keeps a line at its start from being one.
      if (typeof json.value === 'string') judgeHeaderLines(`"${json.value}"`, scan);
      if (level === 0 && scan.leaks.length === 0) judgeWritten(JSON.stringify(json.value), scan, recorded, recorded ? ownStructure(json.value) : undefined);
      return;
    }
  }
  const { values, failed } = read ? embeddedValues(text) : { values: [], failed: text.search(/[[{]/) };
  judgeJwksInString(text, read, scan);
  let prose = '';
  let written = '';
  let copied = 0;
  for (const { from, to, value } of values) {
    judgeValue(value, scan, level, recorded);
    prose += text.slice(copied, from) + HOLE;
    written += text.slice(copied, from) + JSON.stringify(value);
    copied = to;
  }
  prose += text.slice(copied);
  const { passes, more } = decodings(prose);
  if (more) scan.flag('escapes deeper than the check decodes', text);
  passes.forEach((pass, depth) => judgeProse(pass, scan, depth > 0));
  if (failed >= 0 && decodings(text.slice(failed)).passes.some((pass, depth) => holdsVocabulary(pass, depth > 0, scan))) {
    scan.flag('JSON-looking start that does not parse, before secret vocabulary', text.slice(failed));
  } else if (read && passes.length > 1) {
    // A start that only a decoding shows (decision 9 on #425): each decoding is read for one the same way, all of them
    // within one budget of walks.
    const budget = { left: 4 * prose.length + 4096 };
    for (let depth = 1; depth < passes.length; depth++) {
      const start = embeddedValues(passes[depth], budget).failed;
      if (start >= 0 && holdsVocabulary(passes[depth].slice(start), true, scan)) {
        scan.flag('JSON-looking start that does not parse, before secret vocabulary', passes[depth].slice(start));
        break;
      }
    }
  }
  if (level === 0 && values.length > 0 && scan.leaks.length === 0) judgeWritten(written + text.slice(copied), scan, recorded);
}

/**
 * Invariant 4 for a recorded string as it is written out, each JSON value in it in JSON's own spelling: at each
 * decoding of its escapes, where the quotes and backslashes of every level are plain, no quoted secret name has a
 * value that is not a written form at a strict value end, and no JSON value that reads there is a JWK with a private
 * member that is not the mask. This is where a member name that a decoding reads as a secret name, or as more than
 * one member, shows, and a masked value that ends at its string's own closing quote.
 */
function judgeWritten(written, scan, recorded, structure = written) {
  const { passes } = decodings(written);
  for (let depth = 1; depth < passes.length; depth++) {
    const pass = passes[depth];
    // In a bundle file the closing quote of one of the file's own strings stands behind the recorded text it holds: a
    // text may end in a masked member there (decision 8 on #425), as it may where it is judged on its own. Each
    // recorded text is judged on its own as well, where a closing quote inside it is no end.
    judgeMembers(pass, scan, true, false, recorded, recorded ? 'decoded' : 'value');
  }
  // In a bundle file the JWK rules do not read again a string that is a JSON text as a whole: it is a recorded text,
  // judged on its own (decision 7 on #425), and a text the Redactor leaves is left in a file as well (decision 8).
  const keyed = structure === written ? passes : decodings(structure).passes;
  for (let depth = 1; depth < keyed.length; depth++) {
    const pass = keyed[depth];
    if (!pass.includes('"kty"')) continue;
    let whole;
    try {
      whole = JSON.parse(pass);
    } catch {
      judgeJwksAnywhere(pass, scan);
      continue;
    }
    // JSON.parse keeps the last of a repeated name only, so which member belongs to which object is not read there either.
    if (repeatsAName(pass)) judgeJwksIn(pass, scan);
    judgeJwks(whole, scan);
  }
}

/**
 * A bundle file written out for the JWK rules: as it is, but a string that is a JSON object or array as a whole is
 * left empty. Such a string is a recorded JSON text, judged on its own; read again inside the file it would only be
 * the same text one level further down, which the Redactor did not read there.
 */
function ownStructure(value) {
  if (typeof value === 'string') {
    if (/^[ \t\n\r]*[[{]/.test(value)) {
      try {
        JSON.parse(value);
        return '""';
      } catch {
        // Not JSON as a whole: kept.
      }
    }
    return JSON.stringify(value);
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(ownStructure).join(',')}]`;
  return `{${Object.entries(value).map(([name, member]) => `${JSON.stringify(name)}:${ownStructure(member)}`).join(',')}}`;
}

/**
 * A JWK private member's quoted name and its colon, where a member starts: after a brace or a comma, which the match
 * starts at, so each stretch of whitespace is read once.
 */
const PRIVATE_MEMBER = new RegExp(`[{,][${WS}]*"(?:${[...JWK_PRIVATE_MEMBERS].join('|')})"[${WS}]*:[${WS}]*`, 'g');

/** A kty member's quoted name and its colon, anywhere. */
const KTY_MEMBER = new RegExp(`"kty"[${WS}]*:`, 'g');

/** Whether the value at `at` in a decoding is the mask or null, up to where a value ends or its string's own quote closes. */
function isMaskedInDecoding(pass, at) {
  const end = pass.startsWith(`"${MASK}"`, at) ? at + MASK.length + 2 : pass.startsWith('null', at) ? at + 4 : -1;
  return end >= 0 && endsMasked(pass, end, 'decoded');
}

/** Flags the first private member anywhere in `text` that is not the mask. */
function judgeJwksIn(text, scan) {
  for (const m of text.matchAll(PRIVATE_MEMBER)) {
    if (!isMaskedInDecoding(text, m.index + m[0].length)) {
      scan.flag('private member in a decoding that holds a key type', text.slice(m.index, m.index + 60));
      return;
    }
  }
}

/**
 * For a decoding that is not JSON as a whole (decision 6 on #425): with a kty member anywhere in it, every private
 * member anywhere in it must be the mask. No bounds are read: which braces hold which member is what such a decoding
 * does not settle. One kind of value in it is still read as JSON, by its tree: a value that JSON.parse reads whole,
 * while every kty member of the decoding stands inside such values. That is JSON a string holds, as the Redactor
 * writes it and as a bundle file holds many of, where a private name outside the JWK's own object is any name. With
 * a kty member outside every such value, the private members inside them count as well.
 */
function judgeJwksAnywhere(pass, scan) {
  const ktys = [...pass.matchAll(KTY_MEMBER)].map(m => m.index);
  if (ktys.length === 0) return;
  const { values } = embeddedValues(pass);
  let rest = '';
  let copied = 0;
  let next = 0;
  let inValues = 0;
  for (const { from, to } of values) {
    while (next < ktys.length && ktys[next] < from) next++;
    for (; next < ktys.length && ktys[next] < to; next++) inValues++;
    // A private member whose value is such a value is not the mask.
    rest += `${pass.slice(copied, from)}0`;
    copied = to;
  }
  judgeJwksIn(rest + pass.slice(copied), scan);
  for (const { from, to, value } of values) {
    if (inValues < ktys.length) judgeJwksIn(JSON.stringify(value), scan);
    else judgeJwks(value, scan);
  }
}

/**
 * For one recorded string that is not JSON as a whole (decision 7 on #425): with a kty member anywhere in it, a
 * private member anywhere in it must be the mask, unless it stands in the same value as every kty member of the
 * string: a value that JSON.parse reads whole, which {@link judgeValue} judges by its tree.
 *
 * The rule reads one normal form (implementation note under decisions 3 and 7): each value that reads is written in
 * JSON's own spelling, where every member name is plain, and the text around the values is read at each decoding of
 * its escapes, the values that read staying as they are. So a name spelled with an escape, or a value a level down,
 * is read like a plain one; no pattern reads an escape in place.
 */
function judgeJwksInString(text, read, scan) {
  let pass = text;
  for (let depth = 0; depth <= MAX_DECODINGS; depth++) {
    // Only a \u escape can spell a letter of a name.
    if (!pass.includes('kty') && !pass.includes('\\u')) return;
    let normal = '';
    let next = '';
    let copied = 0;
    const spans = [];
    const around = to => {
      const rest = pass.slice(copied, to);
      normal += rest;
      next += unescaped(rest);
    };
    for (const { from, to, value } of read ? embeddedValues(pass).values : []) {
      around(from);
      const json = JSON.stringify(value);
      spans.push({ from: normal.length, to: normal.length + json.length });
      normal += json;
      next += json;
      copied = to;
    }
    around(pass.length);
    const ktys = [...normal.matchAll(KTY_MEMBER)].map(m => m.index);
    if (ktys.length > 0) {
      const holder = spans.find(({ from, to }) => from <= ktys[0] && ktys[ktys.length - 1] < to);
      const flagged = scan.leaks.length;
      judgeJwksIn(holder ? `${normal.slice(0, holder.from)}0${normal.slice(holder.to)}` : normal, scan);
      if (scan.leaks.length > flagged) return;
    }
    if (next === normal) return;
    pass = next;
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

/** A JSON escape of a token68 character, also escaped again: \/, or the \u escape of a letter, a digit or one of -._~+/=. */
const ESCAPED_TOKEN_CHAR = String.raw`\\+(?:/|u00(?:2[BDEF]|3[0-9D]|[46][1-9A-F]|[57][0-9A]|5F|7E))`;

/** Where a word starts: a word boundary, or right after a JSON escape that leaves a letter in front of the word. */
const WORD_START = String.raw`(?:\b|(?<=\\[nrtbf]))`;

/**
 * A scheme (1), its separator, its token68 part (2) and the rest up to whitespace, a quote, a comma, a semicolon or
 * a backslash (3). After Bearer the space may be URL-encoded; after Token and DPoP only spaces and tabs separate. The
 * separator and the credential's characters may be JSON escapes, read in place: a credential a serializer escaped is
 * still one, whatever the same text reads as once decoded.
 */
const SCHEME_CREDENTIAL = new RegExp(String.raw`(?:${WORD_START}|(?<=%[0-9A-Fa-f]{2})(?=Bearer))(Bearer|Basic|Token|DPoP)`
  + String.raw`(?:(?:[ \t]|\\+(?:t|u00(?:20|09)))+|(?<=Bearer|Basic)(?:[${WS}]|\\+(?:[nrtf]|u00(?:20|0[9A-D])))+|(?<=Bearer)(?:%20|\+))`
  + String.raw`(?!(?:realm|error|error_description|scope)[${WS}]*=[${WS}]*[^${WS},])`
  + String.raw`((?:[A-Za-z0-9\-._~+/%]|${ESCAPED_TOKEN_CHAR})+=*)((?:[^${WS}"',;\\]|${ESCAPED_TOKEN_CHAR})*)`, 'gi');

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

/**
 * A scheme in front of the mask, and what follows the mask: anything but where a credential ends, another mask or the
 * period that ends a sentence is the rest of a credential.
 */
const MASKED_SCHEME = new RegExp(String.raw`\b(?:Bearer|Basic|Token|DPoP)[${WS}]+\[REDACTED\]`, 'gi');

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
 * A quoted member name (2) and its colon; (1) is its quote, a plain one or, in JSON held in a JSON string, an escaped
 * one. A secret name holds only letters, _ and -, each also as a \u escape; the whitespace around the colon may be an
 * escaped line break or tab.
 */
const MEMBER_SPACE = String.raw`(?:[${WS}]|\\[nrt])*`;
const MEMBER_NAME = new RegExp(String.raw`(\\?")((?:[A-Za-z\u212A_-]|\\{1,2}u[0-9A-Fa-f]{4})+)\1${MEMBER_SPACE}:${MEMBER_SPACE}`, 'g');

/** Whitespace as the loose-key rule reads it: the one policy for recognizing a loosely spelled key and for judging it. */
const LOOSE_SPACE = String.raw`[\s\p{Z}\u0085]`;

/** What may lie between a name and its key separator, and between that and its value: quotes, whitespace and escapes. */
const GAP = String.raw`(?:${LOOSE_SPACE}|["']|\\+(?:u[0-9A-Fa-f]{4}|[A-Za-z"]))*`;

/**
 * A secret name, loosely: a field name with any number of _ or - around and between its letters, from the first of
 * them, or a header name.
 */
const SECRET_NAME = new RegExp(`(?<![_-])${FIELD_KEY}|${HEADER_NAME.replaceAll('-', '[_-]?')}`, 'gi');

/** A secret name without quotes, its colon and the quote that opens its value: a key in object-literal spelling. */
const LITERAL_KEY = new RegExp(`${LOOSE_SPACE}*(?:${SECRET_NAME.source})${LOOSE_SPACE}*:${LOOSE_SPACE}*"`, 'yiu');

/** A JWK private member's quoted name. */
const PRIVATE_NAME = new RegExp(`"(?:${[...JWK_PRIVATE_MEMBERS].join('|')})\\\\*"`, 'g');

/** A name's key separator, a colon or an equals sign, with a gap on both sides: the name is used as a key. */
const TO_VALUE = new RegExp(`${GAP}[:=]${GAP}`, 'yu');

/** The mask, a scheme in front of it or not, where a value ends: the end, a delimiter or a quote, also an escaped one. */
const MASKED_VALUE = /(?:[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]* )?\[REDACTED\]/y;

/**
 * Whether a name `names` finds in `text`, each read once from left to right, is used as a key whose value is not
 * already the mask or, `evenMasked`, any value.
 */
function namesAKey(names, text, evenMasked) {
  names.lastIndex = 0;
  for (let m = names.exec(text); m; m = names.exec(text)) {
    TO_VALUE.lastIndex = m.index + m[0].length;
    if (!TO_VALUE.test(text)) continue;
    if (evenMasked) return true;
    MASKED_VALUE.lastIndex = TO_VALUE.lastIndex;
    if (!MASKED_VALUE.test(text) || !endsMasked(text, MASKED_VALUE.lastIndex, 'loose')) return true;
  }
  return false;
}

/**
 * Whether `text`, from a JSON-looking start that does not parse, holds secret vocabulary (invariant 4): armor, a
 * secret name used as a key, with a kty a JWK private member's name used as one, or anything the text rules flag in
 * it, the JSON values that read after the start included. As spelled, a key whose value already is the mask is
 * redacted text read again; in a decoding, where quotes of several levels meet, every key counts.
 */
function holdsVocabulary(text, decoded, scan) {
  if (text.includes('-----BEGIN') || namesAKey(SECRET_NAME, text, decoded)
    || (text.includes('kty') && namesAKey(PRIVATE_NAME, text, decoded))) return true;
  const rules = new Scan();
  rules.segments = scan.segments;
  rules.tokenDepth = scan.tokenDepth;
  judgeProse(text, rules, decoded);
  return rules.leaks.length > 0;
}

/** A JSON list of strings, each part read one way only. */
const STRING_LIST = /\[[ \t\n\r]*(?:"(?:[^"\\]|\\.)*"[ \t\n\r]*(?:,[ \t\n\r]*"(?:[^"\\]|\\.)*"[ \t\n\r]*)*)?\]/y;

/** The same in JSON held in a JSON string, each string between escaped quotes and with no quote or backslash in it. */
const EMBEDDED_STRING_LIST = /\[[ \t\n\r]*(?:\\"[^"\\]*\\"[ \t\n\r]*(?:,[ \t\n\r]*\\"[^"\\]*\\"[ \t\n\r]*)*)?\]/y;

/**
 * Whether the value at `at`, after the colon of the secret name `name`, is a form the Redactor writes, at a strict
 * value end: null, a masked string between the name's own `quote`s, or a list of scheme forms quoted the same way.
 */
function readsAsMasked(text, at, name, quote, recorded, kind = 'value') {
  if (text.startsWith('null', at)) return endsMasked(text, at + 4, kind);
  if (text[at] === '[') {
    const lists = quote === '"' ? STRING_LIST : EMBEDDED_STRING_LIST;
    lists.lastIndex = at;
    const list = lists.exec(text);
    if (!list) return false;
    let items;
    try {
      items = JSON.parse(quote === '"' ? list[0] : list[0].replaceAll('\\"', '"'));
    } catch {
      return false;
    }
    return items.every(item => (recorded || item !== MASK) && isMaskedString(name, item)) && endsMasked(text, at + list[0].length, kind);
  }
  if (!text.startsWith(quote, at)) return false;
  const close = text.indexOf(quote, at + quote.length);
  return close > 0 && isMaskedString(name, text.slice(at + quote.length, close)) && endsMasked(text, close + quote.length, kind);
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
  judgeMasks(text, scan);
  for (const m of text.matchAll(MASKED_SCHEME)) {
    if (!endsMasked(text, m.index + m[0].length, 'credential')) scan.flag('credential behind the mask', text.slice(m.index, m.index + 60));
  }
  if (text.includes('eyJ')) judgeTokens(text, scan);
  for (const m of text.matchAll(FORM_SECRET)) {
    if (!m[2].startsWith(MASK) || !endsMasked(m[2], MASK.length, 'end')) scan.flag('form secret', m[0]);
  }
  judgeHeaderLines(text, scan);
  judgeMembers(text, scan, decoded, KTY_NAME.test(text));
}

/** A quoted kty name, its quotes plain or escaped, each letter as itself or as a \\u escape. */
const KTY_NAME = /\\?"(?:k|\\{1,2}u006[bB])(?:t|\\{1,2}u0074)(?:y|\\{1,2}u0079)\\?"/;

/**
 * The terminator check as one pass over every mask in `text`, whichever rule wrote it and also where no rule reads a
 * value (decision 3 on #425, implementation note): behind a mask, and any masks right behind it, the text ends or a
 * terminator stands. A letter, a digit or another character a credential is spelled with is the rest of one.
 */
function judgeMasks(text, scan) {
  for (let at = text.indexOf(MASK); at >= 0; at = text.indexOf(MASK, at)) {
    const from = at;
    at += MASK.length;
    while (text.startsWith(MASK, at)) at += MASK.length;
    if (!endsMasked(text, at, 'mask')) {
      scan.flag('text behind a mask', text.slice(from, from + 60));
      return;
    }
  }
}

/** Flags each credential header line in `text` whose value is not one the Redactor leaves. */
function judgeHeaderLines(text, scan) {
  for (const m of text.matchAll(HEADER_LINE)) {
    if (!keepsLine(m[1], m[2])) scan.flag('credential header line', m[0]);
  }
}

/**
 * Whether a credential header line's value is one the Redactor leaves: blank, the form it writes (also with the mask
 * it writes to the end of a text right behind it), or after an Authorization-style name a Bearer or Basic the scheme
 * rule reads as prose ("Bearer access token required").
 */
function keepsLine(name, value) {
  const mask = value.indexOf(MASK);
  if (value.trim() === '' || (mask >= 0 && isMaskedString(name, value.slice(0, mask + MASK.length))
    && endsMasked(value, mask + MASK.length, 'end'))) return true;
  if (!keepsScheme(name)) return false;
  SCHEME_CREDENTIAL.lastIndex = 0;
  const scheme = SCHEME_CREDENTIAL.exec(value);
  return scheme !== null && scheme.index === 0 && /^(?:bearer|basic)$/i.test(scheme[1]) && isProse(scheme[1], scheme[2], scheme[3]);
}

/**
 * Flags each quoted secret name in `text` whose value is not a form the Redactor writes at a strict value end; with
 * `jwk`, a JWK's private member names are secret too.
 */
function judgeMembers(text, scan, decoded, jwk, recorded = false, kind = 'value') {
  for (const m of text.matchAll(MEMBER_NAME)) {
    const name = m[2].replace(/\\{1,2}u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
    if ((isSecretName(name) || (jwk && JWK_PRIVATE_MEMBERS.has(name))) && !readsAsMasked(text, m.index + m[0].length, name, m[1], recorded, kind)) {
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
 * The leaks in a bundle file whose text is `text`. The file goes through the one path every recorded string goes
 * through ({@link judgeText}); the only difference is that in the file's own structure a credential header's value
 * may be a list of masked strings, as the workbench records a header's values.
 */
export function findFileLeaks(text) {
  return judged(scan => judgeText(text, scan, 0, true));
}

/** The leaks in `value`, a bundle file as JSON.parse reads it: {@link findFileLeaks} of the file written out again. */
export function findJsonLeaks(value) {
  return findFileLeaks(JSON.stringify(value));
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
