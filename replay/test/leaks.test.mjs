// Runs the shared redaction corpus (workbench-core/src/test/resources/redaction-corpus.json,
// also run through Redactor by RedactorCorpusTest) against the leak scanner.
// Needs no bundle: node --test replay/test/leaks.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { findJsonLeaks, findTextLeaks, scanWork } from './leaks.mjs';
import { build, generateCases, PIECE, placed } from './secret-cases.mjs';

const MASK = '[REDACTED]';

const corpus = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../workbench-core/src/test/resources/redaction-corpus.json', import.meta.url)), 'utf8'));

for (const e of corpus.text) {
  test(`flags secret: ${e.id} (${e.rule})`, () => {
    assert.ok(findTextLeaks(e.input).length > 0, `not flagged: ${e.input}`);
  });
}
for (const e of corpus.harmless) {
  test(`ignores harmless text: ${e.id} (${e.rule})`, () => {
    assert.deepEqual(findTextLeaks(e.input), []);
  });
}
for (const e of corpus.headers) {
  test(`flags sensitive header: ${e.name}`, () => {
    assert.equal(findJsonLeaks({ requestHeaders: { [e.name]: [e.value] } }).length, 1);
  });
}
for (const e of corpus.harmlessHeaders) {
  test(`ignores harmless header: ${e.name}`, () => {
    assert.deepEqual(findJsonLeaks({ requestHeaders: { [e.name]: [e.value] } }), []);
  });
}

// What Redactor used to leave behind for each case above is a leak to the scanner, which stays
// stricter than Redactor so it can catch the next such gap; what Redactor leaves now is not.
const leakedOutputs = {
  'Basic credential before a period': 'Received Authorization: Basic dXNlcjpwYXNz.',
  'credential suffix after the mask': 'Bearer [REDACTED]:SECRETPART',
  'form secret cut at a backslash': 'client_secret=[REDACTED]\\xyzTAIL&x=1',
  'embedded secret cut at an escaped quote': '{"result":"{\\"password\\":\\"[REDACTED]\\"ssTAIL\\"}"}',
  'secret object': '{"private_key":{"kty":"RSA","d":"PRIVATED"}}',
  'secret array': '{"access_token":["ARRSECRET"]}',
  'slash-escaped token read as prose': '{"error_description":"rejected Bearer EchoTok\\/TOKENTAIL+x\\/y=="}',
  'slash-escaped token tail after the mask': '{"error_description":"rejected Bearer [REDACTED]\\/TOKENTAIL"}',
};
for (const [name, text] of Object.entries(leakedOutputs)) {
  test(`flags what Redactor used to leave: ${name}`, () => {
    assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text}`);
  });
}
test('flags a secret object or array in parsed JSON', () => {
  assert.equal(findJsonLeaks({ responseBody: '{"private_key":{"d":"PRIVATED"}}' }).length, 1);
  assert.equal(findJsonLeaks({ details: { accessToken: ['ARRSECRET'] } }).length, 1);
});
test('accepts what Redactor leaves now', () => {
  for (const text of [
    'Received Authorization: Basic [REDACTED]',
    'client_secret=[REDACTED]&x=1',
    '{"body":"password=[REDACTED]\\nnext"}',
    '{"body":"grant_type=x&client_secret=[REDACTED]"}',
    '{"result":"{\\"password\\":\\"[REDACTED]\\",\\"user\\":\\"u\\"}"}',
    '{"result":"{\\"access_token\\":\\"[REDACTED]\\"',
    '{"private_key":"[REDACTED]","kid":"k1"}',
    '{"result":"{\\"private_key\\":\\"[REDACTED]\\",\\"kid\\":\\"k1\\"}"}',
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
});
test('accepts what Redactor leaves for a sensitive header line or JSON key (#261)', () => {
  for (const text of [
    'HTTP/1.1 401\nCookie: [REDACTED]\nContent-Length: 0',
    '  x-api-key:[REDACTED]\r\nAccept: */*',
    'Authorization: Bearer [REDACTED]',
    'Proxy-Authorization: [REDACTED]',
    '{"debug":"echo:\\nSet-Cookie: [REDACTED]\\nAccept: */*"}',
    '{"debug":"echo:\\nX-Auth-Token: [REDACTED]"}',
    '{"headers":{"X-Api-Key":"[REDACTED]","Cookie":"[REDACTED]","authorization":"Bearer [REDACTED]","Accept":"x"}}',
    '{"body":"{\\"Set-Cookie\\":\\"[REDACTED]\\"}"}',
    // A redacted body as a report serializes it: its escaped line breaks are escaped again.
    JSON.stringify({ responseBody: '{"debug":"echo:\\nCookie: [REDACTED]\\nAccept: */*"}' }),
    // What Redactor leaves for a header line in JSON embedded in a JSON string.
    '{"body":"{\\"m\\":\\"x\\\\nCookie: [REDACTED]\\\\nAccept: a\\"}"}',
    '{"body":"{\\"m\\":\\"x\\\\nCookie: [REDACTED]\\"}"}',
    '{"m":"x\\n\\tCookie: [REDACTED]\\nend"}',
    // A masked header line at the start of a JSON string; a header-named key is not a line.
    JSON.stringify({ responseBody: 'Cookie: [REDACTED]\nAccept: x' }),
    JSON.stringify({ responseBody: JSON.stringify({ responseBody: 'Authorization: Bearer [REDACTED]' }) }),
    '{"a":1,"Cookie":"[REDACTED]",\n"X-Api-Key": "[REDACTED]"}',
    '{"details":{"authorization":["SCRAM-SHA-256 [REDACTED]"]}}',
    // A tab after the colon, escaped when the text is quoted.
    JSON.stringify({ responseBody: 'HTTP/1.1 401\nCookie:\t[REDACTED]\nAccept: x' }),
    // redactHeaders and redactTree keep an empty header list.
    '{"requestHeaders":{"Cookie":[],"Authorization":[ ]}}',
    // redactTree keeps any scheme of an authorization list item.
    '{"details":{"authorization":["SCRAM-SHA-256 [REDACTED]"]}}',
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  assert.deepEqual(findJsonLeaks({ details: { authorization: ['Bearer [REDACTED]'], cookie: '[REDACTED]' } }), []);
  // A masked field in JSON embedded in a body, as a report serializes it: the closing quote is \\\".
  for (const field of [{ Cookie: '[REDACTED]' }, { authorization: 'Bearer [REDACTED]' }, { access_token: '[REDACTED]' }]) {
    const body = JSON.stringify({ debug: JSON.stringify(field) });
    assert.deepEqual(findTextLeaks(JSON.stringify({ responseBody: body })), [], body);
  }
});
test('accepts what Redactor leaves for a JWK, a Token or DPoP credential and a URL-encoded Bearer (#262)', () => {
  for (const text of [
    '{"kty":"RSA","n":"N1","e":"AQAB","d":"[REDACTED]","p":"[REDACTED]","oth":"[REDACTED]"}',
    '{"keys":[{"kty":"oct","k":"[REDACTED]"},\n {"d" : "[REDACTED]", "kty":"EC"}]}',
    '{"body":"{\\"kty\\":\\"RSA\\",\\"d\\":\\"[REDACTED]\\"}"}',
    JSON.stringify({ responseBody: '{"keys":[{"kty":"oct","k":"[REDACTED]"}]}' }),
    'payer echoed Token [REDACTED]',
    '{"error_description":"rejected DPoP [REDACTED]"}',
    'Authorization: Token [REDACTED]',
    'GET /cb?h=Authorization%3A%20Bearer [REDACTED]',
    'auth=Bearer [REDACTED]',
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  assert.deepEqual(findJsonLeaks({ jwk: { kty: 'RSA', n: 'N1', d: MASK } }), []);
});
test('accepts what Redactor leaves for a JWK nested two and three levels deep, and flags a leak there', () => {
  const nest = text => JSON.stringify({ body: text });
  for (const jwk of [
    '{"kty":"oct","k":"[REDACTED]"}',
    '{"kty":"RSA","n":"N1","d":"[REDACTED]","oth":"[REDACTED]"}',
    '{"d":"2026-11-03","k":[1,2]}',
  ]) {
    assert.deepEqual(findTextLeaks(nest(nest(jwk))), [], nest(nest(jwk)));
    assert.deepEqual(findTextLeaks(nest(nest(nest(jwk)))), [], nest(nest(nest(jwk))));
  }
  for (const jwk of ['{"kty":"oct","k":"LEAKED"}', '{"kty":"RSA","d":"[REDACTED]","p":"LEAKED"}', '{"kty":"RSA","oth":[{"r":"LEAKED"}]}']) {
    assert.ok(findTextLeaks(nest(nest(jwk))).length > 0, nest(nest(jwk)));
    assert.ok(findTextLeaks(nest(nest(nest(jwk)))).length > 0, nest(nest(nest(jwk))));
  }
});
test('reads embedded JSON spelled with unicode escapes (\\u0022, \\u005c, \\u0020, \\u003a), as Redactor does', () => {
  for (const text of [
    String.raw`{"body":"{\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\"[REDACTED]\"}"}`,
    String.raw`{"body":"{\u0022body\u0022:\u0022{\\u0022kty\\u0022:\\u0022RSA\\u0022,\\u0022d\\u0022:\\\"[REDACTED]\\\"}\u0022}"}`,
    String.raw`{"body":"{\"body\":\"{\u005C\"kty\u005C\":\u005C\"RSA\u005C\",\u005C\"d\u005C\":\\\"[REDACTED]\\\"}\"}"}`,
    String.raw`{"body":"{\u0022d\u0022:\u0022x\u0022,\u0022k\u0022:[1,2]}"}`,
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  for (const text of [
    String.raw`{"body":"{\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\u0022LEAKED\u0022}"}`,
    String.raw`{"body":"{\"kty\":\"oct\",\u0022k\u0022:\u0022LEAKED\u0022}"}`,
    String.raw`{"body":"{\"kty\":\"oct\",\"k\":\u0020\"LEAKED\"}"}`,
    String.raw`{"body":"{\"kty\":\"RSA\",\"d\"\u003A\"LEAKED\"}"}`,
    String.raw`{"body":"{\u0022body\u0022:\u0022{\\u0022kty\\u0022:\\u0022RSA\\u0022,\\u0022d\\u0022:\\u0022LEAKED\\u0022}\u0022}"}`,
  ]) {
    assert.ok(findTextLeaks(text).length > 0, text);
  }
});
test('reads unicode-escaped embedded JSON after prose, also in a report field', () => {
  const leaked = String.raw`{"body":"{\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\u0022LEAKED\u0022}"}`;
  const masked = String.raw`{"body":"{\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\"[REDACTED]\"}"}`;
  assert.ok(findTextLeaks(`evidence: ${leaked}`).length > 0);
  assert.ok(findTextLeaks(`evidence: ${leaked} (twice: ${leaked})`).length > 0);
  assert.ok(findJsonLeaks({ responseBody: `evidence: ${leaked}` }).length > 0);
  assert.deepEqual(findTextLeaks(`evidence: ${masked}`), []);
  assert.deepEqual(findJsonLeaks({ responseBody: `evidence: ${masked}` }), []);
});
test('reads JSON after prose in a parsed report string, whatever its escapes were', () => {
  assert.ok(findJsonLeaks({ evidence: 'payer said: {"kty":"oct","k":"LEAKED"}' }).length > 0);
  assert.ok(findTextLeaks(String.raw`{"evidence":"payer said: {\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\u0022LEAKED\u0022}"}`).length > 0);
  assert.deepEqual(findJsonLeaks({ evidence: 'payer said: {"kty":"oct","k":"[REDACTED]"}' }), []);
  assert.deepEqual(findTextLeaks(String.raw`{"evidence":"payer said: {\u0022kty\u0022:\u0022oct\u0022,\u0022k\u0022:\u0022[REDACTED]\u0022}"}`), []);
});
test('reads unicode-escaped embedded JSON that is cut off or repeats a member', () => {
  assert.ok(findTextLeaks(String.raw`{"body":"{\u0022kty\u0022:\u0022RSA\u0022,\u0022d\u0022:\u0022LEAKED`).length > 0);
  assert.ok(findJsonLeaks({ body: '{"kty":"RSA","d":"LEAKED' }).length > 0);
  assert.ok(findTextLeaks(String.raw`{"body":"{\u0022kty\u0022:\u0022RSA\u0022,\u0022d\u0022:\u0022LEAKED\u0022,\u0022d\u0022:\u0022[REDACTED]\u0022}"}`).length > 0);
  assert.ok(findJsonLeaks({ body: '{"kty":"RSA","d":"LEAKED","d":"[REDACTED]"}' }).length > 0);
});
test('treats a private member name as secret only in an object with its own kty', () => {
  for (const text of [
    '{"jwk":{"kty":"RSA","d":"[REDACTED]"},"data":{"d":"2026-11-04"}}',
    '{"data":{"d":"2026-11-04","items":[{"k":"v"}]},"jwk":{"kty":"oct","k":"[REDACTED]"}}',
    '{"kty":"RSA","meta":{"d":"keep"},"d":"[REDACTED]"}',
    '{"body":"{\\"jwk\\":{\\"kty\\":\\"RSA\\",\\"d\\":\\"[REDACTED]\\"},\\"data\\":{\\"d\\":\\"2026-11-04\\"}}"}',
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  for (const text of [
    '{"jwk":{"kty":"RSA","d":"LEAKED"},"data":{"d":"2026-11-04"}}',
    '{"data":{"x":1},"jwk":{"d":"LEAKED","kty":"RSA"}}',
    '{"body":"{\\"data\\":{\\"d\\":\\"x\\"},\\"jwk\\":{\\"kty\\":\\"RSA\\",\\"d\\":\\"LEAKED\\"}}"}',
  ]) {
    assert.ok(findTextLeaks(text).length > 0, text);
  }
});
test('scans unclosed brackets after a unicode escape in linear time', () => {
  const text = String.raw`{"body":"\u0041` + '['.repeat(200_000) + '"}';
  const start = performance.now();
  findTextLeaks(text);
  findJsonLeaks({ body: `x ${'['.repeat(200_000)}` });
  assert.ok(performance.now() - start < 3000, `took ${Math.round(performance.now() - start)} ms`);
});
test('scopes kty in linear time over many members', () => {
  const text = '{"kty":"oct",' + '"k":"[REDACTED]",'.repeat(32_000) + '"x":1}';
  const start = performance.now();
  assert.deepEqual(findTextLeaks(text), []);
  assert.ok(performance.now() - start < 3000, `took ${Math.round(performance.now() - start)} ms`);
});
test('reports escapes still unread after the levels Redactor reads, as Redactor masks them', () => {
  // masksEscapeChainsWithoutBlowingUp's 40-link chain: Redactor masks the string that holds it.
  const quote = String.raw`\u005c` + 'u005c'.repeat(40) + 'u0022';
  const jwk = `{${quote}kty${quote}:${quote}oct${quote},${quote}k${quote}:${quote}PRIVATECHAINVALUE${quote}}`;
  const text = `{"body":"${jwk}"}`;
  assert.ok(findTextLeaks(text).length > 0);
  assert.ok(findJsonLeaks(JSON.parse(text)).length > 0);
  assert.deepEqual(findTextLeaks('{"body":"[REDACTED]"}'), []);
});
test('scopes kty in a bounded number of passes, however many backslash counts the members use', () => {
  // Codex security round 2: each member quoted with a different number of backslashes after a kty.
  const fields = [];
  for (let run = 1; run <= 400; run++) {
    const quote = '\\'.repeat(run) + '"';
    fields.push(`${quote}k${quote}:"[REDACTED]"`);
  }
  const body = `{"kty":"oct",${fields.join(',')}}`;
  for (const text of [body, JSON.stringify({ responseBody: body })]) {
    scanWork.characters = 0;
    findTextLeaks(text);
    assert.ok(scanWork.characters <= 17 * text.length,
      `read ${scanWork.characters} characters of a ${text.length}-character text`);
  }
  scanWork.characters = 0;
  findJsonLeaks({ responseBody: body });
  assert.ok(scanWork.characters <= 17 * body.length, `read ${scanWork.characters}`);
  // A member at a count no serializer writes counts as a JWK member: its value must be the mask.
  assert.ok(findTextLeaks('{"kty":"oct",\\\\"k\\\\":"LEAKED"}').length > 0);
});
test('decodes a name escape only at a backslash count an escape has at its depth', () => {
  // An escaped backslash is not an escape: this name is the text \u006bty, not kty, so d is an ordinary field.
  const literal = String.raw`{"\\u006bty":"RSA","d":"2026-11-04"}`;
  assert.deepEqual(findTextLeaks(literal), []);
  assert.deepEqual(findTextLeaks(JSON.stringify({ responseBody: literal })), []);
  assert.deepEqual(findJsonLeaks({ responseBody: literal }), []);
  assert.deepEqual(findTextLeaks(String.raw`{"body":"{\"\\\\u006bty\":\"RSA\",\"d\":\"x\"}"}`), []);
  assert.ok(findTextLeaks(String.raw`{"\u006bty":"RSA","d":"LEAKED"}`).length > 0);
});
test('scopes kty in embedded JSON after its structure is decoded', () => {
  // The JWK closes on a brace the outer string spells as a unicode escape: the d after it is an ordinary field.
  const ok = String.raw`{"body":"{\"jwk\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"\u007D,\"d\":\"keep\"}"}`;
  assert.deepEqual(findTextLeaks(ok), []);
  assert.deepEqual(findTextLeaks(JSON.stringify({ report: ok })), []);
  assert.ok(findTextLeaks(String.raw`{"body":"{\"jwk\":{\"kty\":\"oct\"\u007D,\"d\":\"keep\",\"x\":{\"kty\":\"RSA\",\"d\":\"LEAKED\"}}"}`).length > 0);
});
// Codex security rounds 1-3 (#262), each with its report form and what Redactor leaves for it.
const reportForm = text => JSON.stringify({ responseBody: text });
const nestedIn = (text, levels) => {
  let out = text;
  for (let level = 0; level < levels; level++) out = JSON.stringify({ body: out });
  return out;
};
// findJsonLeaks reads JSON in a string field; prose credentials in one are left to findTextLeaks over the file.
const assertFlagged = (text, field = true) => {
  assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text.slice(0, 120)}`);
  assert.ok(findTextLeaks(reportForm(text)).length > 0, `report form not flagged: ${text.slice(0, 120)}`);
  if (field) assert.ok(findJsonLeaks({ responseBody: text }).length > 0, `field not flagged: ${text.slice(0, 120)}`);
};
const assertAccepted = text => {
  assert.deepEqual(findTextLeaks(text), [], text.slice(0, 120));
  assert.deepEqual(findTextLeaks(reportForm(text)), [], text.slice(0, 120));
  assert.deepEqual(findJsonLeaks({ responseBody: text }), [], text.slice(0, 120));
};
test('r1: a JWK nested two levels deep, and a short punctuation credential', () => {
  assertFlagged(nestedIn('{"kty":"oct","k":"FAKE_PRIVATE_KEY_293"}', 2));
  assertAccepted(nestedIn('{"kty":"oct","k":"[REDACTED]"}', 2));
  assertFlagged('Bearer -._~+/=', false);
  assertAccepted('Bearer [REDACTED]');
});
test('r3: a JWK nested 17 levels deep behind an unrelated unicode escape', () => {
  const prefix = String.raw`payer said \u0041: `;
  assertFlagged(prefix + nestedIn('{"kty":"oct","k":"FAKE_PRIVATE_KEY_293"}', 17));
  // Redactor masks whole the string that holds JSON nested past the levels it reads.
  assertAccepted(prefix + nestedIn('{"body":"[REDACTED]"}', 15));
  assertAccepted(prefix + nestedIn('{"kty":"oct","k":"[REDACTED]"}', 15));
  // 16 levels down is the last level read: a masked JWK there passes and an unmasked one does not. The report
  // that holds such a body adds a level, so there it is past the cap and fails closed.
  const masked16 = prefix + nestedIn('{"kty":"oct","k":"[REDACTED]"}', 16);
  assert.deepEqual(findTextLeaks(masked16), []);
  assert.deepEqual(findJsonLeaks({ responseBody: masked16 }), []);
  assert.deepEqual(findTextLeaks(reportForm(masked16)).map(l => l.check), ['JSON nested past 17 levels']);
  assertFlagged(prefix + nestedIn('{"kty":"oct","k":"FAKE_PRIVATE_KEY_293"}', 16));
});
test('r3: a stray quote in prose does not hide the JSON after it', () => {
  assertFlagged('evidence: 5" screen {"kty":"oct","k":"LEAKED"}');
  // What Redactor leaves for it.
  assertAccepted('evidence: 5" screen {"kty":"oct","k":"[REDACTED]"}');
});
test('r3: one long backslash run is scanned in linear work', () => {
  const body = JSON.stringify({ k: '[REDACTED]', padding: '\\'.repeat(16384) + 'x', kty: 'oct' });
  for (const text of [body, reportForm(body)]) {
    scanWork.characters = 0;
    assert.deepEqual(findTextLeaks(text), []);
    assert.ok(scanWork.characters <= 40 * text.length + 4096, `read ${scanWork.characters} of ${text.length}`);
  }
  assertFlagged(JSON.stringify({ k: 'LEAKED', padding: '\\'.repeat(16384) + 'x', kty: 'oct' }));
});
test('judges a value cut at a line break, a list of numbers, and a value a colon follows', () => {
  // A value cut off at a line break before a truncation note: Redactor masks it through to the end.
  assertFlagged('{"kty":"oct","k":"LEAKED\n[truncated at 1 MB]');
  assertAccepted('{"kty":"oct","k":"[REDACTED]"');
  // A number in a secret-named list is not a mask: Redactor masks the list whole.
  assertFlagged('payer said: {"client_secret":[12345678]}');
  assertFlagged('{"client_secret":["[REDACTED]",true]}');
  assertAccepted('payer said: {"client_secret":"[REDACTED]"}');
  // A value with a colon after it is still the member's value; Redactor masks it and keeps the colon.
  assertFlagged('{"kty":"oct","k":"LEAKED":0}');
  assertAccepted('{"kty":"oct","k":"[REDACTED]":0}');
});
test('reads JSON serialized into a member name', () => {
  assertFlagged('{"{\\"password\\":\\"LEAKED\\"}":1}');
  assertFlagged('{"{\\"kty\\":\\"oct\\",\\"k\\":\\"LEAKED\\"}":1}');
  // What Redactor leaves for each.
  assertAccepted('{"{\\"password\\":\\"[REDACTED]\\"}":1}');
  assertAccepted('{"{\\"kty\\":\\"oct\\",\\"k\\":\\"[REDACTED]\\"}":1}');
  // So is JSON in a value cut off at a line break, before a truncation note.
  assertFlagged('{"body":"{\\"password\\":\\"LEAKED\\"}\n[truncated at 1 MB]');
  assertAccepted('{"body":"{\\"password\\":\\"[REDACTED]\\"}\n[truncated at 1 MB]');
});
test('r4: a scalar does not swallow the member after it', () => {
  assertFlagged('{"x":0"password":"FAKE_SECRET_293"}');
  assertFlagged('{"kty":"oct","x":true"k":"FAKE_PRIVATE_KEY_293"}');
  assertFlagged('{"client_secret":[1"[REDACTED]",{"password":"FAKE_SECRET_293"}]}');
  // What Redactor leaves for it.
  assertAccepted('{"x":0"password":"[REDACTED]"}');
});
test('r4: a secret value with a raw line break in it is judged whole', () => {
  for (const line of ['\n', '\r']) {
    for (const prefix of ['', '[REDACTED]']) {
      assertFlagged(`{"kty":"oct","k":"${prefix}${line}FAKE_PRIVATE_KEY_293"}`);
      assertFlagged(`{"password":"${prefix}${line}FAKE_SECRET_293"}`);
    }
  }
  // What Redactor leaves for them, and for a value genuinely cut off by a truncation note.
  assertAccepted('{"kty":"oct","k":"[REDACTED]"}');
  assertAccepted('{"password":"[REDACTED]"}');
  assertFlagged('{"kty":"oct","k":"LEAKED\n[truncated at 1 MB]');
  assertAccepted('{"kty":"oct","k":"[REDACTED]"');
  assertAccepted('{"body":"{\\"password\\":\\"[REDACTED]\\"}\n[truncated at 1 MB]');
});
test('reads repeated scheme words, escaped header lines and token runs in linear work', () => {
  // The automated review on a09d112: Bearer+ repeated made the credential check read overlapping suffixes. The
  // escaped-header and eyJ- shapes had the same overlap (4x time per doubling on a09d112).
  const n = 200_000;
  const cases = [
    ['Bearer+'.repeat(n / 7), true],
    ['"' + '\\nCookie: a'.repeat(n / 11) + '"', true],
    ['"' + '\\nCookie: [REDACTED]'.repeat(n / 20) + '"', false],
    ['eyJ-'.repeat(n / 4), false],
    ['token '.repeat(n / 6) + 'DPoP PHNhbWw6QXNz', true],
    // The automated review on 85acec5: each dotted run searched the rest of the text for eyJ.
    ['a.a.a '.repeat(n / 6), false],
    ['a.a.a '.repeat(n / 12) + 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.SIG', true],
  ];
  for (const [text, leaks] of cases) {
    scanWork.characters = 0;
    assert.equal(findTextLeaks(text).length > 0, leaks, text.slice(0, 40));
    assert.ok(scanWork.characters <= 40 * text.length + 4096, `read ${scanWork.characters} of ${text.length}`);
  }
});
test('compares a decoded member name exactly: an extension member with a backslash is not a private one', () => {
  // The automated review on 69a1e64: "\\k" is the name \k, which Redactor keeps.
  assertAccepted('{"kty":"oct","\\\\k":"keep","k":"[REDACTED]"}');
  assertAccepted('{"kty":"oct","k\\\\":"keep","d\\"":"keep","k":"[REDACTED]"}');
  assertFlagged('{"kty":"oct","\\\\k":"keep","k":"LEAKED"}');
  // A name whose quote has a stray backslash before it, outside any string, is malformed and still read as one.
  assert.ok(findTextLeaks('{"kty":"oct",\\\\"k\\\\":"LEAKED"}').length > 0);
});
test('r5: a key block starting in a JWK member, and a chain past the cap in a unicode-quoted string', () => {
  // Redactor's input is flagged in every form, and what it leaves for it passes.
  assertFlagged('{"kty":"RSA","d":"-----BEGIN PRIVATE KEY-----","note":"FAKEKEYMATERIAL_293\\n-----END PRIVATE KEY-----"}');
  assertFlagged('{"kty":"RSA","d":"-----BEGIN PGP PRIVATE KEY BLOCK-----","note":"FAKEKEYMATERIAL_293"}');
  assertAccepted('{"kty":"RSA","d":"[REDACTED]""}');
  assertAccepted('{"kty":"RSA","d":"[REDACTED]"');
  const quote = String.raw`\u005c` + 'u005c'.repeat(40) + 'u0022';
  const jwk = `{${quote}kty${quote}:${quote}oct${quote},${quote}k${quote}:${quote}PRIVATECHAINVALUE${quote}}`;
  assertFlagged(String.raw`\u0022` + jwk + String.raw`\u0022`);
  assertFlagged(String.raw`{\u0022body\u0022:\u0022` + jwk + String.raw`\u0022}`);
  assertAccepted('[REDACTED]');
});
test('treats kty as a JWK member only in a JSON object, not in loose text or an array (#262)', () => {
  // The automated review on 4927c5c: Redactor keeps each of these (RedactorTest.leavesJwkMemberNamesOutsideAJwkAlone).
  const loose = '"kty": "RSA", "d": "dimension"';
  assert.deepEqual(findTextLeaks(JSON.stringify({ responseBody: loose })), [], "the review's report form");
  for (const kept of [loose, '"kty": "RSA", "d": "x"', '["kty": "RSA", "d": "x"]', '["kty": 1, "kty": 2, "d": "x"]',
    JSON.stringify({ body: loose })]) {
    assertAccepted(kept);
  }
  // A real JWK in loose text, beside loose kty text, in an array or cut off, is still judged: flagged as it came,
  // accepted as Redactor leaves it (each masked form is Redactor's output for the leaked one), also embedded.
  const cases = [
    ['note "kty": "RSA", "d": "dimension" and {"kty":"RSA","d":"FAKE_LOOSE_JWK_D"} trailing',
      'note "kty": "RSA", "d": "dimension" and {"kty":"RSA","d":"[REDACTED]"} trailing'],
    ['"kty": "RSA", "keys": [{"kty":"oct","k":"FAKE_LOOSE_JWK_K"}], "d": "dimension"',
      '"kty": "RSA", "keys": [{"kty":"oct","k":"[REDACTED]"}], "d": "dimension"'],
    ['payer echoed {"kty":"RSA","n":"N1","d":"FAKE_LOOSE_JWK_D"', 'payer echoed {"kty":"RSA","n":"N1","d":"[REDACTED]"'],
  ];
  for (const [leaked, masked] of [...cases, ...cases.map(([l, m]) => [JSON.stringify({ body: l }), JSON.stringify({ body: m })])]) {
    assertFlagged(leaked);
    assertAccepted(masked);
  }
});
test('flags member syntax inside a secret-named array (#262)', () => {
  // The automated review on 79ce506: in ["x":"LEAKED"] no list item is read ("x" is a name), so the empty list passed
  // as masked. Redactor masks the array whole; each masked form is its output for the leaked one, also embedded.
  const cases = [
    ['{"client_secret":["x":"LEAKED"]}', '{"client_secret":"[REDACTED]"}'],
    ['{"password":["a","x":"LEAKED"]}', '{"password":"[REDACTED]"}'],
    ['{"kty":"oct","k":["x":"LEAKED"]}', '{"kty":"oct","k":"[REDACTED]"}'],
  ];
  for (const [leaked, masked] of [...cases, ...cases.map(([l, m]) => [JSON.stringify({ body: l }), JSON.stringify({ body: m })])]) {
    assertFlagged(leaked);
    assertAccepted(masked);
  }
  // Member syntax in an array that is no secret's stays as Redactor keeps it.
  assertAccepted('{"note":["x":"y"]}');
});
test('r7: flags a private member Redactor masks once finding the JWKs spends its budget (#262)', () => {
  // Codex round 7, finding 1: repeated kty syntax makes Redactor's JWK search spend its 4n + 1024 budget, and then it
  // masks every private member name, in an object or not. Each masked form is Redactor's output for the leaked one
  // (RedactorTest.masksEveryPrivateMemberOnceFindingTheJwksSpendsItsBudget).
  const d = '"d":"FAKE_PRIVATE_KEY_293"';
  const masked = '"d":"[REDACTED]"';
  const loose = '"kty":"'.repeat(63);
  const spelled = '"\\u006bty":"'.repeat(63);
  const cases = [
    [loose + d, loose + masked],
    [`[${loose}${d}]`, `[${loose}${masked}]`],
    [spelled + d, spelled + masked],
  ];
  // Every character escaped as \u, once and twice over: kty is read one and two levels down.
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const body = text => `{"body":"${text}"}`;
  const quote = '\\u0022';
  const once = [body(escaped(loose + d)), body(escaped(loose + '"d":') + quote + MASK + quote)];
  const twice = [body(escaped(once[0])),
    body(escaped(`{"body":"${escaped(loose + '"d":')}`) + escaped(quote) + MASK + escaped(quote) + escaped('"}'))];
  // Text copied from inside such strings, with no bracket or quote left bare.
  const copied = [escaped(escaped(loose + d)), escaped(escaped(loose + '"d":')) + escaped(quote) + MASK + escaped(quote)];
  for (const [leaked, kept] of [...cases, ...cases.map(([l, m]) => [nestedIn(l, 1), nestedIn(m, 1)]), once, twice, copied]) {
    assertFlagged(leaked);
    assertAccepted(kept);
  }
});
test('r9: flags the twice-escaped copied form when quoted prose follows it (#262)', () => {
  // Codex narrow check at 3c47acc, finding 2: the bare quotes of the prose after the copied r7 form made the whole-text
  // decode fail, so the 63 kty names a level down were never counted. Redactor reads that view and masks d; the masked
  // form is its output (RedactorTest.masksTheTwiceEscapedCopiedFormWithQuotedProseAfterIt).
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const loose = '"kty":"'.repeat(63);
  const quote = '\\u0022';
  const prose = ' note: "ok"';
  assertFlagged(escaped(escaped(loose + '"d":"FAKE_PRIVATE_KEY_293"')) + prose);
  assertAccepted(escaped(escaped(loose + '"d":')) + escaped(quote) + MASK + escaped(quote) + prose);
});
test('r9: flags the twice-escaped copied form after a stray quote whose string JSON cannot read (#262)', () => {
  // The stray quote opens a string to the end of the text, and its \' escape makes JSON.parse reject it, so neither the
  // string nor the text around it was decoded. Redactor still reads the view below and masks d; the masked form is its
  // output (RedactorTest.masksTheTwiceEscapedCopiedFormWithQuotedProseAfterIt).
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const loose = '"kty":"'.repeat(63);
  const quote = '\\u0022';
  for (const [before, after] of [["he said \"don\\'t ", ''], ["he said \"don\\'t ", ' note: "ok"']]) {
    assertFlagged(before + escaped(escaped(loose + '"d":"FAKE_PRIVATE_KEY_293"')) + after);
    assertAccepted(before + escaped(escaped(loose + '"d":')) + escaped(quote) + MASK + escaped(quote) + after);
  }
});
test('flags the twice-escaped copied form after a stray quote and a raw line break (#342)', () => {
  // #293 round-9 follow-up: the stray quote's string ran through the raw line break to the end of the text and read as
  // JSON, so the loose decode left it to the JSON scan, which ends a string that is no member's value at a raw line break
  // and does not decode the bare text after it. The 63 kty names a level down were never counted. Redactor masks d; each
  // masked form is its output (RedactorTest.masksTheTwiceEscapedCopiedFormAfterAStrayQuoteAndARawLineBreak).
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const loose = '"kty":"'.repeat(63);
  const quote = '\\u0022';
  for (const before of ['he said "\n', 'he said "\r\n', 'he said "\r', '"\n', 'he said "\\\n', 'he said "\\\r\n']) {
    for (const after of ['', ' note: "ok"']) {
      assertFlagged(before + escaped(escaped(loose + '"d":"FAKE_PRIVATE_KEY_342"')) + after);
      assertAccepted(before + escaped(escaped(loose + '"d":')) + escaped(quote) + MASK + escaped(quote) + after);
    }
  }
});
test('flags an escaped JWK after a stray quote and a raw line break (#342)', () => {
  // The same gap without the budget: the escapes after the line break were never decoded, so a single JWK copied with
  // every character escaped hid its private member. Each masked form is Redactor's output
  // (RedactorTest.masksAnEscapedJwkAfterAStrayQuoteAndARawLineBreak).
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  for (const before of ['he said "\n', 'he said "\r\n']) {
    assertFlagged(before + escaped('{"kty":"oct","k":"FAKE_JWK_K_342"}'));
    assertAccepted(before + escaped('{"kty":"oct","k":') + escaped('"') + MASK + escaped('"}'));
  }
});
test('flags a copied JWK with mixed quote escapes after a stray quote and a raw line break (#342)', () => {
  // Automated review on 925a782: kty quoted with \u0022 and k with \" (or the other way round). scanJson reads the
  // \" literals and the loose decode reads the rest apart from them, so neither view held kty and k in one object. Each
  // masked form is Redactor's output (RedactorTest.masksACopiedJwkWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak).
  const u = '\\u0022';
  const b = '\\"';
  const jwk = (kty, k, value) => `{${kty}kty${kty}:${kty}oct${kty},${k}k${k}:${k}${value}${k}}`;
  const forms = [
    value => jwk(u, b, value),
    value => jwk(b, u, value),
    value => `{${u}kty${u}:${b}oct${b},${b}k${b}:${b}${value}${b}}`,
    value => `{${b}kty${b}:${u}oct${u},${b}k${b}:${b}${value}${b}}`,
  ];
  for (const before of ['he said "\n', 'he said "\r\n', '"\n', '"\r\n']) {
    // The stray quote's string runs to the end of the text, or to a closing quote after the copy.
    for (const after of ['', '"', '" and "x"']) {
      for (const form of forms) {
        assertFlagged(before + form('FAKE_JWK_K_342') + after);
        assertAccepted(before + form(MASK) + after);
      }
    }
  }
});
test('accepts a loose kty in a copied value with mixed quote escapes after a stray quote and a raw line break (#342)', () => {
  // Automated review on c4ffeef: the value quoted with \" holds a loose kty and d quoted with \u0022. Reading the
  // stray quote's string whole decodes both at once, {"body":""kty":"RSA","d":"dimension""}, where the kty name opens on
  // the quote that closed "": no JWK, as Redactor leaves the text
  // (RedactorTest.keepsALooseKtyInACopiedValueWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak). Automated
  // review on 39dd7ff: so do members before the kty ({"body":""a":0,"kty":...}): an odd number of quotes lies between
  // the object's open bracket and the name.
  const u = '\\u0022';
  const b = '\\"';
  const before = ['', `${u}a${u}:0,`, `${u}a${u}:0,${u}b${u}:${u}x${u},`, `${u}a${u}:{${u}x${u}:1},`, `${u}a${u}:[1,${u}y${u}],`];
  for (const lb of ['\n', '\r\n']) {
    for (const members of before) {
      assertAccepted(`he said "${lb}{${b}body${b}:${b}${members}${u}kty${u}:${u}RSA${u},${u}d${u}:${u}dimension${u}${b}}`);
    }
  }
});
test('flags a copied JWK with mixed quote escapes after an escaped quote in a value, past a raw line break (#342)', () => {
  // Reading the stray quote's string whole, a kty name makes a JWK only with an even number of quotes between its
  // object's open bracket and its own; a quote a backslash escapes ("a\"b") is not one of them. Each masked form is
  // Redactor's output (RedactorTest.masksACopiedJwkWithMixedQuoteEscapesAfterAnEscapedQuoteInAValue).
  const u = '\\u0022';
  const b = '\\"';
  const escapedQuote = '\\\\\\"';
  const forms = [
    k => `{${u}note${u}:${u}a${escapedQuote}b${u},${b}kty${b}:${b}oct${b},${b}k${b}:${b}${k}${b}}`,
    k => `{${b}note${b}:${b}a${escapedQuote}b${b},${u}kty${u}:${u}oct${u},${b}k${b}:${b}${k}${b}}`,
  ];
  for (const lb of ['\n', '\r\n']) {
    for (const form of forms) {
      assertFlagged(`he said "${lb}${form('FAKE_JWK_K_342')}`);
      assertAccepted(`he said "${lb}${form(MASK)}`);
    }
  }
});
test('accepts a kty in a copied value read whole that opens no member after a stray quote and a raw line break (#342)', () => {
  // Automated review on 0ab5aeb: reading the stray quote's string whole, a kty name with no comma or open bracket before
  // it ({"x":0 "kty":...}) made a JWK, though Redactor counts as a member name only the first string after { or , and
  // leaves these as they are (RedactorTest.keepsAKtyThatOpensNoMemberInACopiedValueAfterAStrayQuote). A name after a
  // comma still makes one, also with other text between them, as Redactor reads it.
  const b = '\\"';
  const form = (mid, d) => `{${b}x${b}:${mid}${b}kty${b}:${b}RSA${b},${b}d${b}:${b}${d}${b}}`;
  for (const lb of ['\n', '\r\n']) {
    for (const mid of ['0 ', `${b}a${b} `, `{${b}y${b}:1} `, '[1] ']) {
      assertAccepted(`he said "${lb}${form(mid, 'dimension')}`);
    }
    for (const mid of ['0,', '0 , ', '0, x ', `{${b}y${b}:1},`, '[1],']) {
      assertFlagged(`he said "${lb}${form(mid, 'FAKE_PRIVATE_KEY_342')}`);
      assertAccepted(`he said "${lb}${form(mid, MASK)}`);
    }
  }
});
test('accepts a kty that opens no member in an escaped copy after a stray quote and a raw line break (#342)', () => {
  // Automated review on 380cf7c: with every quote escaped (\u0022, \\u0022, or the copy escaped twice over), the text
  // after the line break is read as an unread span, not a string read whole, and made a JWK of {"x":0 "kty":...}. Redactor
  // leaves it as it is (RedactorTest.keepsAKtyThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote) and masks d after a comma.
  const encodings = [
    text => text.replaceAll('"', '\\u0022'),
    text => text.replaceAll('"', '\\\\u0022'),
    text => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1),
    // The JWK as a string value in the copy: a literal read in such a view is no view main reads either.
    text => `{\\u0022body\\u0022:\\u0022${text.replaceAll('"', '\\\\u0022')}\\u0022}`,
  ];
  const form = (mid, d) => `{"x":${mid}"kty":"RSA","d":"${d}"}`;
  for (const lb of ['\n', '\r\n']) {
    for (const encode of encodings) {
      for (const mid of ['0 ', '"a" ', '{"y":1} ', '[1] ']) {
        assertAccepted(`he said "${lb}${encode(form(mid, 'dimension'))}`);
      }
      for (const mid of ['0,', '0, x ']) {
        assertFlagged(`he said "${lb}${encode(form(mid, 'FAKE_PRIVATE_KEY_342'))}`);
        assertAccepted(`he said "${lb}${encode(form(mid, MASK))}`);
      }
    }
  }
});
test('accepts a kty after an odd number of quotes in an escaped copy after a stray quote and a raw line break (#342)', () => {
  // Automated review on 9a3e247: with every quote escaped, the text after the line break is read as an unread span,
  // where a kty name made a JWK whatever the quotes before it ({""a":0,"kty":...}). Redactor, reading back from the
  // name, finds the object's open bracket inside a string and leaves these as they are
  // (RedactorTest.keepsAKtyAfterAnOddNumberOfQuotesInAnEscapedCopyAfterAStrayQuote); with an even number it masks d.
  const encodings = [
    text => text.replaceAll('"', '\\u0022'),
    text => text.replaceAll('"', '\\\\u0022'),
    text => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1),
  ];
  const form = (before, d) => `{${before}"kty":"RSA","d":"${d}"}`;
  for (const lb of ['\n', '\r\n']) {
    for (const encode of encodings) {
      for (const before of ['""a":0,', '"a":"b"c",']) {
        assertAccepted(`he said "${lb}${encode(form(before, 'dimension'))}`);
      }
      for (const before of ['"a":0,', '']) {
        assertFlagged(`he said "${lb}${encode(form(before, 'FAKE_PRIVATE_KEY_342'))}`);
        assertAccepted(`he said "${lb}${encode(form(before, MASK))}`);
      }
    }
  }
});
test('accepts a private member that opens no member in an escaped copy after a stray quote and a raw line break (#342)', () => {
  // Automated review on fa4fd1d: in a view main does not read, a private member name with no comma before it
  // ({"kty":"RSA","x":0 "d":...}) was judged as the JWK's own. Redactor masks only the JWK's member names, the first
  // string after { or a comma, and leaves these as they are
  // (RedactorTest.keepsAPrivateMemberThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote); after a comma it masks d.
  const encodings = [
    text => text.replaceAll('"', '\\u0022'),
    text => text.replaceAll('"', '\\\\u0022'),
    text => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1),
  ];
  const form = (mid, d) => `{"kty":"RSA","x":${mid}"d":"${d}"}`;
  for (const lb of ['\n', '\r\n']) {
    for (const encode of encodings) {
      // Automated review on 223512b: nor after a value that leaves an odd number of quotes before the name.
      for (const mid of ['0 ', '"a" ', '{"y":1} ', '[1] ', '""a":0,', '"b"c",']) {
        assertAccepted(`he said "${lb}${encode(form(mid, 'dimension'))}`);
      }
      for (const mid of ['0,', '0, y ', '[1],', '"b"c"",']) {
        assertFlagged(`he said "${lb}${encode(form(mid, 'FAKE_PRIVATE_KEY_342'))}`);
        assertAccepted(`he said "${lb}${encode(form(mid, MASK))}`);
      }
    }
  }
});
test('reads JWKs in an escaped copy after a stray quote and a raw line break as Redactor finds them (#342)', () => {
  // Automated review on 65e1e7f, finding 1: reading back from kty, Redactor takes the open bracket inside "{" as the
  // object's, so the members after kty are a JWK's and d is masked; the scanner's quote-count check missed it. Finding 2:
  // after "d"::, Redactor masks nothing, but the scanner judged the second colon as d's value. In views main does not
  // read, jwkLeaks now finds JWKs and their members as Redactor's search does
  // (RedactorTest.readsJwksInAnEscapedCopyAfterAStrayQuoteAsItsSearchFindsThem).
  const encodings = [
    text => text.replaceAll('"', '\\u0022'),
    text => text.replaceAll('"', '\\\\u0022'),
    text => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1),
  ];
  for (const lb of ['\n', '\r\n']) {
    for (const encode of encodings) {
      for (const before of ['"{":""a":0,', '"[":""a":0,"b":{', '"a":"{",']) {
        const form = d => `he said "${lb}${encode(`{${before}"kty":"RSA","d":"${d}"}`)}`;
        assertFlagged(form('FAKE_PRIVATE_KEY_342'));
        assertAccepted(form(MASK));
      }
      assertAccepted(`he said "${lb}${encode('{"kty":"RSA","d"::"dimension"}')}`);
    }
  }
});
test('reads a private member value through its line breaks, and only ASCII whitespace around a colon, as Redactor does (#342)', () => {
  // Automated review on 7050fef: jwkLeaks stopped a value at a line break, so a k that starts with one read as empty
  // and passed, though Redactor reads it to its closing quote and masks it. And JavaScript's \\s took a no-break space
  // around a colon, which Java's does not, so Redactor keeps such a k and the scanner flagged it
  // (RedactorTest.readsAPrivateMemberValueThroughItsLineBreaksAndOnlyAsciiWhitespaceAroundAColon).
  const encodings = [text => text.replaceAll('"', '\\u0022'), text => text.replaceAll('"', '\\\\u0022')];
  for (const lb of ['\n', '\r\n']) {
    for (const encode of encodings) {
      for (const value of ['\\nTAIL', '\\r\\nTAIL', '\\n']) {
        assertFlagged(`he said "${lb}${encode(`{"kty":"oct","k":"${value}"}`)}`);
      }
      assertAccepted(`he said "${lb}${encode('{"kty":"oct","k":"[REDACTED]"}')}`);
      for (const space of ['\u00a0', '\u2003', '\u3000']) {
        for (const form of [`{"kty"${space}:"oct","k":"dimension"}`, `{"kty":"oct","k"${space}:"dimension"}`, `{"kty":"oct","k":${space}"dimension"}`]) {
          assertAccepted(`he said "${lb}${encode(form)}`);
        }
      }
    }
  }
});
test('flags a JWK copied after two stray quotes and raw line breaks, and ends a value at a backslash before a line break (#342)', () => {
  // Automated review on 5173e8e, finding 1: the two stray quotes pair in the loose decode, so the copy after the second
  // line break was in no string left out, and no view decoded it; main misses it too, and Redactor masks k. Finding 2:
  // Redactor ends a value at a backslash before a line break (its escape takes any character but a line break), so a
  // mask followed by one is a mask, and the scanner flagged it
  // (RedactorTest.masksAJwkCopiedAfterTwoStrayQuotesAndEndsAValueAtABackslashBeforeALineBreak).
  const copy = k => JSON.stringify(`{"kty":"oct","k":"${k}"}`).slice(1, -1);
  for (const lb of ['\n', '\r\n']) {
    for (const before of [`he said "${lb}he said "${lb}`, `he said "${lb}x"${lb}more${lb}`, `"${lb}"${lb}`]) {
      assertFlagged(before + copy('FAKE_JWK_K_342'));
      assertAccepted(before + copy(MASK));
    }
    assertAccepted(`he said "${lb}${JSON.stringify(`{"kty":"oct","k":"[REDACTED]\\${lb}TAIL"}`).slice(1, -1)}`);
  }
});
test('flags a copied value after a backslash and a raw Unicode line break, and reads no \\f escape as whitespace (#342)', () => {
  // Automated review on e2487e1, finding 1: a copied value that starts with a backslash and a raw U+0085, U+2028 or
  // U+2029 is an escaped backslash and a raw character in the text Redactor reads, so it masks the whole value, and the
  // scanner cut the value there and accepted it. Finding 3: Redactor's whitespace in an escaped copy is a raw one or an
  // escaped line break or tab, so with a \f escape around a colon it finds no member and keeps the text; the scanner
  // decoded the escape to whitespace and flagged it. A \u000c Redactor does read as whitespace
  // (RedactorTest.masksACopiedValueAfterABackslashAndARawUnicodeLineBreakAndReadsNoFormFeedEscapeAsWhitespace).
  for (const lb of ['\n', '\r\n']) {
    for (const brk of ['\u0085', '\u2028', '\u2029']) {
      assertFlagged(`he said "${lb}${JSON.stringify(`{"kty":"oct","k":"\\${brk}TAIL"}`).slice(1, -1)}`);
      assertFlagged(`he said "${lb}${JSON.stringify(`{"kty":"oct","k":"${MASK}\\${brk}TAIL"}`).slice(1, -1)}`);
    }
    for (const value of ['true', '1', '{}', '\\"FAKE_JWK_K_342\\"']) {
      assertAccepted(`he said "${lb}{\\"kty\\":\\"oct\\",\\"k\\":\\f${value}}`);
      assertAccepted(`he said "${lb}{\\"kty\\":\\"oct\\",\\"k\\"\\f:${value}}`);
      assertAccepted(`he said "${lb}{\\"kty\\"\\f:\\"oct\\",\\"k\\":${value}}`);
      assertFlagged(`he said "${lb}{\\"kty\\":\\"oct\\",\\"k\\":\\u000c${value}}`);
      assertFlagged(`he said "${lb}{\\"kty\\":\\"oct\\",\\"k\\":\\n${value}}`);
    }
  }
});
test('reads past a line break spelled as a \\u escape in a value, and flags a copy after a stray string paired with the next quote (#342)', () => {
  // Automated review on 4175db6, finding 1: Redactor ends a value at a backslash before a line break only where the text
  // spells that line break as an \n or \r escape; spelled as a \u escape (\\u000a, \\\u0085) it reads on and masks
  // the whole value, and the scanner cut the value there and accepted it. A \ before an \n escape Redactor ends at,
  // so that mask stays accepted. Finding 2: after "<line break>","body": the loose decode paired the stray quote with the
  // next one, so a copy whose quotes are all \" was in no string, and nothing decoded it; main misses it too
  // (RedactorTest.readsPastALineBreakSpelledAsAUnicodeEscapeInAValueAndMasksACopyAfterAPairedStrayString).
  const u = '\\u0022';
  const b = '\\"';
  const jwk = (q, k) => `{${q}kty${q}:${q}oct${q},${q}k${q}:${q}${k}${q}}`;
  for (const lb of ['\n', '\r\n']) {
    for (const q of [u, b]) {
      for (const brk of ['\\u000a', '\\u000d', '\\u0085', '\\u2028', '\\u2029']) {
        assertFlagged(`he said "${lb}${jwk(q, `\\u005c${brk}TAIL`)}`);
        assertFlagged(`he said "${lb}${jwk(q, `${MASK}\\u005c${brk}TAIL`)}`);
        assertFlagged(`he said "${lb}${jwk(q, `${MASK}\\\\${brk}TAIL`)}`);
      }
      assertAccepted(`he said "${lb}${jwk(q, `${MASK}\\u005c\\nTAIL`)}`);
    }
    for (const before of [`"${lb}","body":`, `"${lb}","b":1,"body":`, `x"${lb}","body":`]) {
      assertFlagged(before + jwk(b, 'FAKE_JWK_K_342'));
      assertAccepted(before + jwk(b, MASK));
    }
  }
});
test('flags a copy cut off in half an escape at the end of the text, and reads a nest of paired stray strings within the scan budget (#342)', () => {
  // Automated review on 5ca573a, finding 1: a lone backslash or a \u with fewer than four hex digits at the end made
  // the copy one JSON could not read, so its \" escapes were kept and no view held the JWK; Redactor masks k. Finding
  // 2: a masked JWK copied three times after "<line break>"<line break> spent the budget (37,564 against 30,056 with a
  // 500-character pad): the text between strings and the text after a cut string were both read for the same copy.
  // Main accepts it, and Redactor keeps it and masks k
  // (RedactorTest.masksACopyCutOffInHalfAnEscapeAndANestOfPairedStrayStrings).
  const copy = k => JSON.stringify(`{"kty":"oct","k":"${k}"}`).slice(1, -1);
  for (const lb of ['\n', '\r\n']) {
    for (const tail of ['\\', '\\u0', '\\u00', '\\u002', '\\\\\\']) {
      assertFlagged(`he said "${lb}${copy('FAKE_JWK_K_342')}${tail}`);
      assertAccepted(`he said "${lb}${copy(MASK)}${tail}`);
    }
    const nest = (k, pad) => {
      let text = `{"kty":"oct","k":"${k}","pad":"${'x'.repeat(pad)}"}`;
      for (let i = 0; i < 3; i++) text = `"${lb}"${lb}${JSON.stringify(text).slice(1, -1)}`;
      return text;
    };
    for (const pad of [500, 2000]) {
      assertAccepted(nest(MASK, pad));
      assertFlagged(nest('FAKE_JWK_K_342', pad));
    }
    // With a 10,000-character pad the report form, one level deeper, fails closed, as on 4175db6 (accepted, row 2x).
    assert.deepEqual(findTextLeaks(nest(MASK, 10000)), []);
    // 57.9n on 5ca573a, 40.6n on 4175db6.
    const masked = nest(MASK, 2000);
    scanWork.characters = 0;
    findTextLeaks(masked);
    assert.ok(scanWork.characters <= 41 * masked.length, `read ${scanWork.characters} of ${masked.length} characters`);
  }
});
test('flags a JWK private member whose opening quote is escaped one level more than the copy around it (#342)', () => {
  // Automated review on 32194d8, finding 1: in a JWK copied after a stray quote and a raw line break, a member written
  // \"k" inside the object, so escaped once more in the copy, kept an odd run of backslashes before its opening quote,
  // and the scanner skipped it; Redactor matches the field from the last backslash before its quote and masks it. Main
  // misses it too (RedactorTest.masksAJwkPrivateMemberWhoseOpeningQuoteIsEscapedOneLevelMore).
  const forms = [
    v => `{"kty":"oct",\\"k":"${v}"}`,
    v => `{"kty":"oct", \\"d":"${v}"}`,
    v => `{"kty":"RSA","n":"AQAB",\\"d":"${v}",\\"p":"${v}"}`,
  ];
  for (const lb of ['\n', '\r\n']) {
    for (const form of forms) {
      assertFlagged(`he said "${lb}${JSON.stringify(form('FAKE_JWK_K_342')).slice(1, -1)}`);
      assertAccepted(`he said "${lb}${JSON.stringify(form(MASK)).slice(1, -1)}`);
    }
  }
});
test('flags a copy that ends in a malformed \\u escape, a \\u with fewer than four hex digits and then a letter (#342)', () => {
  // Automated review on 92f3ad6: after a stray quote and a raw line break, an escaped JWK or secret field followed at the
  // end of the text by \uZ, \u0Z or \u00G could not be parsed, so its \" escapes were kept and no view held the
  // member; Redactor masks it. Main misses it too
  // (RedactorTest.masksACopyThatEndsInAMalformedUnicodeEscape).
  const copy = text => JSON.stringify(text).slice(1, -1);
  for (const lb of ['\n', '\r\n']) {
    for (const tail of ['\\uZ', '\\u0Z', '\\u00G']) {
      for (const form of [v => `{"kty":"oct","k":"${v}"}`, v => `{"password":"${v}"}`]) {
        assertFlagged(`he said "${lb}${copy(form('FAKE_JWK_K_342'))}${tail}`);
        assertAccepted(`he said "${lb}${copy(form(MASK))}${tail}`);
      }
    }
  }
});
test('reads a \\f escape where the text spells it after a malformed \\u escape is repaired (#342)', () => {
  // Automated review on a7d0f8f: after a stray quote and a raw line break, a malformed \uZ, \u0Z or \u00G before an
  // escaped JWK lost its backslash for JSON to read the copy, but the decoded view's offsets were still those of the text
  // before the repair, one character off past it. So the check of a \f escape around a colon read the wrong character
  // and flagged a member Redactor does not find (RedactorTest.readsAFormFeedEscapeAfterARepairedMalformedUnicodeEscape).
  const q = '\\"';
  for (const lb of ['\n', '\r\n']) {
    for (const pre of ['\\uZ', '\\u0Z', '\\u00G']) {
      for (const value of ['true', `${q}FAKE_JWK_K_342${q}`]) {
        assertAccepted(`he said "${lb}${pre}{${q}kty${q}:${q}oct${q},${q}k${q}:\\f${value}}`);
        assertAccepted(`he said "${lb}${pre}{${q}kty${q}\\f:${q}oct${q},${q}k${q}:${value}}`);
      }
      assertFlagged(`he said "${lb}${pre}{${q}kty${q}:${q}oct${q},${q}k${q}:${q}FAKE_JWK_K_342${q}}`);
      assertAccepted(`he said "${lb}${pre}{${q}kty${q}:${q}oct${q},${q}k${q}:${q}${MASK}${q}}`);
    }
  }
});
test('reads a nested copy that ends in a malformed \\u escape once per level, within the scan budget (#342)', () => {
  // Automated review on c5a0b7f: a masked JWK with a long pad copied three times after a stray quote and a raw line
  // break, then \uZ, spent the budget (56n with a 1,000-character pad, against 35n without the \uZ). The loose decode
  // kept "uZ" where scanJson's literal dropped \uZ, so the two copies differed and each level was read twice. Main
  // accepts it, and Redactor keeps it and masks k (RedactorTest.masksANestedCopyThatEndsInAMalformedUnicodeEscape).
  for (const lb of ['\n', '\r\n']) {
    for (const tail of ['\\uZ', '\\u0Z', '\\u00G']) {
      const nest = (k, pad) => {
        let text = JSON.stringify({ pad: 'x'.repeat(pad), kty: 'oct', k });
        for (let i = 0; i < 3; i++) text = `he said "${lb}${JSON.stringify(text).slice(1, -1)}`;
        return text + tail;
      };
      for (const pad of [1000, 2000]) {
        assertAccepted(nest(MASK, pad));
        assertFlagged(nest('FAKE_JWK_K_342', pad));
      }
      // 58.3n on c5a0b7f, 36.4n with the fix and without the \uZ.
      const masked = nest(MASK, 2000);
      scanWork.characters = 0;
      findTextLeaks(masked);
      assert.ok(scanWork.characters <= 38 * masked.length, `read ${scanWork.characters} of ${masked.length} characters`);
    }
  }
});
test('flags a copied secret value cut off in a malformed \\u escape, which Redactor masks with it (#342)', () => {
  // Automated review on 058e89a: after a stray quote and a raw line break, an unclosed copy whose value is the mask
  // followed by \uZ, \u0Z or \u00G at the end of the text is not Redactor's output: Redactor masks the whole value,
  // suffix and all, and writes a closing quote. 058e89a cut the malformed escape as half an escape, which left the bare
  // mask, and accepted it (RedactorTest.masksACopiedSecretValueCutOffInAMalformedUnicodeEscape).
  const q = '\\"';
  for (const lb of ['\n', '\r\n']) {
    for (const tail of ['\\uZ', '\\u0Z', '\\u00G']) {
      for (const head of [`{${q}kty${q}:${q}oct${q},${q}k${q}:${q}`, `{${q}password${q}:${q}`]) {
        assertFlagged(`he said "${lb}${head}${MASK}${tail}`);
        assertFlagged(`he said "${lb}${head}FAKE_JWK_K_342${tail}`);
        assertAccepted(`he said "${lb}${head}${MASK}${q}`);
      }
    }
  }
});
test('looks up each string cut at a line break in time that grows with the text, not its square (#342)', () => {
  // Automated review on e2487e1, finding 2: each string cut at a raw line break searched every string left out, work
  // the scan budget did not count: 100,000 stray quotes and line breaks took about 18 s, against about 0.2 s now.
  const text = '"\n'.repeat(100_000) + '\\u0041';
  const started = performance.now();
  assert.deepEqual(findTextLeaks(text), []);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 3000, `took ${Math.round(elapsed)} ms`);
});
test('still flags a private member after a loose kty in plain JSON, as on main (#342)', () => {
  // Only in a view main does not read (UNREAD or WHOLE, where jwkLeaks decides) does the quote count decide whether a
  // kty name makes a JWK. In plain JSON main reads, the scanner reads the name after a stray "" as a member, as on main,
  // and so exempts less than Redactor, which keeps these.
  assertFlagged('{"body":""kty":"RSA","d":"FAKE_PRIVATE_KEY_342"}');
  assertFlagged('{"body":""a":0,"kty":"RSA","d":"FAKE_PRIVATE_KEY_342"}');
});
test('flags a copied secret field with mixed quote escapes after a stray quote and a raw line break (#342)', () => {
  // The same split as for the mixed-escape JWK: the member's name or the object around it in the part scanJson does
  // not read, its value in the literal it does. Each masked form is Redactor's output
  // (RedactorTest.masksACopiedSecretFieldWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak).
  const u = '\\u0022';
  const b = '\\"';
  for (const lb of ['\n', '\r\n']) {
    for (const name of ['password', 'client_secret', 'access_token', 'authorization']) {
      assertFlagged(`he said "${lb}{${u}a${u}:1,${b}${name}${b}:${b}FAKE_SECRET_342${b}}`);
      assertAccepted(`he said "${lb}{${u}a${u}:1,${b}${name}${b}:${b}${MASK}${b}}`);
      assertFlagged(`he said "${lb}{${b}${name}${b}:${b}FAKE_SECRET_342${u}}`);
      assertAccepted(`he said "${lb}{${b}${name}${b}:${b}${MASK}${b}}`);
    }
  }
});
test('flags the twice-escaped copied form after a stray quote that opens no member, past a line break or not (#342)', () => {
  // Automated review on 26ffdc3, finding 1: after "<line break>","body": the loose decode one level down paired the
  // quotes otherwise than scanJson, which read the copied form as a scalar, so neither decoded it. Without the line
  // break the scanner missed it on main too. Each masked form is Redactor's output
  // (RedactorTest.masksTheTwiceEscapedCopiedFormAfterAStrayQuoteThatOpensNoMember).
  const escaped = text => [...text].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const loose = '"kty":"'.repeat(63);
  const quote = '\\u0022';
  for (const before of ['"\n","body":', '"\r\n","body":', 'x","body":']) {
    assertFlagged(before + escaped(escaped(loose + '"d":"FAKE_PRIVATE_KEY_342"')));
    assertAccepted(before + escaped(escaped(loose + '"d":')) + escaped(quote) + MASK + escaped(quote));
  }
});
test('reads a string that runs through a raw line break as one string, not as JSON around it (#342)', () => {
  // Automated review on 26ffdc3, finding 2: decoding all the text after a raw line break in a member's value merged the
  // next member's string into the JSON around it, and its escaped quotes made a JWK out of a loose kty. Redactor leaves
  // the text as it is (RedactorTest.keepsALooseKtyInAStringAfterAValueWithARawLineBreak).
  const loose = '"kty":"RSA","d":"dimension"'.replace(/"/g, '\\u0022');
  assertAccepted(`{"note":"a\nb","body":"${loose}"}`);
  assertFlagged(`{"note":"a\nb","body":"${'{"kty":"RSA","d":"FAKE_PRIVATE_KEY_342"}'.replace(/"/g, '\\u0022')}"}`);
});
test('still flags a copied JWK before a stray quote and a unicode escape (#342)', () => {
  // Reading the loose decode from scanJson's literals alone lost it: scanJson opens a literal at the copied \" and
  // runs it to the bare quote. The decode keeps its own view of the text and adds only what scanJson left unread. The
  // masked form is Redactor's output (RedactorTest.masksACopiedJwkBeforeAStrayQuoteAndAUnicodeEscape).
  const copied = k => `{\\"kty\\":\\"oct\\",\\"k\\":\\"${k}\\"}`;
  assertFlagged(copied('FAKE_JWK_K_342') + ' "x" \\u0041');
  assertAccepted(copied(MASK) + ' "x" \\u0041');
});
test('r8: accepts a loose private member next to JWKs whose search cannot spend its budget (#262)', () => {
  // Automated review on 26f8c2b: two masked RSA JWKs and a sibling "d" in no JWK. Redactor's JWK search reads a few
  // hundred characters of its 4n + 1024 and keeps "d" as it is (RedactorTest.keepsALoosePrivateMemberNextToMaskedJwks),
  // so the scanner must accept it too: two kty names near the start of the text cannot spend the budget.
  const jwk = kid => `{"kty":"RSA","kid":"${kid}","use":"sig","alg":"RS256","n":"${'0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA'.repeat(4)}",`
    + '"e":"AQAB","d":"[REDACTED]","p":"[REDACTED]","q":"[REDACTED]","dp":"[REDACTED]","dq":"[REDACTED]","qi":"[REDACTED]"}';
  const text = `{"keys":[${jwk('a')},${jwk('b')}],"d":"dimension"}`;
  assertAccepted(text);
  assertAccepted(nestedIn(text, 1));
  // A private member of either JWK left unmasked is still flagged.
  assertFlagged(text.replace('"d":"[REDACTED]"', '"d":"FAKE_PRIVATE_KEY_293"'));
  // #342 (automated review on 6958f74): after a member value with a raw line break, the escaped copy in the next
  // member is read once, as the string it is, so its two kty names are not counted twice
  // (RedactorTest.keepsALoosePrivateMemberNextToMaskedJwks).
  const escapedCopy = `{"note":"line one\nline two","body":"${text.replace(/"/g, '\\u0022')}"}`;
  assertAccepted(escapedCopy);
  assertFlagged(escapedCopy.replace('[REDACTED]', 'FAKE_PRIVATE_KEY_342'));
});
test('accepts masked JWKs copied after a stray quote and a raw line break, read whole and in parts (#342)', () => {
  // The whole string after the stray quote is read as well as scanJson's literal from the first copied \" on, so each
  // kty name is read twice one level down; counted twice, two masked JWKs looked like enough to spend Redactor's JWK
  // search budget, and the loose "d" was flagged. Redactor keeps each form as it is and masks an unmasked d
  // (RedactorTest.keepsALoosePrivateMemberNextToMaskedJwksCopiedAfterAStrayQuoteAndARawLineBreak).
  const jwk = kid => `{"kty":"RSA","kid":"${kid}","use":"sig","alg":"RS256","n":"${'0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA'.repeat(4)}",`
    + '"e":"AQAB","d":"[REDACTED]","p":"[REDACTED]","q":"[REDACTED]","dp":"[REDACTED]","dq":"[REDACTED]","qi":"[REDACTED]"}';
  const u = t => t.replace(/"/g, '\\u0022');
  const b = t => t.replace(/"/g, '\\"');
  for (const lb of ['\n', '\r\n']) {
    for (const copied of [
      b(`{"keys":[${jwk('a')},${jwk('b')}],"d":"dimension"}`),
      u(`{"keys":[${jwk('a')},`) + b(`${jwk('b')}],"d":"dimension"}`),
      b(`{"keys":[${jwk('a')},`) + u(`${jwk('b')}],"d":"dimension"}`),
    ]) {
      const text = `he said "${lb}${copied}`;
      assertAccepted(text);
      assertFlagged(text.replace('[REDACTED]', 'FAKE_PRIVATE_KEY_342'));
    }
  }
});
test('reads a JWK copied after a stray quote and a raw line break, nested 8 deep, within the scan budget (#342)', () => {
  // Each such string is read whole as well as from its first copied \" on, and a level down both read the same view:
  // read twice at every level, the views doubled per level and spent the scan budget, flagging the masked form.
  // Redactor keeps it and masks k (RedactorTest.masksAJwkCopiedAfterAStrayQuoteAndARawLineBreakNestedEightDeep).
  // A view read normally is not read whole again either: that adds about a third to the work (40n against 32n).
  const jwk = k => `{"kty":"oct","k":"${k}","pad":"${'x'.repeat(100)}"}`;
  for (const lb of ['\n', '\r\n']) {
    const nest = text => {
      for (let i = 0; i < 8; i++) text = `he said "${lb}${JSON.stringify(text).slice(1, -1)}`;
      return text;
    };
    const masked = nest(jwk(MASK));
    assertAccepted(masked);
    assertFlagged(nest(jwk('FAKE_JWK_K_342')));
    scanWork.characters = 0;
    findTextLeaks(masked);
    assert.ok(scanWork.characters <= 36 * masked.length, `read ${scanWork.characters} of ${masked.length} characters`);
  }
});
test('reads a masked JWK with a long pad copied after a stray quote and a raw line break, nested 3 deep, within the scan budget (#342)', () => {
  // Codex security round 1 at 0ab5aeb: with a long pad the repeated reads of the pad at each level spent the
  // 40n + 4096 scan budget, and the masked form failed closed with "scan budget spent", an over-flag outside #341.
  // At 0ab5aeb the shortest pad whose text failed at depth 3 was 1,172 characters with LF and 1,195 with CRLF (its
  // report form, one level deeper, failed with shorter pads).
  // Redactor keeps the masked form and masks k (RedactorTest.masksAJwkWithALongPadCopiedAfterAStrayQuoteNestedThreeDeep).
  const jwk = (k, pad) => `{"kty":"oct","k":"${k}","pad":"${'x'.repeat(pad)}"}`;
  for (const [lb, threshold] of [['\n', 1172], ['\r\n', 1195]]) {
    const nest = text => {
      for (let i = 0; i < 3; i++) text = `he said "${lb}${JSON.stringify(text).slice(1, -1)}`;
      return text;
    };
    for (const pad of [threshold - 1, threshold, 2000]) {
      assertAccepted(nest(jwk(MASK, pad)));
      const leaked = nest(jwk('FAKE_JWK_K_342', pad));
      assertFlagged(leaked);
      assert.ok(findTextLeaks(leaked).some(leak => leak.check === 'JSON secret field'), `k not judged: pad ${pad}`);
    }
    // Each view of the pad is read a bounded number of times: 52n at 0ab5aeb, 36n on main.
    const masked = nest(jwk(MASK, 2000));
    scanWork.characters = 0;
    findTextLeaks(masked);
    assert.ok(scanWork.characters <= 35 * masked.length, `read ${scanWork.characters} of ${masked.length} characters`);
  }
});
test('reads a masked JWK after a long pad, copied after a stray quote and closed at each level, 3 deep, within the scan budget (#342)', () => {
  // Automated review on feb555e: with the pad before kty and a closing quote after each copy, the whole-string reads
  // re-read the pad at each level and spent the budget (213,200 against 210,776 with a 5,000-character pad). Main
  // accepts it, and Redactor keeps it and masks k (RedactorTest.masksAJwkAfterALongPadCopiedAndClosedThreeDeep).
  const nest = (k, lb) => {
    let text = JSON.stringify({ pad: 'x'.repeat(5000), kty: 'oct', k });
    for (let i = 0; i < 3; i++) text = `he said "${lb}${JSON.stringify(text).slice(1, -1)}"`;
    return text;
  };
  for (const lb of ['\n', '\r\n']) {
    const masked = nest(MASK, lb);
    assertAccepted(masked);
    const leaked = nest('FAKE_JWK_K_342', lb);
    assertFlagged(leaked);
    assert.ok(findTextLeaks(leaked).some(leak => leak.check === 'JSON secret field'), 'k not judged');
    scanWork.characters = 0;
    findTextLeaks(masked);
    assert.ok(scanWork.characters <= 38 * masked.length, `read ${scanWork.characters} of ${masked.length} characters`);
  }
});
test('fails closed on a masked JWK after a long pad, copied and closed at each level, 5 deep (#342, accepted)', () => {
  // Owner decision (card 2026-11-06, #342): with the reads #342 adds, harmless masked JWKs nested 4 or more levels deep
  // with pads in the thousands may fail closed with "scan budget spent" where main accepts, and the budget stays at
  // 40n + 4096. This pins that case from the automated review on ff1a8a5 (234,073 against 225,416): it must fail closed,
  // never pass silently, and its leaked form must be flagged too. Should it start to pass, the accepted region shrank.
  const nest = (k, lb) => {
    let text = JSON.stringify({ kty: 'oct', k, pad: 'x'.repeat(5000) });
    for (let i = 0; i < 5; i++) text = `he said "${lb}${JSON.stringify(text).slice(1, -1)}"`;
    return text;
  };
  for (const lb of ['\n', '\r\n']) {
    assert.deepEqual(findTextLeaks(nest(MASK, lb)).map(leak => leak.check), ['scan budget spent']);
    assert.ok(findTextLeaks(nest('FAKE_JWK_K_342', lb)).length > 0);
  }
});
test('reads JSON member names spelled with \\u escapes, as Redactor does (#262)', () => {
  for (const text of [
    String.raw`{"kt\u0079":"RSA","\u0064":"[REDACTED]","\u0064p":"[REDACTED]"}`,
    String.raw`{"body":"{\"kt\\u0079\":\"oct\",\"\\u006B\":\"[REDACTED]\"}"}`,
    String.raw`{"client_s\u0065cret":"[REDACTED]","\u0041uthorization":"SCRAM-SHA-256 [REDACTED]"}`,
    String.raw`{"\u0064":"2026-11-03"}`,
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  for (const text of [
    String.raw`{"kt\u0079":"RSA","d":"LEAKED"}`,
    String.raw`{"kty":"RSA","\u0064":"LEAKED"}`,
    String.raw`{"\u006B\u0074\u0079":"oct","\u006b":"LEAKED"}`,
    String.raw`{"kty":"RSA","\u006fth":[{"r":"LEAKED"}]}`,
    String.raw`{"body":"{\"kt\\u0079\":\"RSA\",\"\\u0064\":\"LEAKED\"}"}`,
    String.raw`{"client_s\u0065cret":"LEAKED"}`,
    String.raw`{"\u0041uthorization":"SCRAM-SHA-256 LEAKED"}`,
  ]) {
    assert.ok(findTextLeaks(text).length > 0, text);
  }
});
test('flags a JWK private member, Token or DPoP credential Redactor would not leave (#262)', () => {
  for (const text of [
    '{"kty":"RSA","d":"LEAKED"}',
    '{"kty":"RSA","d":"[REDACTED]x"}',
    '{"kty":"RSA","d":"[REDACTED]"ssTAIL"}',
    '{"kty":"RSA","d":"[REDACTED]"-tail"}',
    '{"kty":"RSA","d":"[REDACTED]"_tail"}',
    'evidence: {"kty":"oct","k":"[REDACTED]\\" tail LEAKED"}',
    '{"b":"{\\"kty\\":\\"RSA\\",\\"d\\":\\"[REDACTED]\\"-tail\\"}"}',
    '{"kty":"oct","k":12345678}',
    '{"kty":"RSA","oth":[{"r":"LEAKED"}]}',
    '{"body":"{\\"kty\\":\\"RSA\\",\\"d\\":\\"LEAKED\\"}"}',
    'Token LEAKEDtok123',
    'Authorization: Token abc',
    'DPoP [REDACTED]:TAIL',
    'Token -------:',
    // A short punctuation credential is not prose (Codex security review r1); only Token -> is.
    'Bearer -._~+/=',
    'Token -._~+/=',
    'Bearer%20-._~+/=',
    'Authorization: Bearer -._~+/=',
    'Bearer -> HTTP 401',
    'Authorization: Bearer ->',
    'cb?auth=Bearer+LEAKED123',
    'received token DPoP LEAKEDtok123',
    'the token Bearer LEAKEDtok123',
    'Bearer%20++++++++',
    'GET /cb?h=Authorization%3A%20Bearer [REDACTED]:LEAKEDSUFFIX',
    '{"body":"{\\"kty\\":\\"RSA\\",\\"d\\":\\n\\"LEAKED\\"}"}',
    '{"body":"{\\"password\\":\\n\\"LEAKED\\"}"}',
    // Redactor masks a JWK member's array whole, so a list of masks there is never its output.
    'evidence: {"kty":"RSA","d":["LEAKED [REDACTED]"]}',
    'evidence: {"kty":"RSA","d":["[REDACTED]"]}',
    'evidence: {"b":"{\\"kty\\":\\"RSA\\",\\"d\\":[\\"LEAKED [REDACTED]\\"]}"}',
  ]) {
    assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text}`);
  }
  assert.equal(findJsonLeaks({ responseBody: '{"keys":[{"kty":"oct","k":"LEAKED"}]}' }).length, 1);
});
test('flags a sensitive header value Redactor would not leave (#261)', () => {
  for (const text of [
    'Cookie: [REDACTED]; theme=dark',
    'Cookie: sid=LEAKED',
    '{"debug":"echo:\\nCookie: sid=LEAKED\\nend"}',
    '{"debug":"echo:\\nCookie: [REDACTED]sid=LEAKED"}',
    // A masked line does not hide the next escaped line.
    '{"body":"HTTP/1.1 401\\nCookie: [REDACTED]\\nSet-Cookie: sid=LEAKED\\nend"}',
    '{"body":"{\\"m\\":\\"x\\\\nCookie: [REDACTED]\\\\nX-Api-Key: LEAKED\\"}"}',
    JSON.stringify({ responseBody: '{"debug":"echo:\\nCookie: [REDACTED]\\nSet-Cookie: sid=LEAKED"}' }),
    '{"details":{"authorization":["SCRAM-SHA-256 [REDACTED]","LEAKED"]}}',
    // An escaped quote does not end the string the line is in.
    '{"debug":"x\\nCookie: [REDACTED]\\", leak=LEAKED"}',
    // \\n in a JSON string is a backslash and an n, not a line break: the value goes on.
    '{"debug":"x\\nCookie: [REDACTED]\\\\nLEAKED"}',
    'Cookie: [REDACTED]\\\\nLEAKED',
    // \N is not a line-break escape: the value goes on.
    'X-Client-Secret: [REDACTED]\\NLEAKED',
    '{"body":"{\\"m\\":\\"x\\\\nCookie: [REDACTED]\\\\\\", leak=LEAKED\\"}"}',
    'Set-Cookie: Bearer [REDACTED]',
    '{"Cookie":"Bearer [REDACTED]"}',
    '{"x-api-key":123}',
    '{"authorization":{"token":"LEAKED"}}',
  ]) {
    assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text}`);
  }
  assert.equal(findJsonLeaks({ details: { cookie: ['sid=LEAKED'] } }).length, 1);
  assert.equal(findJsonLeaks({ responseBody: '{"X-Api-Key":"LEAKED"}' }).length, 1);
  const body = JSON.stringify({ debug: JSON.stringify({ Cookie: 'sid=LEAKED' }) });
  assert.ok(findTextLeaks(JSON.stringify({ responseBody: body })).length > 0, body);
  for (const text of [
    // An escaped tab before the name is an indent, as in Redactor.
    '{"m":"x\\n\\tCookie: sid=LEAKED"}',
    // A mask that ends at an escaped quote has more of the value after it, at any depth.
    '{"access_token":"[REDACTED]\\", tail=LEAKED"}',
    // Only an authorization list item may have a scheme in front of the mask, as on main for the others.
    'echo: {"client_secret":["LEAKED0001 [REDACTED]"]}',
    'echo: {"Cookie":["LEAKED0001 [REDACTED]"]}',
    // A header line at the start of a JSON string, as a recorded plain-text body is serialized.
    JSON.stringify({ responseBody: 'Cookie: sid=LEAKED\nAccept: x' }),
    JSON.stringify({ responseBody: JSON.stringify({ responseBody: 'Cookie: sid=LEAKED' }) }),
    JSON.stringify({ responseBody: `echo: ${JSON.stringify({ access_token: '[REDACTED]", tail=LEAKED' })}` }),
  ]) {
    assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text}`);
  }
});
test('flags a word in front of a masked non-authorization header list item (#292)', () => {
  // Redactor masks every value of a sensitive header other than Authorization whole, so a prefix that
  // looks like a scheme (tail [REDACTED]) is the start of the secret.
  for (const name of ['Cookie', 'Set-Cookie']) {
    const text = `{"${name}":["tail [REDACTED]"]}`;
    assert.ok(findTextLeaks(text).length > 0, `not flagged: ${text}`);
    const record = { requestHeaders: { [name]: ['[REDACTED]', 'tail [REDACTED]'] } };
    assert.ok(findTextLeaks(JSON.stringify(record)).length > 0, `not flagged: ${JSON.stringify(record)}`);
    assert.equal(findJsonLeaks(record).length, 1, JSON.stringify(record));
  }
});
test('accepts a recorded header list of masked values', () => {
  // Bare masks only (#292).
  const record = { requestHeaders: { 'X-Api-Key': ['[REDACTED]'], Cookie: ['[REDACTED]', '[REDACTED]'], 'Set-Cookie': ['[REDACTED]'] } };
  assert.deepEqual(findTextLeaks(JSON.stringify(record)), []);
  assert.deepEqual(findJsonLeaks(record), []);
  assert.ok(findTextLeaks(JSON.stringify({ requestHeaders: { 'Api-Key': ['Bearer [REDACTED]'] } })).length > 0);
  assert.ok(findTextLeaks('{"api_key":["[REDACTED]","LEAKED"]}').length > 0);
});
test('accepts a scheme in front of a masked authorization header list item', () => {
  const record = { requestHeaders: { Authorization: ['Bearer [REDACTED]'], 'Proxy-Authorization': ['SCRAM-SHA-256 [REDACTED]'] } };
  assert.deepEqual(findTextLeaks(JSON.stringify(record)), []);
});

// A JSON escape of whitespace after the scheme is the separator, as Redactor reads it (#212).
const ESCAPED_SEPARATORS = ['\\t', '\\n', '\\r', '\\u0020', '\\u0009', '\\u000A', '\\u000D', '\\u000a', '\\u000d',
  '\\\\t', '\\\\n', '\\\\r', '\\\\u0020', '\\\\u0009', '\\r\\n', ' \\t', '\\t ', '\\n\\u0020'];
const credentialFlagged = text => findTextLeaks(text).some(l => l.check === 'Bearer/Basic credential');
test('flags a credential after a JSON-escaped separator (#212)', () => {
  for (const separator of ESCAPED_SEPARATORS) {
    for (const text of [
      `{"echo":"Bearer${separator}SecretTokenValue99"}`,
      `{"echo":"Basic${separator}c3ludGhjbGllbnQ6U3ludGg"}`,
      `{"echo":"Authorization: Bearer${separator}SecretTokenValue99"}`,
      `{"echo":"rejected bearer${separator}Ab12\\/SecretRemainder99, twice"}`,
    ]) {
      assert.ok(credentialFlagged(text), `not flagged: ${text}`);
      assertFlagged(text);
    }
  }
  // In JSON quoted inside a JSON string, and in the report that holds a recorded body.
  assertFlagged('{"debug":"{\\"e\\":\\"Bearer\\\\tSecretTokenValue99\\"}"}');
  assert.ok(credentialFlagged(reportForm('{"echo":"Bearer\\tSecretTokenValue99"}')));
  // After Token and DPoP, an escaped space or tab.
  for (const separator of ['\\t', '\\u0020', '\\u0009', '\\\\t', '\\\\u0020', ' \\t']) {
    for (const text of [`{"echo":"Token${separator}9944b09199c62bcf9418"}`, `{"echo":"rejected DPoP${separator}PHNhbWw6QXNzZXJ0aW9u"}`]) {
      assert.ok(credentialFlagged(text), `not flagged: ${text}`);
      assertFlagged(text);
    }
  }
  // The rest of a credential after a mask that follows an escaped separator.
  for (const separator of ['\\t', '\\n', '\\u0020', '\\\\t']) {
    assertFlagged(`{"echo":"Bearer${separator}[REDACTED]\\/SecretRemainder99"}`);
    assertFlagged(`{"echo":"Bearer${separator}[REDACTED]:SecretRemainder99"}`);
  }
});
// A real form feed or vertical tab separates Bearer or Basic from a credential (\s), so its JSON escape does too
// (#212, Codex round 1).
const ESCAPED_FF_VT = ['\\f', '\\u000C', '\\u000c', '\\u000B', '\\u000b', '\\\\f', '\\\\u000C',
  '\\t\\f', '\\f\\n', ' \\f', '\\u000b\\u0020'];
test('flags a credential after a JSON-escaped form feed or vertical tab (#212)', () => {
  for (const separator of ESCAPED_FF_VT) {
    for (const text of [
      `{"echo":"Bearer${separator}SecretTokenValue99"}`,
      `{"echo":"Basic${separator}c3ludGhjbGllbnQ6U3ludGg"}`,
      `{"echo":"Authorization: Bearer${separator}SecretTokenValue99"}`,
      `{"echo":"rejected bearer${separator}Ab12\\/SecretRemainder99, twice"}`,
      `{"echo":"rejected bearer${separator}Ab12\\u002BSecretRemainder99, twice"}`,
    ]) {
      assert.ok(credentialFlagged(text), `not flagged: ${text}`);
      assertFlagged(text);
    }
    assertFlagged(`{"echo":"Bearer${separator}[REDACTED]\\/SecretRemainder99"}`);
  }
  assertFlagged('{"debug":"{\\"e\\":\\"Bearer\\\\fSecretTokenValue99\\"}"}');
  assert.ok(credentialFlagged(reportForm('{"echo":"Bearer\\fSecretTokenValue99"}')));
});
test('accepts prose after a JSON-escaped form feed or vertical tab, and after Token or DPoP (#212)', () => {
  for (const text of ['{"m":"Missing bearer\\ftoken"}', '{"m":"Basic\\u000Cplan"}',
    '{"h":"Bearer\\frealm=\\"synthetic\\", error=\\"invalid_token\\""}']) {
    assertAccepted(text);
  }
  for (const separator of ['\\f', '\\u000C', '\\u000b']) {
    assertAccepted(`{"m":"issue a token${separator}2 times per hour; DPoP${separator}proof-v2 required"}`);
  }
});
test('accepts what Redactor leaves for a credential after a JSON-escaped separator, and prose there (#212)', () => {
  for (const text of [
    '{"echo":"Bearer [REDACTED]"}', '{"echo":"Authorization: Bearer [REDACTED]"}',
    '{"echo":"rejected bearer [REDACTED], twice"}', '{"echo":"Token [REDACTED]"}',
    '{"debug":"{\\"e\\":\\"Bearer [REDACTED]\\"}"}',
    '{"m":"Missing bearer\\ntoken"}', '{"m":"Basic\\nplan"}', '{"m":"Missing bearer\\u0020token."}',
    '{"m":"Basic\\tauthentication is required"}', '{"m":"Missing bearer\\\\ntoken"}',
    '{"h":"Bearer\\trealm=\\"synthetic\\", error=\\"invalid_token\\""}',
    '{"h":"Bearer\\nerror=\\"invalid_token\\", error_description=\\"Expired\\""}',
    '{"h":"Bearer\\u0020error_description=\\"Expired\\""}',
    '{"h":"Basic\\u0020realm=\\"synthetic-payer\\""}',
    '{"h":"Bearer\\r\\nscope=\\"system/*.read\\""}',
  ]) {
    assertAccepted(text);
  }
  // After Token and DPoP an escaped line break is not a separator, as a real one is not.
  for (const separator of ['\\n', '\\r', '\\u000A', '\\u000D', '\\r\\n', '\\\\n']) {
    assertAccepted(`{"m":"issue a token${separator}2 times per hour; DPoP${separator}proof-v2 required"}`);
  }
});

// Class-level check (#160): generated secrets of every shape, placed in headers, bodies and query
// strings (see secret-cases.mjs), must be flagged both unmasked and where a mask stops short of
// their end. RedactorPropertyTest runs the same generator against Redactor. A failure names its
// seed; LEAKS_SEED=<seed> reproduces it.
const SEED = Number(process.env.LEAKS_SEED ?? Math.floor(Math.random() * 2 ** 32));
const CASES = generateCases(SEED, 3000);
const describeCase = c => `seed ${SEED}: ${c.slot} ${c.secret.shape} ${c.encoding}${c.wrap === 'NONE' ? '' : ` in ${c.wrap}`} (${c.carrier}) after ${JSON.stringify(c.separator)}`;

/** Flagged in the slot's own text, as in a report, and in the recorded exchange, as in the bundle. */
const flagged = ({ text, record }) => (text === null || findTextLeaks(text).length > 0)
  && findTextLeaks(JSON.stringify(record)).length + findJsonLeaks(record).length > 0;

test('class-level check: flags every generated secret left unmasked', () => {
  for (const c of CASES) {
    const placement = build(c, placed(c));
    assert.ok(flagged(placement), `${describeCase(c)} not flagged: ${placement.text ?? JSON.stringify(placement.record)}`);
  }
});
test('class-level check: flags a mask that stops short of a generated secret', () => {
  for (const c of CASES) {
    const value = placed(c);
    // Base64 lines without their armor can't be told from other text; Redactor masks PEM blocks whole.
    if ((c.secret.shape === 'PEM' && c.encoding === 'RAW') || value.length <= PIECE) continue;
    const placement = build(c, MASK + value.slice(1 + (c.cut % (value.length - PIECE))));
    assert.ok(flagged(placement), `${describeCase(c)} not flagged: ${placement.text ?? JSON.stringify(placement.record)}`);
  }
});
