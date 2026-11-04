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

// Class-level check (#160): generated secrets of every shape, placed in headers, bodies and query
// strings (see secret-cases.mjs), must be flagged both unmasked and where a mask stops short of
// their end. RedactorPropertyTest runs the same generator against Redactor. A failure names its
// seed; LEAKS_SEED=<seed> reproduces it.
const SEED = Number(process.env.LEAKS_SEED ?? Math.floor(Math.random() * 2 ** 32));
const CASES = generateCases(SEED, 3000);
const describeCase = c => `seed ${SEED}: ${c.slot} ${c.secret.shape} ${c.encoding}${c.wrap === 'NONE' ? '' : ` in ${c.wrap}`} (${c.carrier})`;

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
