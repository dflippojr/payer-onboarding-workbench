// Runs the shared redaction corpus (workbench-core/src/test/resources/redaction-corpus.json,
// also run through Redactor by RedactorCorpusTest) against the leak scanner.
// Needs no bundle: node --test replay/test/leaks.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { findJsonLeaks, findTextLeaks } from './leaks.mjs';
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
    // redactTree keeps any scheme of an authorization list item.
    '{"details":{"authorization":["SCRAM-SHA-256 [REDACTED]"]}}',
  ]) {
    assert.deepEqual(findTextLeaks(text), [], text);
  }
  assert.deepEqual(findJsonLeaks({ details: { authorization: ['Bearer [REDACTED]'], cookie: '[REDACTED]' } }), []);
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
});
test('accepts a recorded header list of masked values', () => {
  assert.deepEqual(findTextLeaks(JSON.stringify({ requestHeaders: { 'X-Api-Key': ['[REDACTED]'], 'Api-Key': ['Bearer [REDACTED]'] } })), []);
  assert.ok(findTextLeaks('{"api_key":["[REDACTED]","LEAKED"]}').length > 0);
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
