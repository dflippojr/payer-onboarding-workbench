// Runs the shared redaction corpus (workbench-core/src/test/resources/redaction-corpus.json,
// also run through Redactor by RedactorCorpusTest) against the leak scanner.
// Needs no bundle: node --test replay/test/leaks.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { findJsonLeaks, findTextLeaks } from './leaks.mjs';

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
  'form secret cut at a backslash': 'client_secret=[REDACTED]\\xyzTAIL&x=1',
  'embedded secret cut at an escaped quote': '{"result":"{\\"password\\":\\"[REDACTED]\\"ssTAIL\\"}"}',
  'secret object': '{"private_key":{"kty":"RSA","d":"PRIVATED"}}',
  'secret array': '{"access_token":["ARRSECRET"]}',
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
test('accepts a recorded header list of masked values', () => {
  assert.deepEqual(findTextLeaks(JSON.stringify({ requestHeaders: { 'X-Api-Key': ['[REDACTED]'], 'Api-Key': ['Bearer [REDACTED]'] } })), []);
  assert.ok(findTextLeaks('{"api_key":["[REDACTED]","LEAKED"]}').length > 0);
});
