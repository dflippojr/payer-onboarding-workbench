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
