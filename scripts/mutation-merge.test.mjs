import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeMutations } from './mutation-merge.mjs';
import { parseMutations } from './mutation-summary.mjs';

const report = (...mutations) => `<?xml version="1.0" encoding="UTF-8"?>
<mutations>
${mutations.map(([file, status]) => `<mutation detected='${status === 'KILLED'}' status='${status}'><sourceFile>${file}</sourceFile><lineNumber>1</lineNumber></mutation>`).join('\n')}
</mutations>
`;

test('the merged report holds every mutant of every class, in one <mutations> element', () => {
  const merged = mergeMutations([
    report(['Check.java', 'KILLED']),
    report(['Support.java', 'SURVIVED'], ['Support.java', 'KILLED']),
  ]);
  assert.equal(merged.match(/<mutations>/g).length, 1);
  assert.deepEqual(parseMutations(merged).map(({ sourceFile, status }) => [sourceFile, status]), [
    ['Check.java', 'KILLED'],
    ['Support.java', 'SURVIVED'],
    ['Support.java', 'KILLED'],
  ]);
});

test('a merge of no reports is an empty, valid report', () => {
  assert.deepEqual(parseMutations(mergeMutations([])), []);
  assert.match(mergeMutations([]), /<mutations>\s*<\/mutations>/);
});
