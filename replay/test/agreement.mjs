// The scanner agreement's rows and verdicts (#377 criterion 2, as amended: no new flags against main, row by row), shared
// by replay/test/leaks.test.mjs, which checks them, and scripts/agreement-baseline.mjs, which writes them.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { findJsonLeaks, findTextLeaks } from './leaks.mjs';

/** The [input, output] pairs of a committed workbench-core/src/test/resources/scanner-grids/<name>.json.gz. */
export function grid(name) {
  const url = new URL(`../../workbench-core/src/test/resources/scanner-grids/${name}.json.gz`, import.meta.url);
  return JSON.parse(gunzipSync(readFileSync(fileURLToPath(url))).toString('utf8'));
}

/** A row's id: the first 16 hex digits of its input's SHA-256 (UTF-8), so it does not move with the row order. */
export function agreementRow(input) {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 16);
}

/** An output as it sits in a recorded run: the value of a response body. */
export const reportForm = text => JSON.stringify({ responseBody: text });

/**
 * The scanner's verdict on `out` at its three entry points, as a digit: bit 0 for findTextLeaks(out), bit 1 for
 * findTextLeaks of its report form, bit 2 for findJsonLeaks({ responseBody: out }).
 */
export function entryBits(out) {
  return (findTextLeaks(out).length > 0 ? 1 : 0) | (findTextLeaks(reportForm(out)).length > 0 ? 2 : 0)
    | (findJsonLeaks({ responseBody: out }).length > 0 ? 4 : 0);
}

/** The flagged rows of `pairs` with their digits, keys in order; a row with no flag is left out. */
export function verdictsOf(pairs) {
  const verdicts = {};
  for (const [input, out] of pairs) {
    const bits = entryBits(out);
    if (bits) verdicts[agreementRow(input)] = bits;
  }
  return Object.fromEntries(Object.entries(verdicts).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

const file = name => fileURLToPath(new URL(`./${name}`, import.meta.url));
export const MAIN_VERDICTS = file('agreement-main-verdicts.json');
export const HEAD_FLAGS = file('agreement-head-flags.json');

/** Main's committed verdicts and the committed head pin. */
export function committedVerdicts() {
  return {
    main: JSON.parse(readFileSync(MAIN_VERDICTS, 'utf8')).main,
    head: JSON.parse(readFileSync(HEAD_FLAGS, 'utf8')).head,
  };
}
