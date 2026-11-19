// Writes the scanner agreement's main verdicts (#377 criterion 2, as amended: no new flags against main, row by row):
// the current scanner's verdict on each output in workbench-core/src/test/resources/scanner-grids/agreement-main-grid.json.gz,
// which AgreementBaselineTest keeps equal to the baseline revision's own Redactor outputs.
//
//   node scripts/agreement-baseline.mjs          rewrites replay/test/agreement-main-verdicts.json only
//   node scripts/agreement-baseline.mjs --head   rewrites replay/test/agreement-head-flags.json only (the head pin)
//
// The two are separate on purpose: regenerating main's verdicts never changes the head pin, so it cannot accept a new
// flag on the head. replay/test/leaks.test.mjs fails if either file differs from what the scanner gives. Review the
// diff (git diff --stat replay/test) before committing.
import { writeFileSync } from 'node:fs';
import { HEAD_FLAGS, MAIN_VERDICTS, grid, verdictsOf } from '../replay/test/agreement.mjs';

const BASELINE = '19b624cd5ced541d2f0461b548d4653ff7bcaeeb';
const DIGITS = 'Each value is a digit: bit 0 for findTextLeaks(output), bit 1 for findTextLeaks of its report form '
  + '{"responseBody": output}, bit 2 for findJsonLeaks({responseBody: output}); a row is the first 16 hex digits of the '
  + "SHA-256 of its input (UTF-8), and a row with no flag is left out.";

const head = process.argv.includes('--head');
const out = head
  ? {
    _comment: 'The pinned rows the current Redactor outputs of agreement-grid.json.gz are flagged on (#377 criterion 2, '
      + 'as amended). Every one must also be flagged on main at the same entry points. ' + DIGITS
      + ' Written by node scripts/agreement-baseline.mjs --head.',
    head: verdictsOf(grid('agreement-grid')),
  }
  : {
    _comment: `The scanner's verdicts on main's Redactor outputs (baseline ${BASELINE}, agreement-main-grid.json.gz, `
      + 'kept equal to that revision\'s own classes by AgreementBaselineTest) for each agreement-grid input (#377 '
      + 'criterion 2, as amended). ' + DIGITS + ' Written by node scripts/agreement-baseline.mjs.',
    main: verdictsOf(grid('agreement-main-grid')),
  };
writeFileSync(head ? HEAD_FLAGS : MAIN_VERDICTS, JSON.stringify(out, null, 1) + '\n');
console.log(`${head ? HEAD_FLAGS : MAIN_VERDICTS}: ${Object.keys(head ? out.head : out.main).length} flagged rows`);
