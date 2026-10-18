#!/usr/bin/env node
// The mutation job's verdict and job summary: reads pitest's mutations.xml and the floor
// (pitest.mutation.floor in diagnostics/pom.xml), prints Markdown with the score and every
// surviving and uncovered mutant, and exits 1 when the score is below the floor.
//
//   node scripts/mutation-summary.mjs <mutations.xml> <pom.xml>
//
// pitest itself fails the build below the floor; this judges a cached report the same way.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const unescape = text => text.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"')
  .replaceAll('&apos;', "'").replaceAll('&amp;', '&');

// pitest's <mutation> elements: their status and detected attributes and the child text we report.
export function parseMutations(xml) {
  const mutations = [];
  for (const [, attributes, body] of xml.matchAll(/<mutation\b([^>]*)>([\s\S]*?)<\/mutation>/g)) {
    const attribute = name => new RegExp(`\\b${name}=['"]([^'"]*)['"]`).exec(attributes)?.[1];
    const child = name => {
      const match = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(body);
      return match ? unescape(match[1]) : '';
    };
    mutations.push({
      status: attribute('status'),
      detected: attribute('detected') === 'true',
      sourceFile: child('sourceFile'),
      mutatedClass: child('mutatedClass'),
      method: child('mutatedMethod'),
      line: Number(child('lineNumber')),
      mutator: child('mutator').split('.').pop(),
      description: child('description'),
    });
  }
  return mutations;
}

export function readFloor(pom) {
  const match = /<pitest\.mutation\.floor>\s*(\d+)\s*<\/pitest\.mutation\.floor>/.exec(pom);
  if (!match) throw new Error('no <pitest.mutation.floor> in the pom');
  return Number(match[1]);
}

// pitest's mutation score: detected mutants over all mutants, rounded down to a whole percent.
export function score(mutations) {
  if (mutations.length === 0) throw new Error('the report has no mutations');
  return Math.floor((100 * mutations.filter(m => m.detected).length) / mutations.length);
}

const cell = text => String(text).replaceAll('|', '\\|').replaceAll('\n', ' ');

function table(mutations) {
  const rows = mutations.toSorted((a, b) => a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line)
    .map(m => `| ${cell(m.sourceFile)}:${m.line} | \`${cell(m.method)}\` | ${cell(m.mutator)} | ${cell(m.description)} |`);
  return ['| Where | Method | Mutator | Mutation |', '|---|---|---|---|', ...rows].join('\n');
}

export function summary(mutations, floor) {
  const value = score(mutations);
  const counts = {};
  for (const m of mutations) counts[m.status] = (counts[m.status] ?? 0) + 1;
  const survived = mutations.filter(m => m.status === 'SURVIVED');
  const uncovered = mutations.filter(m => m.status === 'NO_COVERAGE');
  const lines = [
    '## Mutation testing: diagnostics',
    '',
    `**Score ${value}%** (${mutations.filter(m => m.detected).length} of ${mutations.length} mutants detected); `
      + `floor ${floor}%: ${value >= floor ? 'passed' : '**FAILED**'}.`,
    '',
    Object.entries(counts).sort().map(([status, n]) => `${status} ${n}`).join(' · '),
    '',
    `### Surviving mutants (${survived.length})`,
    '',
    'A test ran the mutated code and still passed: no test asserts on this behaviour.',
    '',
    survived.length ? table(survived) : 'None.',
    '',
    `### Mutants no test reaches (${uncovered.length})`,
    '',
    uncovered.length ? table(uncovered) : 'None.',
    '',
  ];
  return { markdown: lines.join('\n'), passed: value >= floor };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [report, pom] = process.argv.slice(2);
  if (!report || !pom) {
    console.error('usage: node scripts/mutation-summary.mjs <mutations.xml> <pom.xml>');
    process.exit(2);
  }
  const { markdown, passed } = summary(parseMutations(readFileSync(report, 'utf8')), readFloor(readFileSync(pom, 'utf8')));
  console.log(markdown);
  process.exitCode = passed ? 0 : 1;
}
