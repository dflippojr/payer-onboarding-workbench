#!/usr/bin/env node
// Merges the mutations.xml reports of pitest's per-class runs (scripts/mutation.sh) into the one report that
// mutation-summary.mjs judges: every <mutation> of every file, in one <mutations> element.
//
//   node scripts/mutation-merge.mjs <mutations.xml>... > mutations.xml
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function mergeMutations(reports) {
  const mutations = reports.flatMap(xml => [...xml.matchAll(/<mutation\b[\s\S]*?<\/mutation>/g)].map(m => m[0]));
  return `<?xml version="1.0" encoding="UTF-8"?>\n<mutations>\n${mutations.map(m => `${m}\n`).join('')}</mutations>\n`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(mergeMutations(process.argv.slice(2).map(file => readFileSync(file, 'utf8'))));
}
