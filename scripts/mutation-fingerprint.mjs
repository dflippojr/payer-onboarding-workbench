#!/usr/bin/env node
// The partitions of a mutation run and the key each one's pitest report is valid for. pitest analyses one
// diagnostics class at a time (scripts/mutation.sh), and a class's report is reused only while its key
// holds: a SHA-256 over every input its verdicts depend on. The inputs are the root pom, the Maven wrapper,
// the mutation scripts (install-crd-router.sh pins fhir-crd-router), diagnostics' pom and sources, the pom
// and src/main of every reactor module diagnostics depends on (any scope, transitively: mock-payers and
// samples feed its tests), and the JDK's `java -version`. Each check (a class named *Check) also depends
// only on itself, so editing one check invalidates that check's partition and no other. Every other
// class depends on the shared sources, which include the other non-check classes, and so an edit to one
// of them invalidates all partitions.
//
//   node scripts/mutation-fingerprint.mjs     prints <class>TAB<pitest targetClasses>TAB<key>, one line per partition
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE = 'diagnostics';
const SOURCES = `${MODULE}/src/main/java`;
const TOOLING = ['pom.xml', 'mvnw', '.mvn', 'scripts/install-crd-router.sh', 'scripts/mutation.sh',
  'scripts/mutation-merge.mjs', 'scripts/mutation-summary.mjs', 'scripts/mutation-fingerprint.mjs'];

const strip = (xml, tag) => xml.replaceAll(new RegExp(`<${tag}>[\\s\\S]*?</${tag}>`, 'g'), '');
const artifactIds = xml => [...xml.matchAll(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/g)].map(m => m[1]);

// Reactor module directories by artifactId, and the artifactIds each one depends on.
function reactor(dir) {
  const modules = new Map();
  for (const [, name] of readFileSync(join(dir, 'pom.xml'), 'utf8').matchAll(/<module>\s*([^<\s]+)\s*<\/module>/g)) {
    const pom = readFileSync(join(dir, name, 'pom.xml'), 'utf8');
    const own = artifactIds(['parent', 'dependencies', 'dependencyManagement', 'build', 'profiles']
      .reduce(strip, pom))[0];
    const dependencies = [...pom.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].flatMap(m => artifactIds(m[1]));
    modules.set(own, { dir: name, dependencies });
  }
  return modules;
}

// The files at path (a file or a directory, recursively); none when it does not exist.
function walk(dir, path) {
  const full = join(dir, path);
  if (!existsSync(full)) return [];
  if (!statSync(full).isDirectory()) return [path];
  return readdirSync(full).flatMap(name => walk(dir, `${path}/${name}`));
}

// Every input file, relative to dir, sorted.
export function inputFiles(dir) {
  const modules = reactor(dir);
  const needed = new Map();
  const visit = artifactId => {
    const module = modules.get(artifactId);
    if (!module || needed.has(artifactId)) return;
    needed.set(artifactId, module);
    module.dependencies.forEach(visit);
  };
  const own = [...modules].find(([, m]) => m.dir === MODULE)?.[0];
  if (!own) throw new Error(`no ${MODULE} module in ${join(dir, 'pom.xml')}`);
  visit(own);
  const paths = [...TOOLING];
  for (const [artifactId, module] of needed) {
    paths.push(`${module.dir}/pom.xml`, artifactId === own ? `${module.dir}/src` : `${module.dir}/src/main`);
  }
  return [...new Set(paths.flatMap(path => walk(dir, path)))].sort();
}

const isCheck = path => /^diagnostics\/src\/main\/java\/.*Check\.java$/.test(path);

// Every class pitest analyses, one partition each: its name, the targetClasses pattern that selects it
// (inner classes included) and the key of the inputs its report depends on.
export function partitions(dir, runtime) {
  const hash = files => {
    const digest = createHash('sha256').update(`runtime\0${runtime}\0`);
    for (const path of files) {
      const content = readFileSync(join(dir, path));
      digest.update(`${path}\0${content.length}\0`).update(content);
    }
    return digest.digest('hex');
  };
  const inputs = inputFiles(dir);
  const shared = inputs.filter(path => !isCheck(path));
  return walk(dir, SOURCES)
    .filter(path => path.endsWith('.java') && !path.endsWith('package-info.java'))
    .sort()
    .map(path => {
      const dotted = path.slice(`${SOURCES}/`.length, -'.java'.length).replaceAll('/', '.');
      const own = path.slice(0, -'.java'.length).replace(/^.*\//, '');
      const files = [...new Set([...shared, path])].sort();
      return { name: own, target: `${dotted}*`, key: hash(files) };
    });
}

// The JDK Maven runs with: JAVA_HOME's java when set, as mvnw does, else java on PATH.
export function javaVersion() {
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
  const result = spawnSync(java, ['-version'], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`${java} -version failed: ${result.error?.message ?? result.stderr}`);
  return (result.stderr + result.stdout).trim();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(fileURLToPath(import.meta.url), '..', '..');
  for (const { name, target, key } of partitions(root, javaVersion())) {
    console.log([name, target, key].join('\t'));
  }
}
