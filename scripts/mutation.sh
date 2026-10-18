#!/usr/bin/env bash
# Mutation testing for the diagnostics module: pitest (-P mutation in diagnostics/pom.xml) changes
# the checks' code one mutant at a time and runs their unit tests; a mutant every test still passes
# against is a rule no test pins down. Fails when the score is below pitest.mutation.floor.
#
#   bash scripts/mutation.sh
#
# Writes diagnostics/target/pit-reports/ (mutations.xml, index.html and summary.md, which lists the
# surviving mutants) and appends summary.md to $GITHUB_STEP_SUMMARY when it is set. Needs JDK 21 and
# fhir-crd-router installed (scripts/install-crd-router.sh).
#
# MUTATION_REUSE=true judges an existing mutations.xml instead of running pitest, but only when the
# fingerprint stored beside it matches scripts/mutation-fingerprint.mjs now (diagnostics, the modules
# it depends on, Maven, these scripts and the JDK). CI sets it when it restored the report from the
# cache keyed by that fingerprint, so unchanged inputs cost nothing. (Open-source pitest no longer
# ships per-mutant incremental history.)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
reports=diagnostics/target/pit-reports
status=0
fingerprint=$(node scripts/mutation-fingerprint.mjs)

if [ "${MUTATION_REUSE:-}" = true ] && [ -f "$reports/mutations.xml" ] \
  && [ "$(cat "$reports/fingerprint" 2>/dev/null)" = "$fingerprint" ]; then
  echo "Reusing $reports/mutations.xml: its inputs are unchanged since it was produced ($fingerprint)"
else
  rm -rf "$reports"
  ./mvnw -B -q -pl diagnostics -am install -DskipTests -Djacoco.skip=true
  ./mvnw -B -P mutation -pl diagnostics verify -Djacoco.skip=true || status=$?
  if [ -f "$reports/mutations.xml" ]; then
    echo "$fingerprint" > "$reports/fingerprint"
  fi
fi

if [ -f "$reports/mutations.xml" ]; then
  node scripts/mutation-summary.mjs "$reports/mutations.xml" diagnostics/pom.xml > "$reports/summary.md" || status=1
  cat "$reports/summary.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "$reports/summary.md" >> "$GITHUB_STEP_SUMMARY"
  fi
else
  echo "pitest wrote no $reports/mutations.xml" >&2
  status=1
fi
exit "$status"
