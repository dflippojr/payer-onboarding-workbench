#!/usr/bin/env bash
# Mutation testing for the diagnostics module: pitest (-P mutation in diagnostics/pom.xml) changes
# the checks' code one mutant at a time and runs their unit tests; a mutant every test still passes
# against is a rule no test pins down. Fails when the score is below pitest.mutation.floor.
#
#   bash scripts/mutation.sh
#
# Incremental: pitest runs once per diagnostics class (scripts/mutation-fingerprint.mjs lists them), and
# each class's mutations.xml is kept in diagnostics/target/pit-history/<class>/ beside the key of the inputs
# it was produced from. A class whose key still matches is not analysed again, so a changed check costs one
# class, and a changed shared file or test costs them all. CI restores pit-history from an earlier run
# (.github/workflows/ci.yml). pitest's own history needs arcmutate, which open-source pitest 1.30.0 lacks.
#
# Writes diagnostics/target/pit-reports/ (mutations.xml, merged from every class, and summary.md, which lists
# the surviving mutants) and appends summary.md to $GITHUB_STEP_SUMMARY when it is set. The floor is judged
# on the merged score. Needs JDK 21 and fhir-crd-router installed (scripts/install-crd-router.sh).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
history=diagnostics/target/pit-history
reports=diagnostics/target/pit-reports
status=0
partitions=$(node scripts/mutation-fingerprint.mjs)
names=()
files=()

./mvnw -B -q -pl diagnostics -am install -DskipTests -Djacoco.skip=true
mkdir -p "$history"

while IFS=$'\t' read -r name target key; do
  names+=("$name")
  dir="$history/$name"
  if [ -f "$dir/mutations.xml" ] && [ "$(cat "$dir/key" 2>/dev/null)" = "$key" ]; then
    echo "Reusing $name: its inputs are unchanged since its report was produced"
  else
    rm -rf "$dir" "$reports"
    echo "Analysing $name: pitest targetClasses $target"
    # The floor is judged on the merged score below, so a single class does not fail the run.
    ./mvnw -B -P mutation -pl diagnostics test-compile org.pitest:pitest-maven:1.30.0:mutationCoverage \
      -Djacoco.skip=true -Dpit.targetClasses="$target" -Dpitest.mutation.floor=0 \
      || { echo "pitest failed on $name" >&2; exit 1; }
    mkdir -p "$dir"
    mv "$reports/mutations.xml" "$dir/mutations.xml"
    echo "$key" > "$dir/key"
  fi
  files+=("$dir/mutations.xml")
done <<< "$partitions"

for dir in "$history"/*/; do
  case " ${names[*]} " in *" $(basename "$dir") "*) ;; *) rm -rf "$dir" ;; esac
done

rm -rf "$reports"
mkdir -p "$reports"
node scripts/mutation-merge.mjs "${files[@]}" > "$reports/mutations.xml"
node scripts/mutation-summary.mjs "$reports/mutations.xml" diagnostics/pom.xml > "$reports/summary.md" || status=1
cat "$reports/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$reports/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi
exit "$status"
