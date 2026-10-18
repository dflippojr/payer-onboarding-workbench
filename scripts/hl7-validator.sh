#!/usr/bin/env bash
# The official HL7 FHIR Validator as an outside judge of the workbench's response checks
# (diagnostics HL7ValidatorConformanceTest), at the versions pinned in scripts/hl7-validator.env.
#
#   bash scripts/hl7-validator.sh warm        download the pinned jar (SHA-256 checked) and load the
#                                             CRD package and its dependencies into the package cache:
#                                             the only step that uses the network
#   bash scripts/hl7-validator.sh test        run the differential test offline (-no-http-access)
#   bash scripts/hl7-validator.sh warm test   both
#
# Needs bash, curl, sha256sum and JDK 21. The cache is HL7_VALIDATOR_CACHE (default
# ~/.cache/hl7-validator): the jar in <version>/, the FHIR packages in home/.fhir/packages (the
# validator runs with user.home set to home/). The first warm downloads about 40 packages (3.5 GB).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=hl7-validator.env
source "$root/scripts/hl7-validator.env"
cache=${HL7_VALIDATOR_CACHE:-$HOME/.cache/hl7-validator}
export HL7_VALIDATOR_JAR=$cache/$VALIDATOR_VERSION/validator_cli.jar
export HL7_VALIDATOR_HOME=$cache/home

check_jar() {
  echo "$VALIDATOR_SHA256  $HL7_VALIDATOR_JAR" | sha256sum -c --quiet -
}

warm() {
  if [ ! -f "$HL7_VALIDATOR_JAR" ]; then
    mkdir -p "$(dirname "$HL7_VALIDATOR_JAR")"
    curl -sSfL -o "$HL7_VALIDATOR_JAR.part" \
      "https://github.com/hapifhir/org.hl7.fhir.core/releases/download/$VALIDATOR_VERSION/validator_cli.jar"
    mv "$HL7_VALIDATOR_JAR.part" "$HL7_VALIDATOR_JAR"
  fi
  check_jar
  # Written after a successful warm, so a restored cache skips the slow online run.
  local marker="$HL7_VALIDATOR_HOME/.warm-$VALIDATOR_VERSION-${IG//#/-}"
  if [ -f "$marker" ]; then
    echo "warm: validator $VALIDATOR_VERSION and $IG are already cached in $cache"
    return
  fi
  mkdir -p "$HL7_VALIDATOR_HOME"
  local work
  work=$(mktemp -d)
  # One online run over an empty response loads the IG and every package it depends on.
  printf '{"cards": []}\n' > "$work/warm.json"
  java "-Xmx${HL7_VALIDATOR_XMX:-3g}" "-Duser.home=$HL7_VALIDATOR_HOME" -jar "$HL7_VALIDATOR_JAR" "$work/warm.json" \
    -version "$FHIR_VERSION" -ig "$IG" -tx n/a -profile "$PROFILE" -output "$work/out.json" > "$work/log.txt" 2>&1 || true
  if [ ! -s "$work/out.json" ]; then
    tail -n 50 "$work/log.txt"
    rm -rf "$work"
    echo "warm: the validator produced no report" >&2
    exit 1
  fi
  rm -rf "$work"
  touch "$marker"
  echo "warm: validator $VALIDATOR_VERSION and $IG are cached in $cache"
}

run_test() {
  if [ ! -f "$HL7_VALIDATOR_JAR" ]; then
    echo "No validator jar at $HL7_VALIDATOR_JAR; run: bash scripts/hl7-validator.sh warm" >&2
    exit 1
  fi
  check_jar
  cd "$root"
  ./mvnw -B -P hl7-validator -pl diagnostics -am test
}

[ $# -gt 0 ] || { sed -n '2,13p' "$0"; exit 2; }
for command in "$@"; do
  case "$command" in
    warm) warm ;;
    test) run_test ;;
    *) echo "unknown command: $command (warm or test)" >&2; exit 2 ;;
  esac
done
