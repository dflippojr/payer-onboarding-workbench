#!/usr/bin/env bash
# Repeatable demo: builds the workbench, starts it on a free port, runs a scripted
# tour through the REST API and writes each run's report to demo-output/ as
# Markdown, HTML and JSON. Exits non-zero if any expected finding is missing.
#
#   scripts/demo.sh               build, then run the tour
#   DEMO_SKIP_BUILD=1 scripts/demo.sh   reuse workbench-app/target/*.jar
#
# Needs JDK 21 (JAVA_HOME or java on PATH), curl and awk. Synthetic payers only.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/demo-output"
cd "$root"

java_bin="java"
if [ -n "${JAVA_HOME:-}" ]; then
  java_bin="$JAVA_HOME/bin/java"
fi

if [ "${DEMO_SKIP_BUILD:-0}" != "1" ]; then
  echo "==> Building (tests skipped; run ./mvnw verify for those)"
  ./mvnw -B -q -pl workbench-app -am package -DskipTests
fi
jar="$(ls workbench-app/target/workbench-app-*.jar | grep -v '\.original$' | head -1)"

rm -rf "$out"
mkdir -p "$out"
log="$out/app.log"

echo "==> Starting the workbench on a free port"
"$java_bin" -jar "$jar" --server.port=0 >"$log" 2>&1 &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true; wait "$app_pid" 2>/dev/null || true' EXIT

port=""
for _ in $(seq 1 120); do
  port="$(grep -oE 'started on port [0-9]+' "$log" | grep -oE '[0-9]+$' | head -1 || true)"
  if [ -n "$port" ]; then
    break
  fi
  if ! kill -0 "$app_pid" 2>/dev/null; then
    echo "The workbench exited during startup; see $log" >&2
    exit 1
  fi
  sleep 1
done
if [ -z "$port" ]; then
  echo "The workbench did not start within 120 s; see $log" >&2
  exit 1
fi
base="http://127.0.0.1:$port"
echo "    $base"

failures=0
step=0

# tour NAME TITLE REQUEST_JSON EXPECTATIONS...
# Each expectation is "SEVERITY checkId" (must be present), or "no FAIL".
tour() {
  local name="$1" title="$2" request="$3"
  shift 3
  step=$((step + 1))
  local prefix
  prefix="$(printf '%02d-%s' "$step" "$name")"
  echo
  echo "==> $step. $title"
  local response run_id
  response="$(curl -sS --fail-with-body -H 'Content-Type: application/json' -d "$request" "$base/api/runs")"
  run_id="$(printf '%s' "$response" | grep -oE '"runId" *: *"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  for format in md html json; do
    curl -sS --fail-with-body -o "$out/$prefix.$format" "$base/api/runs/$run_id/report?format=$format"
  done

  # "SEVERITY checkId" for every finding, read from the Markdown report's sections.
  local found
  found="$(awk '/^### (FAIL|WARN|INFO|PASS) \(/ { sev = $2 } /^Check: `/ { gsub(/`/, "", $2); print sev " " $2 }' "$out/$prefix.md")"
  echo "    $(grep -m1 -E '^## Verdict' "$out/$prefix.md" | sed 's/^## //')"
  echo "    FAIL/WARN: $(printf '%s\n' "$found" | grep -E '^(FAIL|WARN) ' | tr '\n' ' ' || true)"
  for expected in "$@"; do
    if [ "$expected" = "no FAIL" ]; then
      if printf '%s\n' "$found" | grep -q '^FAIL '; then
        echo "    MISSING: expected no FAIL findings" >&2
        failures=$((failures + 1))
      fi
    elif ! printf '%s\n' "$found" | grep -qxF "$expected"; then
      echo "    MISSING: expected finding $expected" >&2
      failures=$((failures + 1))
    fi
  done
  echo "    reports: demo-output/$prefix.{md,html,json}"
}

tour healthy-northwind "Northwind (OAuth2 client credentials), healthy" \
  '{"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed"}' \
  "no FAIL" "PASS discovery.reachable" "PASS auth.token" "PASS response.schema"

tour healthy-fabrikam "Fabrikam (CDS Hooks JWT), healthy" \
  '{"payerId":"fabrikam-synthetic","sampleId":"order-sign-hospital-bed"}' \
  "no FAIL" "PASS discovery.reachable" "PASS ig.version" "PASS response.schema"

tour fabrikam-wrong-audience "Fabrikam with wrong-audience-reject: the payer rejects the JWT audience" \
  '{"payerId":"fabrikam-synthetic","sampleId":"order-sign-hospital-bed","faults":["wrong-audience-reject"]}' \
  "FAIL auth.jwt-audience"

echo
echo "    (the next run holds every payer response for about 11 s)"
tour northwind-slow-response "Northwind with slow-response: every response is past the latency budget" \
  '{"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed","faults":["slow-response"]}' \
  "FAIL perf.latency"

if grep -lE 'PRIVATE KEY|client_secret=[^[]' "$out"/*.md "$out"/*.html "$out"/*.json >/dev/null 2>&1; then
  echo "A report contains unredacted key or secret material" >&2
  failures=$((failures + 1))
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "Demo FAILED: $failures expectation(s) not met. Reports are in demo-output/." >&2
  exit 1
fi
echo "Demo passed: $step runs, every expected finding present. Reports are in demo-output/."
