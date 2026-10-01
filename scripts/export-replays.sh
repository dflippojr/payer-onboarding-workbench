#!/usr/bin/env bash
# Exports a static replay bundle for embedding on a website: builds the workbench,
# starts it on a free port, records a fixed set of runs through the REST API and
# writes site-dist/ (gitignored):
#
#   site-dist/runs/<id>.json   each run's redacted report (GET /api/runs/{id}/report?format=json)
#   site-dist/manifest.json    workbench version, git commit, generation time, run list
#   site-dist/replay.js        ES module exporting mountReplay(el, { baseUrl })
#   site-dist/replay.css       styles, themeable through CSS custom properties
#   site-dist/index.html       a small page that mounts the replay
#
#   scripts/export-replays.sh                     build, then record
#   EXPORT_SKIP_BUILD=1 scripts/export-replays.sh reuse workbench-app/target/*.jar
#
# Copy the bundle into a site with: node scripts/vendor-into-site.mjs <site>/public/workbench
# Needs JDK 21 (JAVA_HOME or java on PATH), curl, awk and git. Synthetic payers only.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/site-dist"
work="$root/target/export-replays"
cd "$root"

java_bin="java"
if [ -n "${JAVA_HOME:-}" ]; then
  java_bin="$JAVA_HOME/bin/java"
fi

if [ "${EXPORT_SKIP_BUILD:-0}" != "1" ]; then
  echo "==> Building (tests skipped; run ./mvnw verify for those)"
  ./mvnw -B -q -pl workbench-app -am package -DskipTests
fi
jar="$(ls workbench-app/target/workbench-app-*.jar | grep -v '\.original$' | head -1)"

rm -rf "$out" "$work"
mkdir -p "$out/runs" "$work"
log="$work/app.log"

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
entries=()
version=""

# record ID TITLE DESCRIPTION PAYER FAULT EXPECTATIONS...
# FAULT is "-" for a healthy run. Each expectation is "SEVERITY checkId", "no FAIL" or "a FAIL".
# TITLE and DESCRIPTION go into manifest.json as-is, so keep them free of quotes and backslashes.
record() {
  local id="$1" title="$2" description="$3" payer="$4" fault="$5"
  shift 5
  local faults="[]" fault_json="null"
  if [ "$fault" != "-" ]; then
    faults="[\"$fault\"]"
    fault_json="\"$fault\""
  fi
  echo
  echo "==> $title"
  local response run_id file="$out/runs/$id.json"
  response="$(curl -sS --fail-with-body -H 'Content-Type: application/json' \
    -d "{\"payerId\":\"$payer\",\"sampleId\":\"order-sign-hospital-bed\",\"faults\":$faults}" "$base/api/runs")"
  run_id="$(printf '%s' "$response" | grep -oE '"runId" *: *"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  curl -sS --fail-with-body -o "$file" "$base/api/runs/$run_id/report?format=json"

  # Findings list checkId before severity; steps have no checkId.
  local found verdict
  found="$(awk -F'"' '/"checkId" *:/ { id = $4 } /"severity" *:/ && id { print $4 " " id; id = "" }' "$file")"
  verdict="$(awk -F'"' '/"verdict" *:/ { v = 1 } v && /"status" *:/ { print $4; exit }' "$file")"
  if [ -z "$version" ]; then
    version="$(awk -F'"' '/"workbenchVersion" *:/ { print $4; exit }' "$file")"
  fi
  echo "    Verdict: $verdict"
  echo "    FAIL/WARN: $(printf '%s\n' "$found" | grep -E '^(FAIL|WARN) ' | tr '\n' ' ' || true)"
  for expected in "$@"; do
    if [ "$expected" = "no FAIL" ]; then
      if printf '%s\n' "$found" | grep -q '^FAIL '; then
        echo "    MISSING: expected no FAIL findings" >&2
        failures=$((failures + 1))
      fi
    elif [ "$expected" = "a FAIL" ]; then
      if ! printf '%s\n' "$found" | grep -q '^FAIL '; then
        echo "    MISSING: expected at least one FAIL finding" >&2
        failures=$((failures + 1))
      fi
    elif ! printf '%s\n' "$found" | grep -qxF "$expected"; then
      echo "    MISSING: expected finding $expected" >&2
      failures=$((failures + 1))
    fi
  done
  entries+=("$(printf '    {\n      "id": "%s",\n      "title": "%s",\n      "description": "%s",\n      "payerId": "%s",\n      "fault": %s,\n      "verdict": "%s",\n      "file": "runs/%s.json"\n    }' \
    "$id" "$title" "$description" "$payer" "$fault_json" "$verdict" "$id")")
  echo "    site-dist/runs/$id.json"
}

record northwind-healthy "Northwind, healthy" \
  "OAuth2 client credentials payer; every step passes." \
  northwind-synthetic - "no FAIL" "PASS auth.token"

record fabrikam-healthy "Fabrikam, healthy" \
  "CDS Hooks JWT payer; every step passes." \
  fabrikam-synthetic - "no FAIL" "PASS response.schema"

record fabrikam-wrong-audience-reject "Fabrikam rejects the token audience" \
  "The payer checks the JWT aud against a different URL and rejects the hook call." \
  fabrikam-synthetic wrong-audience-reject "a FAIL"

record northwind-expired-token-401 "Northwind says the token expired" \
  "Hook calls get 401 invalid_token with an expired-token message." \
  northwind-synthetic expired-token-401 "a FAIL"

record fabrikam-malformed-card "Fabrikam returns malformed cards" \
  "Cards come back without summary and indicator." \
  fabrikam-synthetic malformed-card "FAIL response.schema"

echo
echo "    (the next run holds every payer response for about 11 s)"
record northwind-slow-response "Northwind is slow" \
  "Every payer response is held past the latency budget." \
  northwind-synthetic slow-response "FAIL perf.latency"

cp replay/replay.js replay/replay.css replay/index.html "$out/"

commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
if [ "$commit" != "unknown" ] && [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  commit="$commit-dirty"
fi
{
  printf '{\n'
  printf '  "name": "payer-onboarding-workbench replay bundle",\n'
  printf '  "workbenchVersion": "%s",\n' "$version"
  printf '  "gitCommit": "%s",\n' "$commit"
  printf '  "generatedAt": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "disclaimer": "Recorded run against a synthetic mock payer. Passing here does not prove real-payer interoperability.",\n'
  printf '  "runs": [\n'
  for i in "${!entries[@]}"; do
    if [ "$i" -gt 0 ]; then printf ',\n'; fi
    printf '%s' "${entries[$i]}"
  done
  printf '\n  ]\n}\n'
} >"$out/manifest.json"

if grep -rlE 'PRIVATE KEY|client_secret=[^[]' "$out" >/dev/null 2>&1; then
  echo "The bundle contains unredacted key or secret material" >&2
  failures=$((failures + 1))
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "Export FAILED: $failures expectation(s) not met. The partial bundle is in site-dist/." >&2
  exit 1
fi
echo "Export done: ${#entries[@]} runs in site-dist/. Check it with: node --test replay/test/bundle.test.mjs"
