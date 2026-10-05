#!/usr/bin/env bash
# Exports a static replay bundle for embedding on a website: builds the workbench,
# starts it on a free port, records a fixed set of runs through the REST API and
# writes site-dist/ (gitignored):
#
#   site-dist/runs/<id>.json   each run's redacted report (GET /api/runs/{id}/report?format=json),
#                              with local addresses rewritten to example hosts (see rewrite_hosts)
#   site-dist/manifest.json    workbench version, git commit, generation time, run list
#   site-dist/replay.js        ES module exporting mountReplay(el, { baseUrl })
#   site-dist/replay.css       styles, themeable through CSS custom properties
#   site-dist/index.html       a small page that mounts the replay
#
#   scripts/export-replays.sh                     build, then record
#   EXPORT_SKIP_BUILD=1 scripts/export-replays.sh reuse workbench-app/target/*.jar
#
# Copy the bundle into a site with: node scripts/vendor-into-site.mjs <site>/public/workbench
# Needs JDK 21 (JAVA_HOME or java on PATH), curl, awk, sed and git. Synthetic payers only.
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

# The mock payers and the JWKS server listen on ephemeral localhost ports. The exported
# runs show each payer at a stable example host instead, and the workbench's JWKS at
# $workbench_host. Only the exported JSON is rewritten; the app records the real addresses.
workbench_host="https://workbench.example"
payer_host() {
  case "$1" in
    northwind-synthetic) echo "https://crd.northwind-health.example" ;;
    fabrikam-synthetic) echo "https://crd.fabrikam-benefits.example" ;;
    tailspin-synthetic) echo "https://crd.tailspin-health.example" ;;
    *) echo "https://crd.$1.example" ;;
  esac
}
# "origin host" pairs from GET /api/payers (compact JSON, fields in record order).
rewrites=()
current_payer=""
while read -r key value; do
  case "$key" in
    payerId) current_payer="$value" ;;
    baseUrl) rewrites+=("$(printf '%s' "$value" | grep -oE '^https?://[^/]+') $(payer_host "$current_payer")") ;;
    jwksUrl) rewrites+=("$(printf '%s' "$value" | grep -oE '^https?://[^/]+') $workbench_host") ;;
  esac
done < <(curl -sS --fail-with-body "$base/api/payers" | grep -oE '"(payerId|baseUrl|jwksUrl)" *: *"[^"]*"' \
  | sed -E 's/^"([^"]+)" *: *"([^"]*)"$/\1 \2/')
if [ "${#rewrites[@]}" -eq 0 ]; then
  echo "GET /api/payers listed no payer addresses to rewrite" >&2
  exit 1
fi

# rewrite_hosts FILE: replaces every recorded origin in FILE with its example host. The
# non-digit guard keeps http://localhost:8181 from matching inside http://localhost:81810.
rewrite_hosts() {
  local pair origin host
  for pair in "${rewrites[@]}"; do
    origin="$(printf '%s' "${pair%% *}" | sed 's/[.]/[.]/g')"
    host="${pair#* }"
    sed -E "s#${origin}([^0-9]|\$)#${host}\1#g" "$1" >"$1.tmp"
    mv "$1.tmp" "$1"
  done
}

failures=0
entries=()
version=""

# record ID TITLE TEASER DESCRIPTION PAYER FAULT EXPECTATIONS...
# TEASER is the one line on the replay's scenario card saying what breaks.
# FAULT is "-" for a healthy run. Each expectation is "SEVERITY checkId", "no FAIL" or "a FAIL".
# TITLE, TEASER and DESCRIPTION go into manifest.json as-is, so keep them free of quotes and backslashes.
record() {
  local id="$1" title="$2" teaser="$3" description="$4" payer="$5" fault="$6"
  shift 6
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
  rewrite_hosts "$file"

  # Findings list checkId before severity; steps have no checkId.
  local found verdict payer_name
  found="$(awk -F'"' '/"checkId" *:/ { id = $4 } /"severity" *:/ && id { print $4 " " id; id = "" }' "$file")"
  verdict="$(awk -F'"' '/"verdict" *:/ { v = 1 } v && /"status" *:/ { print $4; exit }' "$file")"
  payer_name="$(awk -F'"' '/"displayName" *:/ { print $4; exit }' "$file")"
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
  entries+=("$(printf '    {\n      "id": "%s",\n      "title": "%s",\n      "teaser": "%s",\n      "description": "%s",\n      "payerId": "%s",\n      "payerName": "%s",\n      "fault": %s,\n      "verdict": "%s",\n      "file": "runs/%s.json"\n    }' \
    "$id" "$title" "$teaser" "$description" "$payer" "$payer_name" "$fault_json" "$verdict" "$id")")
  echo "    site-dist/runs/$id.json"
}

record northwind-healthy "Northwind, healthy" "Healthy connection" \
  "OAuth2 client credentials payer; every step passes." \
  northwind-synthetic - "no FAIL" "PASS auth.token"

record fabrikam-healthy "Fabrikam, healthy" "Healthy connection" \
  "CDS Hooks JWT payer; every step passes." \
  fabrikam-synthetic - "no FAIL" "PASS response.schema"

record fabrikam-wrong-audience-reject "Fabrikam rejects the token audience" "Payer expects a different JWT audience" \
  "The payer checks the JWT aud against a different URL and rejects the hook call." \
  fabrikam-synthetic wrong-audience-reject "a FAIL"

record northwind-expired-token-401 "Northwind says the token expired" "Token rejected as expired" \
  "Hook calls get 401 invalid_token with an expired-token message." \
  northwind-synthetic expired-token-401 "a FAIL"

record fabrikam-malformed-card "Fabrikam returns malformed cards" "Cards come back malformed" \
  "Cards come back without summary and indicator." \
  fabrikam-synthetic malformed-card "FAIL response.schema"

echo
echo "    (the next run holds the hook call for about 11 s)"
record northwind-slow-response "Northwind is slow" "Payer is slow" \
  "Discovery and auth answer quickly, but the hook call is held past the latency budget." \
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
  printf '  "disclaimer": "Recorded run against a synthetic mock payer; addresses rewritten to example hosts. Passing here does not prove real-payer interoperability.",\n'
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
if grep -rlE 'localhost|127\.0\.0\.1' "$out" >/dev/null 2>&1; then
  echo "The bundle still contains local addresses:" >&2
  grep -rlE 'localhost|127\.0\.0\.1' "$out" >&2
  failures=$((failures + 1))
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "Export FAILED: $failures expectation(s) not met. The partial bundle is in site-dist/." >&2
  exit 1
fi
echo "Export done: ${#entries[@]} runs in site-dist/. Check it with: node --test replay/test/bundle.test.mjs"
