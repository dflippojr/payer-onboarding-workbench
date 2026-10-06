#!/usr/bin/env bash
# Measures the first onboarding run after startup (issue #53).
#
# For each of N fresh starts of the built jar: waits for GET /api/payers to return 200,
# then times POST /api/runs for northwind-synthetic and prints the wall time, the
# discovery and diagnostics step times, and the time from launch to the first 200.
# Uses only the mock payers. Build first: ./mvnw -DskipTests install
#
# Usage: scripts/measure-first-run.sh [starts=5] [port=18081]
set -euo pipefail

starts="${1:-5}"
port="${2:-18081}"
root="$(cd "$(dirname "$0")/.." && pwd)"
jar="$(ls "$root"/workbench-app/target/workbench-app-*-SNAPSHOT.jar | head -n 1)"
body='{"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed"}'
now_ms() { date +%s%3N; }
# elapsed of one step, in ms, from the run response (ISO-8601 seconds, e.g. PT0.1604992S)
step_ms() {
  grep -o "\"stepId\":\"$2\",\"startedAt\":\"[^\"]*\",\"elapsed\":\"PT[0-9.]*S\"" <<<"$1" \
    | sed 's/.*"PT\([0-9.]*\)S"/\1/' | awk '{printf "%.0f", $1 * 1000}'
}

if curl -s -o /dev/null "http://localhost:$port/" 2>/dev/null; then
  echo "something is already listening on port $port; stop it or pass another port" >&2
  exit 1
fi

walls=()
printf '%-6s %-14s %-12s %-16s %-18s\n' start first-run-ms discovery-ms diagnostics-ms launch-to-200-ms
for i in $(seq "$starts"); do
  log="$(mktemp)"
  t0="$(now_ms)"
  java -jar "$jar" --server.port="$port" >"$log" 2>&1 &
  pid=$!
  until curl -sf "http://localhost:$port/api/payers" >/dev/null 2>&1; do
    kill -0 "$pid" 2>/dev/null || { echo "app exited early; see $log" >&2; exit 1; }
    sleep 0.05
  done
  t1="$(now_ms)"
  out="$(curl -s -o - -w '\n%{time_total}' -X POST "http://localhost:$port/api/runs" \
    -H 'content-type: application/json' -d "$body")"
  secs="${out##*$'\n'}"
  json="${out%$'\n'*}"
  wall="$(awk -v s="${secs//,/.}" 'BEGIN{printf "%.0f", s * 1000}')"
  walls+=("$wall")
  printf '%-6s %-14s %-12s %-16s %-18s\n' "$i" "$wall" "$(step_ms "$json" discovery)" \
    "$(step_ms "$json" diagnostics)" "$((t1 - t0))"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$log"
done
median="$(printf '%s\n' "${walls[@]}" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')"
echo "median first-run wall: ${median} ms over ${starts} fresh starts"
