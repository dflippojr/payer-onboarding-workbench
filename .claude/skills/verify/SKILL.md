---
name: verify-payer-workbench
description: Launch and check payer-onboarding-workbench in the real app, not only in unit tests. Starts a disposable synthetic instance, runs doctor health and isolation checks, drives the main onboarding path (or one feature) in desktop and phone browsers, saves evidence, and cleans up every process it started. Use for "verify this change", "launch and check", "does it work in the app", "smoke test", or before saying a UI or API change works.
---

# Verify payer-onboarding-workbench

[docs/ui-testing.md](../../../docs/ui-testing.md) is the contract for the disposable instance. This skill calls the same scripts and does not restate its rules. Read the contract's "Scope and isolation" section for prerequisites and isolation guarantees before the first run.

One command runs all five steps. Cleanup runs even when an earlier step fails:

```sh
node .claude/skills/verify/scripts/verify.mjs                 # whole main path
node .claude/skills/verify/scripts/verify.mjs --feature report # only the area you changed
```

It prints `VERIFY_EVIDENCE=<folder>` and exits non-zero if any step fails. Read `<folder>/summary.md` first. Run one verification per worktree at a time, because the contract allows one mutating worker.

## 1. Launch

Build the jar and install browsers as "Scope and isolation" describes. JDK 21 must be on `JAVA_HOME`. `verify.mjs` then runs `node scripts/ui-instance.mjs start` from the contract's "Start" section as an owned child process. It refuses to run when `.ui-test/instance.json` already exists, because that instance is not this run's to stop. Before anything else it writes `launch.json` to the evidence folder. After readiness it adds the launcher, supervisor and Java PIDs, the app and control ports, the instance data directory and the log paths from the handle.

## 2. Doctor

`scripts/doctor.mjs` is read-only. Run it alone against an instance you started with `node .claude/skills/verify/scripts/doctor.mjs [--expect-port=N]`. It prints PASS or FAIL for each check and exits 1 on any failure:

| Check | Passes when |
| --- | --- |
| handle | the handle says `ready` and records Java and supervisor PIDs |
| loopback-url | app and control URLs are `http://127.0.0.1:<port>`, on the expected port |
| health | `/actuator/health` reports `UP` |
| loopback-only | the app port refuses connections on every non-loopback interface address |
| seed-payers, seed-samples | exactly the three `*-synthetic` payers, and `order-sign-hospital-bed` is listed |
| custom-endpoints-off | `/api/features` reports `customEndpoints: false` |
| data-path, log-path | data is a `ui-workbench-*` directory directly under OS temp, and the log is `.ui-test/app.log` |
| environment | no `SPRING_*`, `WORKBENCH_*` or Java option overrides, and no credential-named variables |

The doctor never prints variable values or interface addresses. If doctor fails, drive is skipped and cleanup still runs.

## 3. Drive

`scripts/drive.mjs` runs `drive/main-path.spec.ts` through Playwright Test with one worker. It runs in the `desktop` project (Chromium 1440x900) and the `phone` project (iPhone SE WebKit), against the launched instance only. It reuses `ready`, `runOnboarding`, `reopen` and `auditEvent` from `tests/ui/fixtures.ts`. Pass `--feature <name>` to drive one row of the feature map.

### Feature map

| Feature | Page / route | How it is driven | What proves it |
| --- | --- | --- | --- |
| `healthy` | `/`, `POST /api/runs` | Northwind synthetic, SANDBOX, `order-sign-hospital-bed`, faults reset, Run onboarding | six steps including Discovery and Send sample hook request, "Done: no failures.", `run.completed` audit with matching run ID |
| `failure` | `/` Findings section | same choice plus the "Discovery is down" fault, run, open Evidence | "broke at: Discovery", `discovery.reachable` FAIL finding with a visible fix, evidence disclosure opens |
| `report` | `GET /api/runs/{id}/report` (Download report) | failed run, reopen from Recent runs, download HTML | report contains the run ID, FAIL and the synthetic disclaimer, `report.rendered` audit; copy saved under `reports/` |
| `reset` | `/` form | check a fault and fill igVersion, then Reset faults and settings, then run | fault and setting cleared, next run is "Done: no failures." |

When you change something outside this map, add a row and a tagged test in `drive/main-path.spec.ts`. Keep larger journeys in `tests/ui` (see the contract's "Journeys" section). The `selftest-fail` tag is not a feature. It fails on purpose so that `cleanup.test.mjs` can exercise cleanup.

## 4. Evidence

Evidence is saved in `.verify/<timestamp>/`, which git ignores:

- `summary.md`: result, commit, a table of step results, doctor output, drive tally, screenshots and cleanup checks
- `launch.json` and `launch.log`: recorded PIDs, ports and paths, plus the launcher output
- `doctor.txt`, `drive.log` and `playwright/` (traces for failed tests only)
- `screenshots/<desktop|phone>-<feature>.png` (full page) and `reports/` (downloaded diagnostic reports)
- `logs.txt`: startup, audit, WARN and ERROR lines from `.ui-test/app.log`, and the tail of `supervisor.log`

Attach or quote `summary.md` when you report the result.

## 5. Cleanup

`scripts/cleanup.mjs <evidence-dir>` runs automatically, and you can rerun it by hand if a run was interrupted. It runs the contract's "Teardown" command, `node scripts/ui-instance.mjs stop`, but only when this run created the handle. Then it stops any recorded PID that is still alive, by that PID only, never by name or port. On Windows it uses `taskkill /T`. On POSIX it signals the process group. It removes the data directory with the same `ui-workbench-*` guard the launcher uses. Then it checks that every recorded PID has exited, that the handle and data directory are gone, and that the app and control ports are free. It writes `cleanup.json` and fails the run if any check fails. Playwright closes its own browsers. They are children of the recorded drive PID, so killing that PID's process tree covers them.

## Tests

`npm run test:verify` runs the doctor unit tests (healthy, not ready, non-loopback, missing seed, environment) and an integration test. The integration test launches a real instance, fails the drive step on purpose and checks that nothing is left behind. The integration test is skipped when the jar is not built.
