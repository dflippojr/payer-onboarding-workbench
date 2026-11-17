# Observability and metrics

## Observability

Each run has a correlation id, which is its run id. Payers ask for a request id when you report a failed call, so the workbench sends it as `X-Request-Id` on every discovery, token and hook call, shows it on each recorded request in the timeline, and prints it in all three report formats (the `Correlation id (X-Request-Id)` row, or `correlationId` in JSON). The mock payers echo the header back on the response and log it with the method, path and status, so you can follow one call from the workbench's log to the payer's log:

```text
INFO ... [5dd4e05a-d342-478a-88c3-c65cca71958e] i.g.d.p.app.OnboardingRunner : step runId=5dd4e05a-d342-478a-88c3-c65cca71958e payer=northwind-synthetic step=discovery status=passed ms=221
INFO ... [] i.g.d.payerworkbench.mock.MockPayer : Northwind Health (synthetic): POST /oauth/token -> 200 requestId=5dd4e05a-d342-478a-88c3-c65cca71958e
```

While a run executes, its id is in the logging MDC (`runId`, shown in brackets on every log line, and `payer`). Each step logs one INFO line with the run id, payer, step, status and milliseconds. Request and response bodies are never logged. `OnboardingFlowTest` captures everything each of its tests logs and fails if the `Redactor` patterns would mask anything in it, or if a request or response body shows up.

Spring Boot Actuator exposes `/actuator/health`, `/actuator/info` and `/actuator/prometheus`, and no other endpoint. They share the API's port and so listen on loopback only. If you move them to a port of their own with `management.server.port`, also pass `--management.server.address=127.0.0.1`: that port does not use `server.address` and otherwise listens on every interface. (Spring Boot refuses `management.server.address` without a separate port, so it can't be the default.) A port of its own keeps the `Host` check described under [API](../README.md#api), with `management.server.address` as its bind literal. The run metrics are tagged with `payer` and `environment`. No tag carries a run id, URL or anything else with high cardinality.

| Metric | Type | Extra tags |
|---|---|---|
| `workbench.runs` | counter | `verdict` (`PASS`, `PASS_WITH_WARNINGS`, `FAIL`), `broke_at` (step id, or `none`) |
| `workbench.step.duration` | timer | `step`, `status` (`passed`, `failed`, `skipped`) |
| `workbench.payer.request.duration` | timer, one sample per HTTP attempt (a retried call counts twice) | `phase` (`discovery`, `token`, `hook`), `status_class` (`2xx`, `4xx`, `5xx`, `error` when no response arrived) |
| `workbench.findings` | counter | `check`, `severity` |

After one healthy Northwind run and one with `discovery-500` (excerpt):

```sh
$ curl -s localhost:8080/actuator/prometheus | grep workbench_
workbench_findings_total{check="discovery.reachable",environment="SANDBOX",payer="northwind-synthetic",severity="FAIL"} 1.0
workbench_findings_total{check="discovery.reachable",environment="SANDBOX",payer="northwind-synthetic",severity="PASS"} 1.0
workbench_payer_request_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",phase="discovery",status_class="2xx"} 1
workbench_payer_request_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",phase="discovery",status_class="5xx"} 1
workbench_payer_request_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",phase="hook",status_class="2xx"} 1
workbench_runs_total{broke_at="discovery",environment="SANDBOX",payer="northwind-synthetic",verdict="FAIL"} 1.0
workbench_runs_total{broke_at="none",environment="SANDBOX",payer="northwind-synthetic",verdict="PASS"} 1.0
workbench_step_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",status="failed",step="discovery"} 1
workbench_step_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",status="passed",step="discovery"} 1
workbench_step_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",status="passed",step="hook-request"} 1
workbench_step_duration_seconds_count{environment="SANDBOX",payer="northwind-synthetic",status="skipped",step="hook-request"} 1
```

`ObservabilityTest` checks the exposed endpoints and these counts. Runs are still kept in memory only, and there is no tracing.
