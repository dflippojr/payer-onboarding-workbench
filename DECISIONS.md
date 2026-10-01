# Decisions

Choices made while planning the workbench (issue #1). Each has a short rationale so the owner can override it; changing one means a new issue, not a silent edit.

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Java 21, Maven wrapper, Spring Boot 4.1.x, MIT license.** | Matches the sibling `integration-failure-lab` (Java 21, Boot 4.1.1, `./mvnw`), so both projects share tooling and conventions. Java 21 can consume the router's Java 17 artifacts. The wrapper means no system-wide Maven is needed. MIT matches the router and the lab. |
| 2 | **Consume fhir-crd-router `directory-core` and `client-sdk`, pinned to commit `7f5fd56`, installed from source by `scripts/install-crd-router.sh` (and `.ps1`) into `.deps/` (gitignored). CI does the same before building. Use the router's own version (`0.1.0-SNAPSHOT`).** | The router is not on Maven Central yet (its own issue #2). Pinning a commit keeps builds reproducible without changing the router repo, which must stay usable on its own; the workbench is an optional consumer. When the router is published, swap the script for a normal dependency version in the parent POM (`fhir-crd-router.version`). |
| 3 | **Maven multi-module layout:** `workbench-core` (pure Java domain and shared contracts, no Spring), `mock-payers` (two embedded synthetic CDS Hooks payers, #2), `diagnostics` (checks and engine, #3), `samples` (synthetic request payloads, #4), `workbench-app` (Spring Boot app, REST API and static UI, #5, #6). | One module per later issue lets three workers proceed in parallel without editing the same files. Keeping `workbench-core` free of Spring keeps the contracts reusable and fast to test. |
| 4 | **UI is static HTML/CSS/JS served by Spring Boot from `workbench-app/src/main/resources/static`, with no frontend build step.** | Same approach as the failure lab, so the UI can later be vendored into the personal website without a JS toolchain. |

## Implementation choices made in #1

These are smaller calls made while building the skeleton, recorded for the same reason.

- **Parent POM inherits `spring-boot-starter-parent`.** That gives one dependency-management source for every module. Only `workbench-app` depends on Spring; the other modules stay plain Java.
- **Redaction at construction time.** `HttpExchange` redacts headers and bodies, and `Finding` redacts `evidence`, in their constructors. That way secret material cannot reach a report even if a caller forgets to redact. `RunObservations` holds a `RedactedConnection` (credential references reduced to "configured: yes/no") and `TokenResponseMetadata` (never the token value).
- **JWTs keep header and payload; only the signature is masked.** Claims such as `iss`, `aud` and `exp` are the usual cause of token failures, so diagnostics need to see them. A JWT that is the value of a secret field such as `access_token`, or a bearer credential, is masked entirely.

## Implementation choices made in #6

- **Reports redact again, field by field.** `StepResult.details` is only documented as secret-free, so `RunReport` passes every string through `Redactor` and masks any field named like a secret before any format renders. All three formats render from that one sanitized model.
- **Workbench version from `build-info`.** The Spring Boot plugin's `build-info` goal writes `META-INF/build-info.properties`; reports read `build.version` from it (falling back to the jar manifest, then `unknown`).
- **The demo starts the app on port 0** and reads the port from the startup log, so it never collides with anything already listening. The bash script checks findings from the Markdown report with `awk` so it needs no `jq`; the PowerShell script reads the JSON report.
- **The demo keeps the default latency budgets**, so the `slow-response` run takes about 35 s but shows what a real slow payer looks like.
