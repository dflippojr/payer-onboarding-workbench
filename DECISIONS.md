# Decisions

Choices made while planning the workbench (issue #1). Each has a short rationale so the owner can override it; changing one means a new issue, not a silent edit.

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Java 21, Maven wrapper, Spring Boot 4.1.x, MIT license.** | Matches the sibling `integration-failure-lab` (Java 21, Boot 4.1.1, `./mvnw`), so both projects share tooling and conventions. Java 21 can consume the router's Java 17 artifacts. The wrapper means no system-wide Maven is needed. MIT matches the router and the lab. |
| 2 | **Consume fhir-crd-router `directory-core` and `client-sdk`, pinned to commit `a5f013eed94024b72ccc2bf4fd89c73b5460da12` (router PR #16, CoverageInformationValidator), installed from source by `scripts/install-crd-router.sh` (and `.ps1`) into `.deps/` (gitignored). CI does the same before building. Use the router's own version (`0.1.0-SNAPSHOT`).** | The router is not on Maven Central yet (its own issue #2). Pinning a commit keeps builds reproducible without changing the router repo, which must stay usable on its own; the workbench is an optional consumer. When the router is published, swap the script for a normal dependency version in the parent POM (`fhir-crd-router.version`). |
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
- **The demo keeps the default latency budgets**, so the `slow-response` run takes about 11 s but shows what a real slow payer looks like.

## Implementation choices made in #14

- **Hook-call JWT claims ride on `HookResponse`.** The additive `workbench-core` change is a `JwtClaims` record (`iss`, `aud`, `exp`, `iat`, `jti`, `kid`) on an optional `HookResponse.clientJwt`, so each claim set stays tied to the call that carried it. The four-argument constructor is kept. The token, its encoded parts and its signature are never stored.
- **An exact `aud` can still be an audience failure.** With `wrong-audience-reject` the workbench's `aud` already is the service URL, and the payer validates against another one. Comparing `aud` with the URL alone would miss that, so `auth.jwt-audience` also FAILs a hook-call 401 whose error (body or `WWW-Authenticate`) mentions `aud` or the audience, and quotes the first other URL the payer names.
- **One 401, one finding.** `response.schema` skips a hook-call 401 that `auth.jwt-audience` FAILs, so the report points at the audience and nowhere else.

## Implementation choices made in #15

- **The replay bundle lives in `replay/` and is assembled into `site-dist/` by the export scripts.** `site-dist/` is gitignored and rebuilt from scratch on every export, so recorded runs (with their run ids, ephemeral ports and timestamps) never land in git.
- **`replay.js` ports `app.js`'s rendering instead of importing it.** `app.js` is a non-module script served by Spring, and it renders the live run result. The bundle renders the report JSON, which has a different step shape (`status` and `elapsedMs` at the top level). The element builder and formatting helpers are copied as-is. If either UI's rendering changes, keep the two in step by hand.
- **The replay plays runs back on a scaled clock but never shows scaled numbers (#21).** Recorded steps mostly take a few ms, so each step is shown for `clamp(ms × 0.25, 350, 1200)` ms, with the whole run capped at 6 s. Every latency on screen is the recorded one. Playback stops at the report's `brokeAt` step. Later steps are greyed out but keep their recorded status, so `Run diagnostics`, which still ran after a broken flow, reads "failed" rather than a made-up "skipped". The report has no latency budgets in it, so the slow-payer bar parses the budget from the `perf.latency` finding's explanation and falls back to `LatencyCheck`'s 5 s and 10 s defaults. It picks the step by matching the method and URL in the finding's evidence, rather than taking the slowest step.
- **Expectations for the token faults are loose.** The export script expects any `FAIL` for `wrong-audience-reject` and `expired-token-401`, and specific checks only for `malformed-card` (`response.schema`) and `slow-response` (`perf.latency`). That way a diagnostics change (#14) that renames or adds a token check does not break the export.
- **The leak test re-implements `Redactor`'s patterns in JavaScript** (`replay/test/leaks.mjs`), so it needs no Java. It also self-tests against synthetic secrets it generates at runtime, so a pattern that silently stops matching shows up as a failure. Keep `leaks.mjs` in step with `Redactor.java`.
- **The colour tokens fall back in two steps:** `--pw-*` reads the host's `--paper`, `--ink` and so on, then falls back to a neutral default. A site with the lab's tokens is themed without extra CSS, and one without them still gets readable light and dark colours.

## Implementation choices made in #23

- **Replays show example hosts, rewritten by the export scripts.** After redaction, each export script reads the payers' base URLs and the JWKS URL from `GET /api/payers` and replaces those origins in each run's JSON: `https://crd.northwind-health.example`, `https://crd.fabrikam-benefits.example` and `https://workbench.example`. It is a plain text replacement on the exported file, so every field changes together, and the export fails if any `localhost` or `127.0.0.1` is left. The app and its reports keep recording the real addresses.
- **Fabrikam's expected audience moved to `https://api.fabrikam-benefits.example`.** It used to be `https://crd.fabrikam-benefits.example`, which is now the host the replays show Fabrikam at, so the rewritten `aud` would have matched it. The `api.` host keeps the finding's story (the payer validates against its public gateway URL) true in both the live app and the replays.
- **`slow-response` holds only `POST /cds-services/{id}`.** Delaying discovery and the token endpoint too made every step of the slow replay take about 11 s, which hid the point: the hook call is what clinicians wait on, and it is the only call `perf.latency` measures.

## Real TLS for synthetic payers (#30)

Generate a test CA, a second untrusted CA, and server certificates using BouncyCastle `bcpkix-jdk18on`. The JDK has no public certificate-building API; shelling out to keytool would persist key material. All TLS identities and trust stores stay in memory. Both app-hosted payers use HTTPS; standalone launchers retain HTTP by default and accept `--tls`. A key manager selects the certificate from the current fault settings, with precedence untrusted, expired, then wrong hostname when several are selected.

Each onboarding run uses a fresh HttpClient and SSLContext trusting only the test CA. This prevents pooled connections and resumed TLS sessions from bypassing fault selection, and leaves JVM default trust untouched. Retire the simulated `tls-required` response in favor of actual handshake failures.

Keep the app's JWKS endpoint on loopback HTTP: it serves only the public JWT verification key, and Fabrikam?s existing fetcher can continue to use its default client without receiving the payer CA trust configuration. Payer discovery, OAuth token requests and hook requests all use HTTPS.

## Observability (#34)

- **The run id is the correlation id.** One id per run is enough to match a call in the payer's logs, and reusing the run id means the report, the API and the logs never disagree. It is a random UUID, so it carries no data.
- **`X-Request-Id` is added by a transport decorator, not by the SDK.** The router SDK has no hook for extra headers, so `RequestIdClient` wraps the `HttpClient` the SDK sends through, which covers discovery, token and hook calls (retries too). The SDK reports the request it built, before the decorator ran, so `ExchangeRecorder` adds the header to each recorded request. The mock's echo on the response is the independent proof that the payer got it. A connection with mutual TLS would bypass the decorator, because the SDK builds its own client for those; none of the synthetic payers use mutual TLS.
- **`ForwardingHttpClient` holds the delegation that `JwtObservingClient` and `RequestIdClient` share.** Both only change or inspect the request on its way out.
- **The mock logs a request at INFO only when it carries a well-formed request id.** Uncorrelated test and admin traffic stays quiet. A malformed id is neither logged nor echoed, and the logged path is the raw (still percent-encoded) path, so a request can't forge a log line.
- **The verdict tag reuses `RunReport`'s verdict rules,** so the metric and the report can't disagree. `broke_at` is the step id (`discovery`), not the report's title, and `none` when the flow completed.
- **Metrics are recorded per HTTP attempt,** so a 401 that the SDK retries shows as two `hook` samples, as it does in the timeline.

## SMART Backend Services synthetic payer (#31)

- **Tailspin is synthetic throughout.** It declares CRD 2.2.1 and shares Northwind's coverage determinations; its generated signing key is separate from Fabrikam's and memory only. The existing loopback JWKS server publishes both public keys.
- **Build on #35's SDK transport.** #35 (PR #37) merged after this issue was written and moved Northwind authentication to `CdsHooksClient`. Tailspin follows that same path: the SDK calls `JwtSigner.clientAssertion`, sends and retries token requests, and the workbench's `ExchangeRecorder` retains each redacted token exchange in the authenticate timeline. The transport decorator decodes only the seven allowed assertion claims before the SDK drops token request bodies. This preserves #35 and #34: `JwtObservingClient` uses the shared `ForwardingHttpClient.prepare()` hook, and `RequestIdClient` still sends the run correlation id on every discovery, token and hook attempt.
- **Assertion observations are metadata only.** `RunObservations.clientAssertion` carries `JwtClaims` with additive `sub`; old constructors remain usable. No signed assertion, encoded part, signature or private key is retained. `auth.client-assertion` uses these claims and `error_description` to explain audience, identity, lifetime and replay rejection. A successful token exchange produces PASS.
- **Verification uses registered URLs only.** Tailspin and Fabrikam share signature verification and JWKS refresh on unknown `kid`; an assertion's `jku` never chooses the verification URL. Tailspin validates RS384/ES384, exact identity and token endpoint audience, a future expiry no more than five minutes ahead, and atomically rejects replayed `jti` until expiry.
- **Export adds only an origin rewrite.** Tailspin maps to `https://crd.tailspin-health.example`; the six existing replay runs and site files remain the same.

## Redactor and the leak scanner share a corpus (#42)

- **`workbench-core/src/test/resources/redaction-corpus.json` is the contract between `Redactor.java` and `replay/test/leaks.mjs`.** `RedactorCorpusTest` and `replay/test/leaks.test.mjs` both run every entry, so a rule or field name that only one side handles fails CI. A new redaction rule gets its first test there, as an entry per shape plus a harmless near-miss. Every entry is synthetic and obviously fake.
- **`scannerOnly` marks a known gap.** JSON embedded in a JSON string (`\"access_token\":\"…\"`) is flagged by the scanner but not masked by `Redactor`, which sees recorded bodies before they are escaped into a report. The Java test pins that `Redactor` leaves such an entry alone, so closing the gap forces the flag to be removed.
