# diagnostics

Turns what an onboarding run observed (`RunObservations` from `workbench-core`) into findings an integration engineer can act on: what went wrong, the evidence, why it matters and what to try.

```java
List<Finding> findings = new DiagnosticEngine().run(observations);
```

`DiagnosticEngine` runs every check and returns the findings most severe first (`FAIL`, `WARN`, `INFO`, `PASS`). A healthy run yields `PASS` findings for what was verified, not an empty list. Checks that do not apply to a run (for example token checks when no token was requested) add nothing. A check that throws is reported as a `WARN` under its own id and does not stop the others.

Thresholds and expectations are set with `DiagnosticsConfig`: the hooks the caller needs (default `order-sign`), the latency budgets (5 s warn, 10 s fail) and the clock-skew tolerance (60 s).

## Check catalog

| checkId | Detects | Severities |
|---|---|---|
| `discovery.reachable` | The discovery endpoint (`GET .../cds-services`) is unreachable, returns a status other than 200, isn't JSON, or has no `services` array. | FAIL / PASS |
| `discovery.services` | No CRD hooks advertised; hooks the caller needs (`DiagnosticsConfig.requiredHooks`) are missing. | FAIL / PASS |
| `discovery.prefetch-keys` | Prefetch keys other than the standard `patient`, `encounter`, `coverage` that the router library builds. Each key is mapped to the standard key its FHIR query implies. Reported, not failed. | INFO / PASS |
| `auth.token` | Token endpoint unreachable, 401 / `invalid_client`, 400 `invalid_scope`, other OAuth2 errors, no `access_token`, missing `expires_in` (WARN). | FAIL / WARN / PASS |
| `auth.client-assertion` | SMART Backend Services assertion accepted (PASS), or identity (`iss`/`sub`), exact `aud`, lifetime (`exp`/`iat`), replay (`jti`), and signature rejection explained from allowed claims and payer `error_description`. | FAIL / PASS |
| `auth.jwt-audience` | A 401 (or 400 `invalid_client`/`invalid_grant`) after sending a JWT whose `aud` isn't exactly the URL it was sent to: trailing slash, extra or missing path segment such as `/r4`, other host, scheme or port. Also a hook-call 401 whose error is about the audience when the CDS Hooks client JWT's `aud` already is the service URL, so the payer expects some other URL. INFO if the payer accepted a mismatch anyway. | FAIL / INFO / PASS |
| `auth.clock-skew` | Rejections consistent with `exp`/`iat` skew: the error mentions token timing, or the JWT's `iat`/`exp` disagrees with the payer's `Date` header by more than the tolerance. WARN if the skew was accepted. | FAIL / WARN / PASS |
| `ig.version` | The payer's CRD IG version differs from the connection record's `igVersion`. FAIL if the major version differs, otherwise WARN. INFO if either side doesn't state a version. | FAIL / WARN / INFO / PASS |
| `response.schema` | Hook calls that return an error status, except a 401 that `auth.jwt-audience` already explains. Responses without a `cards` array. Cards missing `summary`, `indicator` or `source.label`. An `indicator` other than `info`/`warning`/`critical`. A summary over 140 characters is a WARN. | FAIL / WARN / PASS |
| `response.coverage-location` | Coverage information (`ext-coverage-information`) sent in card suggestions instead of `systemActions`. The library handles both; the finding explains the interop risk. | INFO / PASS |
| `response.coverage-information` | Router validation of every coverage-information extension in action resources against CRD 2.2.1; evidence includes the resource, path and message. Legacy `identifier` warns. No extensions means no finding. | FAIL / WARN / PASS |
| `perf.latency` | Hook latency over budget (default WARN above 5 s, FAIL above 10 s, where CDS Hooks clients often time out) and timed-out hook calls. | FAIL / WARN / PASS |
| `tls.handshake` | TLS/mTLS failures and their likely cause: untrusted server CA, expired server certificate, hostname mismatch, missing client certificate, rejected client certificate, no common protocol version. | FAIL / PASS |

## Where checks find their data

- **Client assertion observations.** The app records only `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, and `kid` in `RunObservations.clientAssertion` before the SDK discards the token request body. `auth.client-assertion` uses this metadata; it never reads or stores a signed assertion.
- **JWT claims.** `Redactor` keeps a JWT's header and payload but masks its signature, so `auth.jwt-audience` and `auth.clock-skew` can read the claims of a `client_assertion` in a token request body. A bearer JWT in an `Authorization` header is masked in full, so for a CDS Hooks client JWT the caller records its non-secret claims (`iss`, `aud`, `exp`, `iat`, `jti`, `kid`) in `HookResponse.clientJwt`, never the token or signature. `auth.jwt-audience` reads `aud` from there.
- **Payer clock.** The payer's clock is taken from the `Date` response header.
- **IG version.** CDS Hooks has no standard field for the payer's IG version. `ig.version` reads it from a discovery `extension` key containing `igVersion`, `ig-version` or `ig_version` (at the top level or on a service). Failing that, it uses a versioned Da Vinci CRD canonical URL (`...davinci-crd/...|2.0.1`) in a hook response.
- **Evidence redaction.** Evidence quotes redacted exchanges. `Finding` runs evidence through `Redactor` again as a safety net. `FindingRedactionTest` proves that an access token, a client secret, a private key and a JWT signature never appear in any finding, even when the payer echoes them back.

## Tests

The fixtures are hand-written `RunObservations` built in `Fixtures` (under `src/test/java`), with JSON bodies under `src/test/resources/fixtures`. `Fixtures.healthy()` passes every check, and each test swaps in one fault. Run them with:

```sh
./mvnw -pl diagnostics -am test
```
