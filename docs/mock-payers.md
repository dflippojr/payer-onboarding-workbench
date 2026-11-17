# Mock payers and sample requests

## Mock payers

`mock-payers` contains three synthetic CDS Hooks payers built on the JDK's `com.sun.net.httpserver`. They behave differently on purpose, so the workbench has something realistic to onboard against. Tests start them in-process on an ephemeral port (`start(0)`). You can also run either one standalone. Every name, identifier and decision they return is made up.

**Northwind Health (synthetic)** follows the spec.

- Declares Da Vinci CRD 2.2.1. `GET /cds-services` lists `order-sign` and `order-select` with standard prefetch keys (`patient`, `encounter`, `coverage`).
- Auth is OAuth2 client credentials with `client_secret_basic` at `/oauth/token`. Tokens expire (5 minutes by default). Hook calls without a valid `Authorization: Bearer` token get 401.
- `order-sign` returns coverage information in `systemActions`. Outcomes depend only on the order code. E0250 is covered and needs prior auth. E0424 is covered with no auth. Any other code is conditional and needs clinical documentation.

**Fabrikam Benefits (synthetic)** is quirky in the same ways as the HL7 reference implementation.

- Declares the older CRD 2.0.1. Its prefetch keys are non-standard (`coverageBundle`, `deviceRequestBundle`).
- Puts coverage information inside card suggestions instead of `systemActions`.
- Auth is the CDS Hooks 2.0 client JWT. Fabrikam checks the signature against the client's JWKS, which it fetches from a URL you register per issuer. It also checks `iss`, that `aud` is exactly the service URL, and the times: `iat` is required and at most an hour ahead of the payer's clock, `exp` minus `iat` is at most five minutes (SMART Backend Services' cap, a profile choice of this mock rather than a CDS Hooks rule), and a `jti` is rejected as a replay until its `exp` passes. RS384 and ES384 are accepted.

**Tailspin Health Plan (synthetic)** exercises SMART Backend Services (`private_key_jwt`). Payer id `tailspin-synthetic`, CRD 2.2.1, standard prefetch keys, and coverage information in `systemActions` share Northwind's synthetic rules. Its `/oauth/token` endpoint accepts client credentials with the JWT bearer assertion type, verifies RS384 or ES384 against the registered client JWKS, requires `iss` = `sub` = client id and exact token endpoint `aud`, checks future `exp` at most five minutes ahead, and rejects reused `jti`. Rejections return `401 invalid_client` naming the claim. All faults apply; `wrong-audience-reject` expects `https://auth.tailspin-health.example/token` and breaks at authenticate.

### Start one standalone

Install the router first (`bash scripts/install-crd-router.sh`), then:

```bash
./mvnw -q -pl mock-payers -am install -DskipTests

# Northwind on port 8181 (the default). It prints a client secret generated for this run.
./mvnw -q -pl mock-payers exec:java \
  -Dexec.mainClass=io.github.dflippojr.payerworkbench.mock.NorthwindPayer \
  -Dexec.args="--port 8181 --client-id workbench-demo"

# Fabrikam on port 8182 (the default). Register each client as ISS=JWKS_URL.
./mvnw -q -pl mock-payers exec:java \
  -Dexec.mainClass=io.github.dflippojr.payerworkbench.mock.FabrikamPayer \
  -Dexec.args="--port 8182 --client https://ehr.example/client=http://localhost:9000/jwks.json"
```

Northwind options: `--port`, `--client-id`, `--client-secret` (generated if omitted), `--token-lifetime-seconds`, `--public-base-url`. Fabrikam and Tailspin options: `--port`, `--client ISS=JWKS_URL` (repeatable), `--public-base-url`. Tailspin runs as `io.github.dflippojr.payerworkbench.mock.TailspinPayer` with default port 8183; register clients with `--client ID=JWKS_URL`, just as for Fabrikam. Use `--port 0` for a free port. No keys or secrets are stored in the repo. Tests generate key pairs at runtime and serve the JWKS themselves.

### Fault injection

Each payer has the same faults. All are off by default and deterministic: while a fault is on, every affected request fails the same way. You can toggle them in code (`payer.faults().enable(Fault.MALFORMED_CARD)`) or over HTTP:

```bash
curl http://localhost:8181/admin/faults                                     # list faults and their state
curl -X POST "http://localhost:8181/admin/faults/slow-response?delayMs=3000" # turn one on
curl -X DELETE http://localhost:8181/admin/faults/slow-response             # turn one off
curl -X DELETE http://localhost:8181/admin/faults                           # turn all off
```

| Fault | What the client sees |
|-------|----------------------|
| `slow-response` | Hook calls (`POST /cds-services/{id}`) wait `delayMs` (default 2000) before they are handled. Discovery, the token endpoint and admin stay fast. |
| `expired-token-401` | Hook calls get 401 as if the credential had expired. |
| `rate-limited-429` | Hook calls get 429 with `Retry-After: 30` and a JSON error body on all payers. `perf.rate-limit` parses seconds and HTTP-date delays and advises backoff; the workbench does not retry. |
| `wrong-audience-reject` | Hook calls get 401 because the payer expects a different audience: Fabrikam wants the JWT `aud` under `https://api.fabrikam-benefits.example`, Northwind wants access tokens issued for `https://crd.northwind-health.example`. Tailspin rejects the token request with `401 invalid_client`, expecting assertion `aud` = `https://auth.tailspin-health.example/token`. |
| `malformed-card` | Cards come back without the required `summary` and `indicator`. |
| `discovery-500` | `GET /cds-services` returns 500. |
| `coverage-info-incomplete` | `order-sign` coverage information omits both assertion-id names and sets `covered` to `invalid-covered`; the content check lists both errors. |
| `prefetch-missing-400` | Hook calls missing a declared prefetch key get 400. With the fault off, missing prefetch is tolerated. |
| `untrusted-certificate` | TLS presents a certificate signed by a second CA the workbench does not trust. |
| `expired-certificate` | TLS presents a certificate from the trusted CA whose validity ended yesterday. |
| `hostname-mismatch` | TLS presents a trusted certificate for `crd.other-payer.example` only. |

Faulted HTTP responses carry an `X-Mock-Fault` header naming the fault. A well-formed `X-Request-Id` (up to 128 letters, digits, `.`, `_`, `:` or `-`) is echoed on the response and logged at INFO; anything else is ignored, so it can't forge a header or log line. Certificate faults terminate the TLS handshake before HTTP can be sent and affect admin connections too. The admin endpoint has no authentication; the mocks listen on loopback only.

The app starts all three mock payers over real HTTPS at `https://127.0.0.1:<port>`. A synthetic test CA and server certificates for `localhost` and `127.0.0.1` are generated in memory at startup; no certificate or private-key files are written. Payer calls trust only that test CA, and healthy runs show a `tls.handshake` PASS. Certificate faults fail before HTTP discovery receives a response.

Standalone payers use plain HTTP by default. Add `--tls` to any standalone launcher for HTTPS with an ephemeral test CA. This CA is not installed in the JVM or operating-system trust store. Fabrikam and Tailspin fetch the app's public JWKS over loopback HTTP. TLS faults affect the handshake for every endpoint, including admin endpoints; clear them programmatically or restart a standalone payer to recover.

### Payer behaviours and the behaviour matrix

Faults break a payer. A `PayerBehaviour` instead varies it the way real payers legitimately differ. Pass one to any payer's builder (`NorthwindPayer.builder().behaviour(...)`); it is fixed for the payer's lifetime, and `PayerBehaviour.STANDARD` (the default) changes nothing. It covers:

- the access-token format: opaque, JWT signed RS256 or ES256, a JWT whose `aud` names another server, or an 8 KiB token;
- the token response: `token_type` case, a missing `token_type` or one the SDK cannot use (DPoP, mac), `expires_in` as a string, extra fields, the `Content-Type`, or HTTP 200 with an OAuth `error` body;
- hook authentication: enforced, or ignored entirely;
- the payer's clock, which also moves its `Date` header;
- a 307/308 redirect on one endpoint;
- the discovery document: extra services for unknown hooks, no `prefetch`, or an empty `services` array.

The JDK server always stamps `Date` itself, so a payer with a clock offset listens behind a small loopback relay that rewrites that header. A clock offset therefore needs plain HTTP.

`workbench-app/src/test/resources/payer-matrix.json` is the payer-behaviour matrix. Each row is one behaviour plus the spec clause (CDS Hooks 2.0, SMART Backend Services, RFC 6749/6750/7519/7523/9068/9110) that sets its expected verdict and findings. `PayerMatrixTest` runs every row end to end through `OnboardingRunner`, as a loopback custom endpoint. `PayerMatrixShapeTest` fails if a dimension drops below two values or a behaviour variant loses its row. A row the workbench gets wrong today carries `"knownDefect": "#NNN"`; the test then requires the wrong answer, so a fix fails the row until the marker is removed.

## Sample requests

The `samples` module ships synthetic CDS Hooks requests, so you can run meaningful requests without writing FHIR by hand. Each sample is a directory under `samples/src/main/resources/samples/` with `request.json` (the request as sent) and `metadata.json` (title, hook, what it demonstrates, the outcome to expect from each mock payer).

| Sample id | Hook | Order | Expect from payer A (Northwind) | Expect from payer B (Fabrikam) |
|-----------|------|-------|---------------------------------|--------------------------------|
| `order-sign-hospital-bed` | order-sign | Hospital bed, HCPCS E0250 | Covered, prior authorization required | Coverage information in a card suggestion |
| `order-sign-home-oxygen` | order-sign | Home oxygen, HCPCS E0424 | Covered, no prior authorization | Coverage information in a card suggestion |
| `order-sign-conditional-cpap` | order-sign | CPAP device, HCPCS E0601 | Conditional, documentation needed | Coverage information in a card suggestion |
| `order-sign-missing-prefetch` | order-sign | Hospital bed, sent with no prefetch | Error for missing prefetch (`prefetch-missing`) | Same |
| `order-select-walker` | order-select | Walker, HCPCS E0143, beside a PT evaluation (CPT 97161) | Conditional, documentation needed | Not supported, if Fabrikam does not list order-select |
| `appointment-book-dme-fitting` | appointment-book | DME fitting appointment | Not supported | Not supported |

All samples share one synthetic cast: patient `Synthetic, Pat` (`Patient/pat-synthetic-001`), practitioner `Dr. Doc Synthetic` (`Practitioner/pract-synthetic-001`), coverage `Coverage/cov-synthetic-001` and encounter `Encounter/enc-synthetic-001`. The practitioner's NPI is the placeholder `9999999999`, which is not a real NPI.

Load them from Java with `SampleCatalog`:

```java
SampleCatalog catalog = new SampleCatalog();
catalog.list();                                                        // metadata for every sample
Sample bed = catalog.load("order-sign-hospital-bed");                  // standard CRD prefetch keys
Sample bedB = catalog.load("order-sign-hospital-bed", PrefetchVariant.PAYER_B);
CdsHookRequest request = bed.withNewHookInstance().request();          // client-sdk type, ready to send
```

`PrefetchVariant.STANDARD` sends `patient`, `encounter` and `coverage`. `PrefetchVariant.PAYER_B` matches mock payer B, which uses keys in the style of the HL7 reference implementation: `coverage` becomes `coverageBundle`, and the draft DeviceRequests are also sent as `deviceRequestBundle` with their patient, requester and coverage included.

`SampleFactory` builds every request with the fhir-crd-router `client-sdk` types (`CdsHookRequest`, `CrdHookContext`, `CrdPrefetch`), so it doubles as a usage example for that library. The `request.json` files are its output, and a test fails if they drift. To change a sample, edit `SampleFactory` or the shared FHIR resources in `samples/fhir/`, then regenerate from the repo root:

```sh
./mvnw -q -pl samples -am install -DskipTests
./mvnw -q -pl samples dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "samples/target/classes:$(cat samples/target/cp.txt)" io.github.dflippojr.payerworkbench.samples.SampleFactory
```

On Windows, use `;` instead of `:` as the classpath separator.
