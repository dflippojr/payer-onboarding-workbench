# Payer Onboarding Workbench

Connect to a (synthetic) insurance payer's FHIR CRD / CDS Hooks endpoint, inspect its discovery response, run sample requests, and get a plain-language diagnostic report when something goes wrong.

Built on [fhir-crd-router](https://github.com/dflippojr/fhir-crd-router), which stays independently usable; this workbench is an optional consumer of it.

**Status:** project skeleton. Modules and shared contracts exist; mock payers, checks, samples and the UI are tracked in GitHub issues.

All data is synthetic. No real payers, patients, or PHI. A passing run against the mock payers does not establish interoperability with any real payer.

## Develop

Requires JDK 21. Maven is not needed; use the wrapper.

fhir-crd-router is not on Maven Central yet, so install it into your local Maven repository first. The script clones the pinned commit into `.deps/` (gitignored) and runs its build:

```sh
./scripts/install-crd-router.sh        # macOS, Linux, Git Bash
```

```powershell
.\scripts\install-crd-router.ps1       # Windows PowerShell
```

Build and run the tests:

```sh
./mvnw verify
```

Run the app (serves on http://localhost:8080 by default; pass `--server.port=<port>` to change it):

```sh
./mvnw -pl workbench-app -am spring-boot:run
```

Modules:

| Module | Purpose |
|--------|---------|
| `workbench-core` | Shared contracts and `Redactor`. Pure Java, no Spring. |
| `mock-payers` | Two embedded synthetic CDS Hooks payers. |
| `diagnostics` | Diagnostic checks and the engine that runs them. |
| `samples` | Synthetic request payloads. |
| `workbench-app` | Spring Boot app: REST API and static UI. |

Design decisions and how to override them: [DECISIONS.md](DECISIONS.md).

## Mock payers

`mock-payers` contains two synthetic CDS Hooks payers built on the JDK's `com.sun.net.httpserver`. They behave differently on purpose, so the workbench has something realistic to onboard against. Tests start them in-process on an ephemeral port (`start(0)`). You can also run either one standalone. Every name, identifier and decision they return is made up.

**Northwind Health (synthetic)** follows the spec.

- Declares Da Vinci CRD 2.2.1. `GET /cds-services` lists `order-sign` and `order-select` with standard prefetch keys (`patient`, `coverage`).
- Auth is OAuth2 client credentials with `client_secret_basic` at `/oauth/token`. Tokens expire (5 minutes by default). Hook calls without a valid `Authorization: Bearer` token get 401.
- `order-sign` returns coverage information in `systemActions`. Outcomes depend only on the order code. E0250 is covered and needs prior auth. E0424 is covered with no auth. Any other code is conditional and needs clinical documentation.

**Fabrikam Benefits (synthetic)** is quirky in the same ways as the HL7 reference implementation.

- Declares the older CRD 2.0.1. Its prefetch keys are non-standard (`coverageBundle`, `deviceRequestBundle`).
- Puts coverage information inside card suggestions instead of `systemActions`.
- Auth is the CDS Hooks 2.0 client JWT. Fabrikam checks the signature against the client's JWKS, which it fetches from a URL you register per issuer. It also checks `iss`, that `aud` is exactly the service URL, `exp`, and `jti` replay. RS384 and ES384 are accepted.

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

Northwind options: `--port`, `--client-id`, `--client-secret` (generated if omitted), `--token-lifetime-seconds`, `--public-base-url`. Fabrikam options: `--port`, `--client ISS=JWKS_URL` (repeatable), `--public-base-url`. Use `--port 0` for a free port. No keys or secrets are stored in the repo. Tests generate key pairs at runtime and serve the JWKS themselves.

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
| `slow-response` | Every non-admin request waits `delayMs` (default 2000) before it is handled. |
| `expired-token-401` | Hook calls get 401 as if the credential had expired. |
| `wrong-audience-reject` | Hook calls get 401 because the payer expects a different audience. |
| `malformed-card` | Cards come back without the required `summary` and `indicator`. |
| `discovery-500` | `GET /cds-services` returns 500. |
| `prefetch-missing-400` | Hook calls missing a declared prefetch key get 400. With the fault off, missing prefetch is tolerated. |
| `tls-required` | Every non-admin request gets 426 Upgrade Required. This is simulated: the mocks never serve TLS. |

Faulted responses carry an `X-Mock-Fault` header naming the fault. The admin endpoint has no authentication and is never affected by faults, so the mocks listen on loopback only.

## License

MIT. See [LICENSE](LICENSE).
