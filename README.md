# Payer Onboarding Workbench

Connect to a (synthetic) insurance payer's FHIR CRD / CDS Hooks endpoint, inspect its discovery response, run sample requests, and get a plain-language diagnostic report when something goes wrong.

Built on [fhir-crd-router](https://github.com/dflippojr/fhir-crd-router), which stays independently usable; this workbench is an optional consumer of it.

**Status:** v1 is done. The onboarding flow (API and browser UI), the three mock payers, the diagnostic checks, the sample library, report export, the scripted demo and the replay bundle are merged, and the replay is live on [dflippojr.dev](https://dflippojr.dev/). Later work is tracked in [GitHub issues](https://github.com/dflippojr/payer-onboarding-workbench/issues).

All data is synthetic. No real payers, patients, or PHI. A passing run against the mock payers does not establish interoperability with any real payer. The one exception is [custom endpoints](docs/api.md#run-against-your-own-endpoint), off by default: a run still sends synthetic requests, but its report holds that endpoint's real responses.

## Docs

- [Onboarding flow and API](docs/api.md): the run steps, the REST API, custom endpoints and the report formats.
- [Faults](docs/faults.md): the fault table that the integration tests run row by row.
- [Audit trail](docs/audit.md): the offline audit review, the durable journal and fault changes.
- [Observability](docs/observability.md): health, info, Prometheus metrics and correlation ids.
- [Demo, embed and replay](docs/replay.md): the scripted demo, the replay on the home page and the published bundle.
- [Mock payers and sample requests](docs/mock-payers.md): the three synthetic payers, their faults and behaviour matrix, and the sample requests.
- [CI, dependencies and the SonarCloud secret](docs/ci.md): the GitHub Actions workflows, coverage floors and Dependabot.
- [UI testing](docs/ui-testing.md): the disposable UI instance and the browser journeys.

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

Run the app (serves on http://localhost:8080 by default, listening on loopback only because the API has no authentication; `--server.address` changes that). Install the sibling modules once, then run `workbench-app` on its own; adding `-am` to `spring-boot:run` fails on the parent pom, which has no main class:

```sh
./mvnw install -DskipTests
./mvnw -pl workbench-app spring-boot:run
./mvnw -pl workbench-app spring-boot:run -Dspring-boot.run.arguments=--server.port=9090   # another port
```

The five GitHub Actions workflows, the JaCoCo coverage floors, Dependabot and the SonarCloud Dependabot secret are in [docs/ci.md](docs/ci.md). `npm run ci:local` runs the same steps as `ci.yml`, and [AGENTS.md](AGENTS.md) says how to run each gate job on your machine.

Modules:

| Module | Purpose |
|--------|---------|
| `workbench-core` | Shared contracts and `Redactor`. Pure Java, no Spring. |
| `mock-payers` | Three embedded synthetic CDS Hooks payers. |
| `diagnostics` | Diagnostic checks and the engine that runs them. |
| `samples` | Synthetic request payloads. |
| `workbench-app` | Spring Boot app: REST API and static UI. |

Design decisions and how to override them: [DECISIONS.md](DECISIONS.md).

## UI interaction tests

Use the [UI testing contract](docs/ui-testing.md) for the disposable synthetic instance, device/theme journeys and cleanup. After building the jar with Maven, run `npm ci --ignore-scripts`, `node node_modules/@playwright/test/cli.js install chromium webkit`, `npm run test:ui-instance` and `npm run test:ui`. The browser tests run with one worker and start one fresh owned loopback instance per Playwright project; tests isolate themselves by their own run IDs, and a test that needs an untouched instance sets `freshInstance`. Start an exploratory instance with `node scripts/ui-instance.mjs start`; stop it with `node scripts/ui-instance.mjs stop`.

To check a change in the running app (launch, doctor, drive the main path, evidence, cleanup), use the [verify skill](.claude/skills/verify/SKILL.md): `npm run verify`.

## Onboarding flow

`workbench-app` connects to a payer, runs the onboarding steps and shows where the flow breaks. The steps, the REST API, custom endpoints and the report formats are in [docs/api.md](docs/api.md); the fault table that the integration tests run row by row is in [docs/faults.md](docs/faults.md).

### API

Moved to [docs/api.md](docs/api.md#api).

### Run against your own endpoint

Moved to [docs/api.md](docs/api.md#run-against-your-own-endpoint).

### Diagnostic reports

Moved to [docs/api.md](docs/api.md#diagnostic-reports).

### What each fault and misconfiguration fails

Moved to [docs/faults.md](docs/faults.md#what-each-fault-and-misconfiguration-fails).

## Audit review (offline)

Moved to [docs/audit.md](docs/audit.md#audit-review-offline).

### Durable audit journal (#69)

Moved to [docs/audit.md](docs/audit.md#durable-audit-journal-69).

### Fault changes and system operations

Moved to [docs/audit.md](docs/audit.md#fault-changes-and-system-operations).

## Observability

Moved to [docs/observability.md](docs/observability.md#observability).

## Demo

The scripted demo (`scripts/demo.mjs`), the replay embedded on [dflippojr.dev](https://dflippojr.dev/), and the published replay bundle are in [docs/replay.md](docs/replay.md).

## Embed on a website

Moved to [docs/replay.md](docs/replay.md#embed-on-a-website).

### The published bundle

Moved to [docs/replay.md](docs/replay.md#the-published-bundle).

## Mock payers

The three synthetic CDS Hooks payers in `mock-payers` (Northwind, Fabrikam and Tailspin) behave differently on purpose. Their start-up, fault injection, behaviour matrix and the sample requests are in [docs/mock-payers.md](docs/mock-payers.md).

### Start one standalone

Moved to [docs/mock-payers.md](docs/mock-payers.md#start-one-standalone).

### Fault injection

Moved to [docs/mock-payers.md](docs/mock-payers.md#fault-injection).

### Payer behaviours and the behaviour matrix

Moved to [docs/mock-payers.md](docs/mock-payers.md#payer-behaviours-and-the-behaviour-matrix).

## Sample requests

Moved to [docs/mock-payers.md](docs/mock-payers.md#sample-requests).

## License

MIT. See [LICENSE](LICENSE).
