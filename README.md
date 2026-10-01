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

## License

MIT. See [LICENSE](LICENSE).
