# Conformance corpus

The workbench's three response checks are `response.schema`, `response.coverage-information` and `response.coverage-location`. Here an outside judge, the official HL7 FHIR Validator, checks them. Without it, the checks, the mock payers and fhir-crd-router's CRD validator all come from one reading of the IG. A misreading would be applied the same way everywhere and pass every other test.

## What is here

- **`healthy-<payer>-<sample>.json`.** Northwind, Fabrikam and Tailspin each answer every sample whose hook they serve. The answers come from each mock's own hook handler (`MockPayerHooks`), with the clock fixed at 2026-03-02 and each payer's own prefetch style. The `order-sign-missing-prefetch` sample is skipped because it gets an error, not a response, and `appointment-book-dme-fitting` because no mock serves that hook.
- **`mutant-<rule>.json`.** A healthy response with one rule broken. The `base` and `rule` fields in `index.json` say which response it starts from and what was broken: a required element removed, cardinality broken, a wrong code or code system, a wrong coverage-information extension structure, or an unknown extension. Most mutants start from Northwind's hospital-bed answer, which carries coverage information in `systemActions`. The suggestion mutants start from Fabrikam's, which carries it in card suggestions.
- **`index.json`.** Every item with its description.
- **`conformance-allowlist.json`.** The known disagreements (see below).

`ConformanceCorpus` (under `src/test/java`) generates all of these. `ConformanceCorpusTest` runs in every build and fails when a committed file differs from what the mocks produce today. After a deliberate mock change, regenerate the corpus and review the diff:

```sh
./mvnw -pl diagnostics -am test -Dtest=ConformanceCorpusTest -Dsurefire.failIfNoSpecifiedTests=false -Dconformance.corpus.write=true
```

## Running the judge

```sh
bash scripts/hl7-validator.sh warm test
```

- **`warm`** downloads the validator jar pinned in [scripts/hl7-validator.env](../../../../../scripts/hl7-validator.env) and checks its SHA-256. It then runs the validator once with network access, so the CRD package and every package it depends on (about 3.5 GB) are cached in `~/.cache/hl7-validator`. CI caches that directory, keyed by the pins file.
- **`test`** runs `HL7ValidatorConformanceTest` (JUnit tag `hl7-validator`, Maven profile `hl7-validator`). It validates every corpus file in one validator run with `-no-http-access`, `-tx n/a` and `-allow-example-urls true`. Each file is checked against the HL7 tools package's `CDSHooksResponse` logical model, so cards are judged too, with the CRD 2.2.1 package loaded for the order resources and the coverage-information extension. The test writes `diagnostics/target/hl7-validator/report.md`, which shows the agreement rate and every verdict, plus the raw `validator-output.json`.

## The mapping table

Each validator issue is assigned to at most one check by where it points. The validator's verdict for a check is its worst issue there. The workbench's verdict is its worst finding from that check. The two must be equal.

| Validator issue | Belongs to |
|---|---|
| `Extension_EXTP_Context_Wrong` naming `ext-coverage-information` (the extension used where its context does not allow it) | `response.coverage-location` |
| At or inside a coverage-information extension in an action resource | `response.coverage-information` |
| On the CDS Hooks envelope: the response, `cards` and their fields, `systemActions` itself (not inside an action's `resource`) | `response.schema` |
| A card's `source.topic` coding | no check: none judges card topic codes |
| Anywhere else in an action resource (the rest of the echoed order, such as its HCPCS coding) | no check |

| Validator severity | Verdict | Workbench finding | Verdict |
|---|---|---|---|
| `error`, `fatal` | FAIL | `FAIL` | FAIL |
| `warning` | WARN | `WARN` | WARN |
| `information` | ignored | `PASS`, `INFO`, no finding | OK |
| no issue | OK | | |

Issues no check claims are counted in the report under "Validator issues no check claims", so nothing is silently dropped.

## Known disagreements

`conformance-allowlist.json` holds at most five entries. Each names one cause, the check it affects, one reason and one open issue. It also lists each response it affects, with the verdict pair expected there. The test fails on any disagreement that is not listed. It also fails on a listed one that now agrees, so a fixed entry must be removed. `ConformanceCorpusTest` checks the workbench side of every entry in every build.

Before adding an entry, decide which side is wrong:

- **The workbench is wrong.** Fix the check and add a unit test for the case. The PR that added this corpus did that twice:
  - `response.coverage-location` passed coverage information placed on a coding inside the order (`mutant-ci-on-coding`).
  - `response.schema` passed cards with suggestions but no `selectionBehavior` (`mutant-card-selection-behavior-removed`).
- **A mock is wrong.** Fix the mock and regenerate the corpus. Northwind and Tailspin used a card topic code system that does not exist, and Fabrikam's suggestion cards lacked `selectionBehavior`.
- **The validator is wrong, or the difference is deliberate.** Add an entry only if neither of the above applies.
