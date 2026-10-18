# Agent notes

- To prove a change works in the real app, use the verify skill: [.claude/skills/verify/SKILL.md](.claude/skills/verify/SKILL.md) (`npm run verify`), which builds on [docs/ui-testing.md](docs/ui-testing.md).

## How to prove a change works

- **Full gate: `npm run ci:local`.** It runs every `run:` step of [.github/workflows/ci.yml](.github/workflows/ci.yml) in the same order: Maven verify (tests and the JaCoCo coverage floors), the demo tour, the UI journeys, the replay export, the Node suites and the CRD reference runs. It stops the UI instance and the reference server even when a step fails and exits non-zero at the first failure. It needs Node 22+, JDK 21 on `JAVA_HOME`, Docker running, and Git Bash on Windows. Run it before you push; CI's `gate` check runs the same steps.
- **Outside judge: the CRD reference runs.** CI's `crd-reference` job runs every sample against the HL7 Da Vinci CRD reference server (pinned in [scripts/crd-reference-server.env](scripts/crd-reference-server.env)) as a custom endpoint and checks the verdicts against the specs. To run it alone, with Docker running:

  ```sh
  bash scripts/crd-reference-server.sh start     # first run builds the image (several minutes)
  node --test scripts/reference-runs.mjs         # builds the jar; REFERENCE_SKIP_BUILD=1 reuses it
  bash scripts/crd-reference-server.sh stop
  ```

  Reports land in `.crd-ri/reports/`, the server log in `.crd-ri/server.log`. A change that makes a healthy reference server get a `FAIL` is a regression, not a flaky test.
- **Running-app proof: `npm run verify`.** For a UI or API change, run the verify skill and quote its `summary.md` in the PR.
- **Outside judge for response content: `bash scripts/hl7-validator.sh warm test`.** CI's `hl7-validator` job (inside `gate`) checks `response.schema`, `response.coverage-information` and `response.coverage-location` against the pinned official HL7 FHIR Validator over the corpus in `diagnostics/src/test/resources/conformance-corpus/`. Its README has the mapping table and the allowlist rules. When you change those checks or the mock payers, run it and quote the agreement line from `diagnostics/target/hl7-validator/report.md`.
- **New diagnostic checks need a reachability scenario.** `CheckReachabilityTest` (workbench-app) runs every check `DiagnosticEngine` registers through the real runner and mock payers, and fails for a check with no row in its `TABLE`: one scenario (a fault, a connection edit, a sample or a `payer-matrix.json` row) where the check must fire and one where it must pass. The table lands in `workbench-app/target/check-reachability.md`.
- **Mutation floor on diagnostics: `bash scripts/mutation.sh`.** CI's `mutation` job (inside `gate`) runs pitest on the `diagnostics` module and fails below `pitest.mutation.floor` in [diagnostics/pom.xml](diagnostics/pom.xml); `diagnostics/target/pit-reports/summary.md` lists the surviving mutants. When you change a check, kill the mutants you add. The floor only ever goes up.
- **Bug fixes start with a failing test.** First write a test that fails on `main` for the reported reason, then make it pass. Say in the PR that it failed before the fix.
- **The PR body has a `## Proof` table** ([dflippojr/.github#13](https://github.com/dflippojr/.github/issues/13)): one row per acceptance criterion, with how it was verified and the evidence (a test name, command output, a `summary.md` excerpt, a CI run link).

  | Acceptance criterion | How verified | Evidence |
  |---|---|---|
  | One criterion from the issue | The test or command that checks it | Its output, a link or a `summary.md` excerpt |
- **Never lower a coverage floor.** `jacoco.line.floor` in each module's `pom.xml` only ever goes up.
