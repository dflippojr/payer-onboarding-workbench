package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.diagnostics.AuthTokenCheck;
import io.github.dflippojr.payerworkbench.diagnostics.ClientAssertionCheck;
import io.github.dflippojr.payerworkbench.diagnostics.ClockSkewCheck;
import io.github.dflippojr.payerworkbench.diagnostics.CoverageInformationCheck;
import io.github.dflippojr.payerworkbench.diagnostics.CoverageLocationCheck;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticEngine;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticsConfig;
import io.github.dflippojr.payerworkbench.diagnostics.DiscoveryPrefetchKeysCheck;
import io.github.dflippojr.payerworkbench.diagnostics.DiscoveryReachableCheck;
import io.github.dflippojr.payerworkbench.diagnostics.DiscoveryServicesCheck;
import io.github.dflippojr.payerworkbench.diagnostics.HookRejectedCheck;
import io.github.dflippojr.payerworkbench.diagnostics.IgVersionCheck;
import io.github.dflippojr.payerworkbench.diagnostics.JwtAudienceCheck;
import io.github.dflippojr.payerworkbench.diagnostics.LatencyCheck;
import io.github.dflippojr.payerworkbench.diagnostics.RateLimitCheck;
import io.github.dflippojr.payerworkbench.diagnostics.ResponseSchemaCheck;
import io.github.dflippojr.payerworkbench.diagnostics.TlsHandshakeCheck;
import io.github.dflippojr.payerworkbench.mock.Fault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.FABRIKAM_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.TAILSPIN_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The reachability matrix (#171): every check {@link DiagnosticEngine} registers is proven to fire through
 * the real {@link OnboardingRunner} against the mock payers, not only in unit tests that hand it
 * observations directly (the gap #163 slipped through). For each check id, one scenario must make the check
 * emit a non-PASS finding and another must leave it passing.
 *
 * <p>A scenario is a mock payer {@link Fault}, a connection edit, a sample, or a {@code payer-matrix.json}
 * row. The tests are parameterized over the engine's registered checks, not over {@link #TABLE}, so a new
 * check without a row here fails until it gets one.
 *
 * <p>The latency budgets are scaled down, as in {@link OnboardingFlowTest}, so {@code slow-response}
 * fails in under a second.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "workbench.custom-endpoints.enabled=true",
        "workbench.latency-warn=300ms",
        "workbench.latency-fail=600ms",
        "workbench.slow-response-delay=900ms"})
class CheckReachabilityTest {

    private static final String HEALTHY_SAMPLE = "order-sign-hospital-bed";

    /** Where {@link #everyRegisteredCheckHasAReachabilityScenario()} writes the table, for PR proof. */
    static final Path TABLE_REPORT = Path.of("target", "check-reachability.md");

    /** Check id to the scenario that must make it fire and the one where it must pass, in catalog order. */
    static final Map<String, Reachability> TABLE = table(
            new Reachability(DiscoveryReachableCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.DISCOVERY_500), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(DiscoveryServicesCheck.CHECK_ID,
                    sample(NORTHWIND_ID, "appointment-book-dme-fitting"), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            // Fabrikam names its prefetch keys coverageBundle and deviceRequestBundle: INFO.
            new Reachability(DiscoveryPrefetchKeysCheck.CHECK_ID,
                    healthy(FABRIKAM_ID), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(AuthTokenCheck.CHECK_ID,
                    clientId(NORTHWIND_ID, "someone-else"), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(ClientAssertionCheck.CHECK_ID,
                    fault(TAILSPIN_ID, Fault.WRONG_AUDIENCE_REJECT), healthy(TAILSPIN_ID), Pass.EMITS_PASS),
            new Reachability(JwtAudienceCheck.CHECK_ID,
                    fault(FABRIKAM_ID, Fault.WRONG_AUDIENCE_REJECT), healthy(FABRIKAM_ID), Pass.EMITS_PASS),
            new Reachability(HookRejectedCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.EXPIRED_TOKEN_401), healthy(NORTHWIND_ID), Pass.SILENT),
            new Reachability(RateLimitCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.RATE_LIMITED_429), healthy(NORTHWIND_ID), Pass.SILENT),
            new Reachability(ClockSkewCheck.CHECK_ID,
                    matrix("clock/cds-hooks-jwt-payer-ahead-5m"), healthy(FABRIKAM_ID), Pass.EMITS_PASS),
            new Reachability(IgVersionCheck.CHECK_ID,
                    igVersion(NORTHWIND_ID, "1.0.0"), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(ResponseSchemaCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.MALFORMED_CARD), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            // Fabrikam returns coverage information in card suggestions, not systemActions: INFO.
            new Reachability(CoverageLocationCheck.CHECK_ID,
                    healthy(FABRIKAM_ID), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(CoverageInformationCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.COVERAGE_INFO_INCOMPLETE), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(LatencyCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.SLOW_RESPONSE), healthy(NORTHWIND_ID), Pass.EMITS_PASS),
            new Reachability(TlsHandshakeCheck.CHECK_ID,
                    fault(NORTHWIND_ID, Fault.UNTRUSTED_CERTIFICATE), healthy(NORTHWIND_ID), Pass.EMITS_PASS));

    @Autowired
    OnboardingRunner runner;

    /** The ids the runner's engine registers, in catalog order. */
    static Stream<String> registeredChecks() {
        return DiagnosticEngine.defaultChecks(DiagnosticsConfig.defaults()).stream().map(DiagnosticCheck::id);
    }

    @Test
    void everyRegisteredCheckHasAReachabilityScenario() throws IOException {
        Set<String> registered = registeredChecks().collect(Collectors.toCollection(TreeSet::new));
        Set<String> missing = new TreeSet<>(registered);
        missing.removeAll(TABLE.keySet());
        Set<String> stale = new TreeSet<>(TABLE.keySet());
        stale.removeAll(registered);
        Files.createDirectories(TABLE_REPORT.getParent());
        Files.writeString(TABLE_REPORT, markdown());
        assertEquals(Set.of(), missing, "registered checks with no reachability scenario in CheckReachabilityTest.TABLE");
        assertEquals(Set.of(), stale, "CheckReachabilityTest.TABLE rows for checks the engine no longer registers");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registeredChecks")
    void eachCheckFiresThroughTheRunner(String checkId) throws Exception {
        Reachability row = TABLE.get(checkId);
        assertNotNull(row, () -> checkId + " has no reachability scenario: add a row to CheckReachabilityTest.TABLE");
        List<Finding> findings = findings(row.fires().run(runner), checkId);

        assertTrue(findings.stream().anyMatch(f -> f.severity() != Severity.PASS),
                () -> checkId + " did not fire under " + row.fires().name() + ": " + findings);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registeredChecks")
    void eachCheckPassesThroughTheRunner(String checkId) throws Exception {
        Reachability row = TABLE.get(checkId);
        assertNotNull(row, () -> checkId + " has no reachability scenario: add a row to CheckReachabilityTest.TABLE");
        List<Finding> findings = findings(row.passes().run(runner), checkId);

        assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.PASS),
                () -> checkId + " did not pass under " + row.passes().name() + ": " + findings);
        if (row.pass() == Pass.EMITS_PASS) {
            assertFalse(findings.isEmpty(), () -> checkId + " reported nothing under " + row.passes().name()
                    + ", so it never evaluated the run");
        }
    }

    /**
     * {@code checkId}'s findings. The engine's own WARN for a check that threw is no proof the check
     * fired, so it fails the test instead of counting.
     */
    private static List<Finding> findings(OnboardingRun run, String checkId) {
        List<Finding> findings = run.findings().stream().filter(f -> f.checkId().equals(checkId)).toList();
        for (Finding finding : findings) {
            assertFalse(finding.title().equals("Check " + checkId + " could not run"),
                    () -> checkId + " threw: " + finding.evidence());
        }
        return findings;
    }

    /** What a passing run must show for a check: a PASS finding, or nothing because it reports only problems. */
    enum Pass { EMITS_PASS, SILENT }

    record Reachability(String checkId, Scenario fires, Scenario passes, Pass pass) {
    }

    /** A named way to run the onboarding flow once. */
    record Scenario(String name, Runner runner) {

        OnboardingRun run(OnboardingRunner onboarding) throws Exception {
            return runner.run(onboarding);
        }
    }

    @FunctionalInterface
    interface Runner {
        OnboardingRun run(OnboardingRunner onboarding) throws Exception;
    }

    private static Scenario healthy(String payerId) {
        return named(payerId + " healthy", payerId, HEALTHY_SAMPLE, List.of(), null);
    }

    private static Scenario fault(String payerId, Fault fault) {
        return named(payerId + " fault " + fault.id(), payerId, HEALTHY_SAMPLE, List.of(fault.id()), null);
    }

    private static Scenario sample(String payerId, String sampleId) {
        return named(payerId + " sample " + sampleId, payerId, sampleId, List.of(), null);
    }

    private static Scenario clientId(String payerId, String clientId) {
        return named(payerId + " client id edited to " + clientId, payerId, HEALTHY_SAMPLE, List.of(),
                new RunRequest.ConnectionOverrides(null, null, clientId));
    }

    private static Scenario igVersion(String payerId, String igVersion) {
        return named(payerId + " IG version edited to " + igVersion, payerId, HEALTHY_SAMPLE, List.of(),
                new RunRequest.ConnectionOverrides(null, igVersion, null));
    }

    private static Scenario named(String name, String payerId, String sampleId, List<String> faults,
                                  RunRequest.ConnectionOverrides edits) {
        return new Scenario(name, onboarding -> onboarding.run(
                new RunRequest(payerId, Environment.SANDBOX, sampleId, faults, null, edits)));
    }

    /** A {@code payer-matrix.json} row, run as {@link PayerMatrixTest} runs it: a custom endpoint. */
    private static Scenario matrix(String rowId) {
        return new Scenario("payer-matrix row " + rowId, onboarding -> {
            PayerMatrix.Row row = PayerMatrix.load().rows().stream().filter(r -> r.id().equals(rowId))
                    .findFirst().orElseThrow(() -> new IllegalArgumentException("no payer-matrix row " + rowId));
            try (PayerMatrixTest.Scenario scenario = new PayerMatrixTest.Scenario(row)) {
                return onboarding.run(scenario.request());
            }
        });
    }

    private static Map<String, Reachability> table(Reachability... rows) {
        Map<String, Reachability> table = new LinkedHashMap<>();
        for (Reachability row : rows) {
            if (table.put(row.checkId(), row) != null) {
                throw new IllegalArgumentException("two reachability rows for " + row.checkId());
            }
        }
        return Collections.unmodifiableMap(table);
    }

    static String markdown() {
        StringBuilder out = new StringBuilder("| Check id | Fires under | Passes under |\n|---|---|---|\n");
        for (Reachability row : TABLE.values()) {
            out.append("| `").append(row.checkId()).append("` | ").append(row.fires().name()).append(" | ")
                    .append(row.passes().name())
                    .append(row.pass() == Pass.SILENT ? " (no finding: the check reports only problems)" : "")
                    .append(" |\n");
        }
        return out.toString();
    }
}
