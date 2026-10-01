package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.mock.Fault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.FABRIKAM_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The onboarding flow against both in-process mock payers: a healthy run passes, and
 * each fault and each common misconfiguration fails the expected check. The latency
 * budgets are scaled down so {@code slow-response} fails in under a second.
 */
@SpringBootTest(properties = {
        "workbench.latency-warn=300ms",
        "workbench.latency-fail=600ms",
        "workbench.slow-response-delay=900ms"})
class OnboardingFlowTest {

    private static final String HEALTHY_SAMPLE = "order-sign-hospital-bed";
    /** prefetch-missing-400 only fires when the client leaves out prefetch it could have sent. */
    private static final String NO_PREFETCH_SAMPLE = "order-sign-missing-prefetch";

    @Autowired
    OnboardingRunner runner;

    @Autowired
    SyntheticPayers payers;

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void healthyRunPassesEveryStepWithNoFail(String payerId) {
        OnboardingRun run = runner.run(request(payerId, HEALTHY_SAMPLE, List.of()));

        assertEquals(List.of("resolve-connection", "discovery", "authenticate", "hook-request", "parse-response",
                "diagnostics"), run.steps().stream().map(StepResult::stepId).toList());
        run.steps().forEach(step -> assertTrue(step.ok(), step.stepId() + ": " + step.summary()));
        assertEquals(List.of(), failIds(run));
        assertTrue(run.findings().stream().anyMatch(f -> f.severity() == Severity.PASS));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void healthyRunWithoutPrefetchStillPasses(String payerId) {
        assertEquals(List.of(), failIds(runner.run(request(payerId, NO_PREFETCH_SAMPLE, List.of()))));
    }

    static Stream<Arguments> faults() {
        List<Arguments> cases = new ArrayList<>();
        for (String payerId : List.of(NORTHWIND_ID, FABRIKAM_ID)) {
            cases.add(Arguments.of(payerId, Fault.SLOW_RESPONSE, HEALTHY_SAMPLE, "perf.latency", null));
            cases.add(Arguments.of(payerId, Fault.EXPIRED_TOKEN_401, HEALTHY_SAMPLE, "auth.clock-skew", "hook-request"));
            cases.add(Arguments.of(payerId, Fault.WRONG_AUDIENCE_REJECT, HEALTHY_SAMPLE, "response.schema", "hook-request"));
            cases.add(Arguments.of(payerId, Fault.MALFORMED_CARD, HEALTHY_SAMPLE, "response.schema", "parse-response"));
            cases.add(Arguments.of(payerId, Fault.DISCOVERY_500, HEALTHY_SAMPLE, "discovery.reachable", "discovery"));
            cases.add(Arguments.of(payerId, Fault.PREFETCH_MISSING_400, NO_PREFETCH_SAMPLE, "response.schema", "hook-request"));
            cases.add(Arguments.of(payerId, Fault.TLS_REQUIRED, HEALTHY_SAMPLE, "discovery.reachable", "discovery"));
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0} {1} -> {3}")
    @MethodSource("faults")
    void eachFaultProducesTheExpectedFail(String payerId, Fault fault, String sampleId, String expectedCheckId,
                                          String failedStep) {
        OnboardingRun run = runner.run(request(payerId, sampleId, List.of(fault.id())));

        assertTrue(failIds(run).contains(expectedCheckId), "FAIL ids: " + failIds(run));
        if (failedStep != null) {
            assertEquals(failedStep, firstFailedStep(run));
        }
        StepResult diagnostics = run.steps().getLast();
        assertEquals("diagnostics", diagnostics.stepId());
        assertFalse(diagnostics.ok());
        assertTrue(payers.payer(payerId).orElseThrow().faults().enabled().isEmpty(), "faults are cleared after a run");
    }

    @Test
    void faultsDoNotLeakIntoTheNextRun() {
        runner.run(request(NORTHWIND_ID, HEALTHY_SAMPLE, List.of(Fault.DISCOVERY_500.id())));
        assertEquals(List.of(), failIds(runner.run(request(NORTHWIND_ID, HEALTHY_SAMPLE, List.of()))));
    }

    @Test
    void missingConnectionRecordStopsAtResolve() {
        OnboardingRun run = runner.run(new RunRequest(NORTHWIND_ID, Environment.PRODUCTION, HEALTHY_SAMPLE,
                List.of(), null, null));

        assertEquals("resolve-connection", firstFailedStep(run));
        assertEquals(List.of(OnboardingRunner.CONNECTION_RECORD_CHECK), failIds(run));
        run.steps().subList(1, 5).forEach(step -> assertEquals("skipped", step.details().get("status")));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void baseUrlSuffixBreaksDiscovery(String payerId) {
        OnboardingRun run = runner.run(edited(payerId, new RunRequest.ConnectionOverrides("/r4", null, null, null)));

        assertEquals("discovery", firstFailedStep(run));
        assertEquals(List.of("discovery.reachable"), failIds(run));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void igVersionMismatchFailsIgVersionCheck(String payerId) {
        OnboardingRun run = runner.run(edited(payerId, new RunRequest.ConnectionOverrides(null, "1.0.0", null, null)));

        assertEquals(null, firstFailedStep(run));
        assertEquals(List.of("ig.version"), failIds(run));
    }

    @Test
    void wrongClientIdFailsTheTokenRequest() {
        OnboardingRun run = runner.run(edited(NORTHWIND_ID,
                new RunRequest.ConnectionOverrides(null, null, null, "someone-else")));

        assertEquals("authenticate", firstFailedStep(run));
        assertTrue(failIds(run).contains("auth.token"), "FAIL ids: " + failIds(run));
    }

    @Test
    void wrongIssuerIsRejectedByTheJwtPayer() {
        OnboardingRun run = runner.run(edited(FABRIKAM_ID,
                new RunRequest.ConnectionOverrides(null, null, null, "someone-else")));

        assertEquals("hook-request", firstFailedStep(run));
        assertTrue(failIds(run).contains("response.schema"), "FAIL ids: " + failIds(run));
    }

    @Test
    void audOverrideWithTrailingSlashFailsJwtAudience() {
        String serviceUrl = payers.payer(FABRIKAM_ID).orElseThrow().baseUrl() + "/cds-services/order-sign-crd";
        OnboardingRun run = runner.run(edited(FABRIKAM_ID,
                new RunRequest.ConnectionOverrides(null, null, serviceUrl + "/", null)));

        assertEquals("hook-request", firstFailedStep(run));
        assertTrue(failIds(run).contains("auth.jwt-audience"), "FAIL ids: " + failIds(run));
        StepResult auth = run.steps().get(2);
        assertEquals(false, auth.details().get("audMatchesRequestUrl"));
        assertEquals(serviceUrl + "/", ((Map<?, ?>) auth.details().get("jwtClaims")).get("aud"));
    }

    @Test
    void sampleForAHookThePayerDoesNotServeStopsAtDiscovery() {
        OnboardingRun run = runner.run(request(NORTHWIND_ID, "appointment-book-dme-fitting", List.of()));

        assertEquals("discovery", firstFailedStep(run));
        assertTrue(failIds(run).contains("discovery.services"), "FAIL ids: " + failIds(run));
    }

    @Test
    void unknownInputsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> runner.run(request("nobody", HEALTHY_SAMPLE, List.of())));
        assertThrows(IllegalArgumentException.class, () -> runner.run(request(NORTHWIND_ID, "nothing", List.of())));
        assertThrows(IllegalArgumentException.class,
                () -> runner.run(request(NORTHWIND_ID, HEALTHY_SAMPLE, List.of("set-on-fire"))));
    }

    private static RunRequest request(String payerId, String sampleId, List<String> faults) {
        return new RunRequest(payerId, Environment.SANDBOX, sampleId, faults, null, null);
    }

    private static RunRequest edited(String payerId, RunRequest.ConnectionOverrides edits) {
        return new RunRequest(payerId, Environment.SANDBOX, HEALTHY_SAMPLE, List.of(), null, edits);
    }

    private static List<String> failIds(OnboardingRun run) {
        return run.findings().stream().filter(f -> f.severity() == Severity.FAIL).map(Finding::checkId).distinct().toList();
    }

    private static String firstFailedStep(OnboardingRun run) {
        return run.steps().stream()
                .filter(s -> !s.stepId().equals("diagnostics") && "failed".equals(s.details().get("status")))
                .map(StepResult::stepId)
                .findFirst()
                .orElse(null);
    }
}
