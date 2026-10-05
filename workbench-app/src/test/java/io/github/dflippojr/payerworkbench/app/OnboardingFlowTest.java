package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Redactor;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
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
 *
 * <p>Everything each test logs is captured and checked: no secret, token or request
 * body may reach the log.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(properties = {
        "workbench.latency-warn=300ms",
        "workbench.latency-fail=600ms",
        "workbench.slow-response-delay=900ms"})
class OnboardingFlowTest {

    private static final String HEALTHY_SAMPLE = "order-sign-hospital-bed";
    /** prefetch-missing-400 only fires when the client leaves out prefetch it could have sent. */
    private static final String NO_PREFETCH_SAMPLE = "order-sign-missing-prefetch";
    /** Everything the tests logged, for the class-level check. */
    private static final StringBuilder LOG = new StringBuilder();

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
        Finding coverage = run.findings().stream()
                .filter(f -> f.checkId().equals("response.coverage-information")).findFirst().orElseThrow();
        assertEquals(payerId.equals(FABRIKAM_ID) ? Severity.WARN : Severity.PASS, coverage.severity());
        if (payerId.equals(FABRIKAM_ID)) {
            assertTrue(coverage.evidence().contains("identifier is the pre-2.x name"));
        }
        assertTrue(run.findings().stream().anyMatch(f -> f.checkId().equals("tls.handshake") && f.severity() == Severity.PASS));
        assertTrue(payers.payer(payerId).orElseThrow().baseUrl().startsWith("https://127.0.0.1:"));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void everyPayerCallCarriesTheRunsCorrelationId(String payerId) {
        OnboardingRun run = runner.run(request(payerId, HEALTHY_SAMPLE, List.of()));

        List<ExchangeView> calls = new ArrayList<>(exchanges(run, "discovery"));
        List<ExchangeView> tokens = exchanges(run, "authenticate");
        if (tokens != null) {
            calls.addAll(tokens);
        }
        calls.addAll(exchanges(run, "hook-request"));
        // Northwind fetches a token; Fabrikam signs its own JWT, so it has no token call.
        assertEquals(payerId.equals(NORTHWIND_ID) ? 3 : 2, calls.size());
        for (ExchangeView call : calls) {
            assertEquals(List.of(run.runId()), header(call.requestHeaders(), "X-Request-Id"), call.url());
            // The payer echoes what it received, so this proves the header reached it.
            assertEquals(List.of(run.runId()), header(call.responseHeaders(), "X-Request-Id"), call.url());
        }
        RunReport report = RunReport.of(run, payerId, "2.1.0", java.time.Instant.now(), "test");
        assertEquals(run.runId(), report.correlationId());
        for (ReportRenderer.Format format : ReportRenderer.Format.values()) {
            assertTrue(ReportRenderer.render(report, format).contains(run.runId()), format::toString);
        }
    }

    /** What each test logged must hold nothing a redactor would mask and no request or response body. */
    @AfterEach
    void logCarriesNoSecretsOrBodies(CapturedOutput output) {
        String log = output.getAll();
        LOG.append(log);
        assertEquals(Redactor.redact(log), log, "the log contains something the Redactor masks");
        for (String body : List.of("draftOrders", "\"hookInstance\"", "client_assertion", "\"cards\"",
                "-----BEGIN", "eyJ")) {
            assertFalse(log.contains(body), "the log contains " + body);
        }
    }

    /** The checks above saw real traffic: step lines from the runner and request ids from the payers. */
    @AfterAll
    static void stepsAndRequestIdsWereLogged() {
        assertTrue(LOG.toString().contains(" step=discovery status=passed ms="), "no step lines were logged");
        assertTrue(LOG.toString().contains("requestId="), "the mock payers did not log the request id");
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
            // Northwind's audience is on its own access token, which the workbench cannot inspect.
            cases.add(Arguments.of(payerId, Fault.WRONG_AUDIENCE_REJECT, HEALTHY_SAMPLE,
                    payerId.equals(FABRIKAM_ID) ? "auth.jwt-audience" : "response.schema", "hook-request"));
            cases.add(Arguments.of(payerId, Fault.COVERAGE_INFO_INCOMPLETE, HEALTHY_SAMPLE,
                    "response.coverage-information", null));
            cases.add(Arguments.of(payerId, Fault.MALFORMED_CARD, HEALTHY_SAMPLE, "response.schema", "parse-response"));
            cases.add(Arguments.of(payerId, Fault.DISCOVERY_500, HEALTHY_SAMPLE, "discovery.reachable", "discovery"));
            cases.add(Arguments.of(payerId, Fault.PREFETCH_MISSING_400, NO_PREFETCH_SAMPLE, "response.schema", "hook-request"));

        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0} {1} -> {3}")
    @MethodSource("faults")
    void eachFaultProducesTheExpectedFail(String payerId, Fault fault, String sampleId, String expectedCheckId,
                                          String failedStep) {
        OnboardingRun run = runner.run(request(payerId, sampleId, List.of(fault.id())));

        assertTrue(failIds(run).contains(expectedCheckId), "FAIL ids: " + failIds(run));
        if (fault == Fault.COVERAGE_INFO_INCOMPLETE) {
            Finding coverage = run.findings().stream()
                    .filter(f -> f.checkId().equals(expectedCheckId)).findFirst().orElseThrow();
            assertTrue(coverage.evidence().contains("coverage-assertion-id is required"));
            assertTrue(coverage.evidence().contains("covered code 'invalid-covered'"));
            assertTrue(coverage.evidence().contains("DeviceRequest/"));
        }
        if (failedStep != null) {
            assertEquals(failedStep, firstFailedStep(run));
        }
        StepResult diagnostics = run.steps().getLast();
        assertEquals("diagnostics", diagnostics.stepId());
        assertFalse(diagnostics.ok());
        assertTrue(payers.payer(payerId).orElseThrow().faults().enabled().isEmpty(), "faults are cleared after a run");
    }

    static Stream<Arguments> certificateFaults() {
        return Stream.of(NORTHWIND_ID, FABRIKAM_ID).flatMap(payer -> Stream.of(
                Arguments.of(payer, Fault.UNTRUSTED_CERTIFICATE, "not trusted"),
                Arguments.of(payer, Fault.EXPIRED_CERTIFICATE, "has expired"),
                Arguments.of(payer, Fault.HOSTNAME_MISMATCH, "different host")));
    }

    @ParameterizedTest
    @MethodSource("certificateFaults")
    void certificateFaultFailsRealHandshakeAndRecovers(String payerId, Fault fault, String cause) {
        runner.run(request(payerId, HEALTHY_SAMPLE, List.of()));
        OnboardingRun run = runner.run(request(payerId, HEALTHY_SAMPLE, List.of(fault.id())));
        assertEquals("discovery", firstFailedStep(run));
        Finding finding = run.findings().stream().filter(f -> f.checkId().equals("tls.handshake")).findFirst().orElseThrow();
        assertEquals(Severity.FAIL, finding.severity());
        assertTrue(finding.title().contains(cause), finding::toString);
        assertTrue(finding.evidence().contains("SSLHandshakeException"), finding::evidence);
        for (ReportRenderer.Format format : ReportRenderer.Format.values()) {
            String report = ReportRenderer.render(RunReport.of(run, payerId, "2.1.0", java.time.Instant.now(), "test"), format);
            assertFalse(report.contains("-----BEGIN"), "TLS material leaked into " + format);
            assertFalse(report.contains("privateKey"), "TLS private key leaked into " + format);
        }
        assertEquals(List.of(), failIds(runner.run(request(payerId, HEALTHY_SAMPLE, List.of()))));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void slowResponseHoldsOnlyTheHookCall(String payerId) {
        OnboardingRun run = runner.run(request(payerId, HEALTHY_SAMPLE, List.of(Fault.SLOW_RESPONSE.id())));

        Duration delay = Duration.ofMillis(900);
        for (StepResult step : run.steps()) {
            if (step.stepId().equals("discovery") || step.stepId().equals("authenticate")) {
                assertTrue(step.elapsed().compareTo(delay) < 0, step.stepId() + " took " + step.elapsed());
            }
        }
        StepResult hook = run.steps().stream().filter(s -> s.stepId().equals("hook-request")).findFirst().orElseThrow();
        assertTrue(hook.elapsed().compareTo(delay) >= 0, "hook-request took " + hook.elapsed());
        assertEquals(List.of("perf.latency"), failIds(run));
    }

    @ParameterizedTest
    @ValueSource(strings = {"expired-token-401", "wrong-audience-reject"})
    void oauth401RecordsBothAttemptsAndRefresh(String fault) {
        OnboardingRun run = runner.run(request(NORTHWIND_ID, HEALTHY_SAMPLE, List.of(fault)));
        List<ExchangeView> tokens = exchanges(run, "authenticate");
        List<ExchangeView> hooks = exchanges(run, "hook-request");
        assertEquals(2, tokens.size());
        assertEquals(List.of(200, 200), tokens.stream().map(ExchangeView::status).toList());
        assertEquals(List.of(401, 401), hooks.stream().map(ExchangeView::status).toList());
        assertEquals(tokens.stream().mapToLong(ExchangeView::latencyMs).sum(),
                run.steps().get(2).elapsed().toMillis(), 1);
        assertTrue(tokens.stream().allMatch(e -> e.requestBody() == null));
        assertTrue(tokens.stream().noneMatch(e -> e.responseBody().contains("access_token")));
        assertEquals(1, run.findings().stream().filter(f -> f.checkId().equals("response.schema")
                && f.severity() == Severity.FAIL).count());
        assertEquals(fault.equals("expired-token-401") ? List.of("auth.clock-skew", "response.schema")
                : List.of("response.schema"), failIds(run));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void sdkRequestTimeoutIsReportedAtTheHook(String payerId) {
        OnboardingRunner timed = new OnboardingRunner(payers, new SampleCatalog(),
                new WorkbenchProperties(Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(10),
                        Duration.ofMillis(500), 10), new RunMetrics(new SimpleMeterRegistry()));
        OnboardingRun run = timed.run(request(payerId, HEALTHY_SAMPLE, List.of(Fault.SLOW_RESPONSE.id())));
        assertEquals("hook-request", firstFailedStep(run));
        ExchangeView hook = exchanges(run, "hook-request").getFirst();
        assertEquals(0, hook.status());
        assertTrue(hook.transportError().contains("HttpTimeoutException"), hook::transportError);
        assertTrue(failIds(run).contains("perf.latency"));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void sdkNormalizesOneTrailingSlashInBaseUrl(String payerId) {
        OnboardingRun run = runner.run(edited(payerId, new RunRequest.ConnectionOverrides("/", null, null)));
        assertEquals(List.of(), failIds(run));
        run.steps().forEach(step -> assertTrue(step.ok(), step::summary));
    }

    @Test
    void jwtAuthenticateRecordsActualNonSecretClaims() {
        OnboardingRun run = runner.run(request(FABRIKAM_ID, HEALTHY_SAMPLE, List.of()));
        Map<?, ?> claims = (Map<?, ?>) run.steps().get(2).details().get("jwtClaims");
        assertEquals(exchanges(run, "hook-request").getFirst().url(), claims.get("aud"));
        assertTrue(claims.containsKey("jti"));
        assertEquals(true, run.steps().get(2).details().get("audMatchesRequestUrl"));
        assertEquals("Bearer [REDACTED]", exchanges(run, "hook-request").getFirst().requestHeaders()
                .entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase("authorization"))
                .findFirst().orElseThrow().getValue().getFirst());
    }

    private static List<String> header(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue).findFirst().orElse(List.of());
    }

    @SuppressWarnings("unchecked")
    private static List<ExchangeView> exchanges(OnboardingRun run, String step) {
        return (List<ExchangeView>) run.steps().stream().filter(s -> s.stepId().equals(step))
                .findFirst().orElseThrow().details().get("exchanges");
    }

    @Test
    void wrongAudienceOnTheJwtPayerIsDiagnosedAsTheAudience() {
        OnboardingRun run = runner.run(request(FABRIKAM_ID, HEALTHY_SAMPLE, List.of(Fault.WRONG_AUDIENCE_REJECT.id())));

        assertEquals(List.of("auth.jwt-audience"), failIds(run));
        Finding audience = run.findings().stream()
                .filter(f -> f.checkId().equals("auth.jwt-audience")).findFirst().orElseThrow();
        assertEquals("Payer expects a different JWT audience", audience.title());
        assertTrue(audience.evidence().contains(FabrikamPayer.WRONG_AUDIENCE_BASE), audience::evidence);
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
        OnboardingRun run = runner.run(edited(payerId, new RunRequest.ConnectionOverrides("/r4", null, null)));

        assertEquals("discovery", firstFailedStep(run));
        assertEquals(List.of("discovery.reachable"), failIds(run));
    }

    @ParameterizedTest
    @ValueSource(strings = {NORTHWIND_ID, FABRIKAM_ID})
    void igVersionMismatchFailsIgVersionCheck(String payerId) {
        OnboardingRun run = runner.run(edited(payerId, new RunRequest.ConnectionOverrides(null, "1.0.0", null)));

        assertEquals(null, firstFailedStep(run));
        assertEquals(List.of("ig.version"), failIds(run));
    }

    @Test
    void wrongClientIdFailsTheTokenRequest() {
        OnboardingRun run = runner.run(edited(NORTHWIND_ID,
                new RunRequest.ConnectionOverrides(null, null, "someone-else")));

        assertEquals("authenticate", firstFailedStep(run));
        assertTrue(failIds(run).contains("auth.token"), "FAIL ids: " + failIds(run));
    }

    @Test
    void wrongIssuerIsRejectedByTheJwtPayer() {
        OnboardingRun run = runner.run(edited(FABRIKAM_ID,
                new RunRequest.ConnectionOverrides(null, null, "someone-else")));

        assertEquals("hook-request", firstFailedStep(run));
        assertTrue(failIds(run).contains("response.schema"), "FAIL ids: " + failIds(run));
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
