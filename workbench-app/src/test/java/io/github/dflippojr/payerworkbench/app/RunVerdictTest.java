package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RunVerdictTest {
    record Case(List<StepResult> steps, List<Severity> findings, String status, String headline, String brokeAt) { }

    static Stream<Case> cases() {
        String pass = "Every step passed and no check failed.";
        String fail = "Not ready: the flow broke at Discovery.";
        return Stream.of(
                new Case(List.of(), List.of(), "PASS", pass, null),
                new Case(List.of(), List.of(Severity.INFO), "PASS", pass, null),
                new Case(List.of(step("discovery", true, "passed")), List.of(Severity.PASS), "PASS", pass, null),
                new Case(List.of(), List.of(Severity.WARN), "PASS_WITH_WARNINGS",
                        "Every step passed, with 1 warning to review.", null),
                new Case(List.of(), List.of(Severity.WARN, Severity.WARN), "PASS_WITH_WARNINGS",
                        "Every step passed, with 2 warnings to review.", null),
                new Case(List.of(), List.of(Severity.FAIL), "FAIL",
                        "Not ready: 1 failing check. Onboarding cannot succeed until it is fixed.", null),
                new Case(List.of(step("discovery", true, "failed"), step("authenticate", false, "failed")),
                        List.of(Severity.FAIL, Severity.FAIL, Severity.WARN), "FAIL",
                        "Not ready: 2 failing checks; the flow broke at Discovery. Onboarding cannot succeed until they are fixed.", "discovery"),
                new Case(List.of(step("discovery", true, "failed")), List.of(Severity.WARN), "FAIL", fail, "discovery"),
                new Case(List.of(step("diagnostics", false, "failed")), List.of(), "PASS", pass, null),
                new Case(List.of(step("diagnostics", false, "failed")), List.of(Severity.FAIL), "FAIL",
                        "Not ready: 1 failing check. Onboarding cannot succeed until it is fixed.", null),
                new Case(List.of(step("discovery", false, "skipped")), List.of(), "PASS", pass, null),
                new Case(List.of(step("discovery", false, "passed")), List.of(), "PASS", pass, null),
                new Case(List.of(step("discovery", true, null)), List.of(), "PASS", pass, null),
                new Case(List.of(step("discovery", false, null)), List.of(), "FAIL", fail, "discovery"),
                new Case(List.of(step("discovery", true, 42)), List.of(), "PASS", pass, null),
                new Case(List.of(step("discovery", false, 42)), List.of(), "FAIL", fail, "discovery"),
                new Case(List.of(step("synthetic-custom", false, "failed")), List.of(), "FAIL",
                        "Not ready: the flow broke at synthetic-custom.", "synthetic-custom"));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void reportAndMetricsUseTheSameRawPolicy(Case c) {
        List<Finding> findings = c.findings.stream().map(severity ->
                new Finding("synthetic-check", severity, "Synthetic", "Synthetic", null, null)).toList();
        OnboardingRun run = new OnboardingRun("synthetic-run", "northwind-synthetic", Environment.SANDBOX,
                c.steps, findings);
        RunVerdict summary = RunVerdict.of(run);
        RunReport report = RunReport.of(run, null, null, Instant.EPOCH, "test");
        assertEquals(c.status, summary.status());
        assertEquals(c.brokeAt, summary.brokeAt());
        assertEquals(c.status, report.verdict().status());
        assertEquals(c.headline, report.verdict().headline());
        assertEquals(c.brokeAt == null ? null : RunVerdict.title(c.brokeAt), report.verdict().brokeAt());
        assertEquals(List.of(Severity.FAIL, Severity.WARN, Severity.INFO, Severity.PASS),
                List.copyOf(report.counts().keySet()));
        for (Severity severity : Severity.values()) {
            assertEquals(c.findings.stream().filter(s -> s == severity).count(), report.counts().get(severity));
        }
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            new RunMetrics(registry).record(run, List.of());
            assertEquals(1, registry.get(RunMetrics.RUNS).tags("verdict", c.status,
                    "broke_at", c.brokeAt == null ? "none" : c.brokeAt).counter().count());
            for (StepResult step : c.steps) {
                assertEquals(1, registry.get(RunMetrics.STEP_DURATION).tags("step", step.stepId(),
                        "status", RunVerdict.stepStatus(step)).timer().count());
            }
        } finally {
            registry.close();
        }
    }

    /** Jackson would invoke this accessor if metrics accidentally built a report. */
    public static class UnreadableBody {
        public String getBody() {
            throw new AssertionError("Metrics must not convert or traverse exchange bodies");
        }
    }

    @Test
    void metricsIgnoreDiagnosticBodies() {
        StepResult step = new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "Synthetic",
                Map.of("status", "passed", "exchanges", List.of(new UnreadableBody())));
        OnboardingRun run = new OnboardingRun("synthetic-run", "northwind-synthetic", Environment.SANDBOX,
                List.of(step), List.of());
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            new RunMetrics(registry).record(run, List.of());
            assertEquals(1, registry.get(RunMetrics.RUNS).tags("verdict", "PASS", "broke_at", "none")
                    .counter().count());
        } finally {
            registry.close();
        }
    }

    private static StepResult step(String id, boolean ok, Object status) {
        return new StepResult(id, Instant.EPOCH, Duration.ofMillis(12), ok, "Synthetic",
                status == null ? Map.of() : Map.of("status", status));
    }
}
