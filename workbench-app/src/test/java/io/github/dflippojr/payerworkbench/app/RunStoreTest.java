package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RunStoreTest {
    private final RunStore store = new RunStore(new WorkbenchProperties(null, null, null, null, 2));

    @Test
    void emptyHistoryAndInsertionOrderEviction() {
        assertTrue(store.list().isEmpty());
        store.save(run("one", Severity.PASS, true));
        store.save(run("two", Severity.WARN, true));
        var snapshot = store.list();
        assertEquals(List.of("two", "one"), snapshot.stream().map(RunSummary::runId).toList());
        store.find("one"); // Retrieval must not move the oldest entry.
        store.save(run("three", Severity.FAIL, false));
        assertEquals(List.of("three", "two"), store.list().stream().map(RunSummary::runId).toList());
        assertTrue(store.find("one").isEmpty());
        assertEquals(2, snapshot.size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.clear());
    }

    @ParameterizedTest
    @EnumSource(Severity.class)
    void summariesMatchReportAndExcludeAllDetails(Severity severity) {
        var run = run("summary", severity, true);
        store.save(run);
        var summary = store.list().getFirst();
        var report = RunReport.of(run, null, null, Instant.EPOCH, "test");
        assertEquals(report.verdict().status(), summary.verdict());
        assertEquals(report.counts(), summary.counts());
        assertEquals(report.startedAt(), summary.startedAt());
        assertEquals("SANDBOX", summary.environment());
        assertEquals("synthetic-payer", summary.payerId());
        var mapper = JsonMapper.builder().build();
        var json = mapper.valueToTree(summary);
        Set<String> fields = json.properties().stream().map(Map.Entry::getKey).collect(Collectors.toSet());
        assertEquals(Set.of("runId", "payerId", "environment", "startedAt", "verdict", "counts"), fields);
        assertFalse(json.toString().contains("PLANTED"));
        assertEquals(4, json.path("counts").size());
    }

    @Test
    void failedStepAndNoStepsFollowReportSemantics() {
        store.save(run("broken", Severity.PASS, false));
        assertEquals("FAIL", store.list().getFirst().verdict());
        store.save(new OnboardingRun("empty", "synthetic-payer", Environment.SANDBOX, List.of(), List.of()));
        assertNull(store.list().getFirst().startedAt());
        assertEquals("PASS", store.list().getFirst().verdict());
    }

    static Stream<OnboardingRun> parityRuns() {
        Instant at = Instant.parse("2026-10-01T12:00:00.123456Z");
        StepResult passed = new StepResult("discovery", at, Duration.ZERO, true, "ok", Map.of());
        StepResult broken = new StepResult("authenticate", at.plusSeconds(1), Duration.ZERO, false, "broken", Map.of());
        StepResult diagnosticsFailed = new StepResult("diagnostics", at, Duration.ZERO, false, "diag",
                Map.of("status", "failed"));
        return Stream.of(
                parityRun("pass", List.of(passed), Severity.PASS, Severity.INFO),
                parityRun("warnings", List.of(passed), Severity.PASS, Severity.WARN, Severity.WARN),
                parityRun("fail-finding", List.of(passed), Severity.FAIL, Severity.WARN, Severity.PASS),
                parityRun("fail-broken-step", List.of(passed, broken), Severity.WARN, Severity.PASS),
                parityRun("diagnostics-only", List.of(passed, diagnosticsFailed), Severity.PASS),
                parityRun("diagnostics-with-fail", List.of(diagnosticsFailed), Severity.FAIL),
                parityRun("no-steps", List.of()));
    }

    @ParameterizedTest
    @MethodSource("parityRuns")
    void summaryFromRawRunMatchesReport(OnboardingRun run) {
        var summary = RunSummary.of(run);
        var report = RunReport.of(run, null, null, Instant.EPOCH, "unknown");
        assertEquals(new RunSummary(run.runId(), run.payerId(), report.environment(), report.startedAt(),
                report.verdict().status(), report.counts()), summary);
        assertEquals(List.copyOf(report.counts().keySet()), List.copyOf(summary.counts().keySet()));
        var mapper = JsonMapper.builder().build();
        assertEquals(mapper.valueToTree(report.counts()).toString(), mapper.valueToTree(summary.counts()).toString());
        assertThrows(UnsupportedOperationException.class, () -> summary.counts().put(Severity.FAIL, 0L));
    }

    @Test
    void concurrentSaveAndListAreBoundedSafeSnapshots() throws Exception {
        try (var executor = Executors.newFixedThreadPool(4)) {
            var tasks = IntStream.range(0, 100).<java.util.concurrent.Callable<Void>>mapToObj(i -> () -> {
                store.save(run("concurrent-" + i, Severity.PASS, true));
                var snapshot = store.list();
                assertTrue(snapshot.size() <= 2);
                assertEquals(snapshot.size(), snapshot.stream().map(RunSummary::runId).distinct().count());
                return null;
            }).toList();
            for (var result : executor.invokeAll(tasks)) result.get();
        }
        assertEquals(2, store.list().size());
    }

    @Test
    void maxRunsRunsWithBodiesNearTheResponseLimitStayWithinTheByteBudget() {
        // #162: 200 runs x a 4 MiB body used to exhaust a 512 MiB heap. Each run now keeps a 64 Ki prefix.
        var properties = new WorkbenchProperties(null, null, null, null, null);
        var bounded = new RunStore(properties);
        String nearLimit = "{\"cards\":[],\"padding\":\"" + "a".repeat(properties.maxResponseBytes().intValue() - 30) + "\"}";
        ExchangeView kept = ExchangeView.of(new HttpExchange("POST", "http://127.0.0.1/hook", 200, Duration.ZERO,
                Map.of(), "{}", Map.of(), nearLimit, null));
        assertTrue(kept.responseBody().length() < ExchangeView.BODY_LIMIT_CHARS + 100, "kept " + kept.responseBody().length());
        assertTrue(kept.responseBody().endsWith(" of " + nearLimit.length() + " characters]"));
        for (int i = 0; i < properties.maxRuns(); i++) {
            bounded.save(new OnboardingRun("near-limit-" + i, "synthetic-payer", Environment.SANDBOX,
                    List.of(new StepResult("hook-request", Instant.EPOCH, Duration.ZERO, false, "too large",
                            Map.of("exchanges", List.of(kept)))), List.of()));
        }
        assertEquals(properties.maxRuns(), bounded.list().size());
        assertTrue(bounded.storedBytes() < properties.maxRuns() * (ExchangeView.BODY_LIMIT_CHARS + 1024L),
                "stored " + bounded.storedBytes());
        assertTrue(bounded.storedBytes() <= properties.maxStoredRunBytes());
    }

    @Test
    void keptPrefixCutThroughAMaskIsMaskedWhole() {
        String head = "{\"padding\":\"" + "a".repeat(ExchangeView.BODY_LIMIT_CHARS - 35) + "\",\"access_token\":\"";
        String kept = ExchangeView.kept(head + "[REDACTED]\"}" + "b".repeat(100));
        assertTrue(kept.startsWith(head + "[REDACTED]\"\n[kept the first " + ExchangeView.BODY_LIMIT_CHARS + " of "), kept.substring(head.length()));
        assertEquals("short", ExchangeView.kept("short"));
    }

    @Test
    void byteBudgetForgetsTheOldestRunsFirstAndKeepsTheNewest() {
        var bounded = new RunStore(new WorkbenchProperties(null, null, null, null, 200, null, null, null, 100_000L));
        // A run can be large for reasons other than a body, such as thousands of cards.
        for (int i = 0; i < 5; i++) {
            bounded.save(new OnboardingRun("big-" + i, "synthetic-payer", Environment.SANDBOX,
                    List.of(new StepResult("parse-response", Instant.EPOCH, Duration.ZERO, true, "parsed",
                            Map.of("cards", List.of("c".repeat(40_000))))), List.of()));
        }
        assertEquals(List.of("big-4", "big-3"), bounded.list().stream().map(RunSummary::runId).toList());
        assertTrue(bounded.storedBytes() <= 100_000L, "stored " + bounded.storedBytes());
        bounded.save(new OnboardingRun("huge", "synthetic-payer", Environment.SANDBOX,
                List.of(new StepResult("parse-response", Instant.EPOCH, Duration.ZERO, true, "c".repeat(200_000),
                        Map.of())), List.of()));
        assertEquals(List.of("huge"), bounded.list().stream().map(RunSummary::runId).toList());
        assertTrue(bounded.find("huge").isPresent());
    }

    private static OnboardingRun parityRun(String id, List<StepResult> steps, Severity... severities) {
        return new OnboardingRun(id, "synthetic-payer", Environment.SANDBOX, steps,
                Stream.of(severities).map(s -> new Finding("synthetic", s, "Synthetic", "Synthetic", null, null)).toList());
    }

    private static OnboardingRun run(String id, Severity severity, boolean ok) {
        return new OnboardingRun(id, "synthetic-payer", Environment.SANDBOX,
                List.of(new StepResult("discovery", Instant.parse("2026-10-01T12:00:00Z"), Duration.ZERO,
                        ok, "PLANTED body", Map.of("clientSecret", "PLANTED credential",
                        "exchanges", List.of(Map.of("requestBody", "PLANTED request", "responseBody", "PLANTED response"))))),
                List.of(new Finding("synthetic", severity, "PLANTED title", "PLANTED explanation", null, null)));
    }
}
