package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

    private static OnboardingRun run(String id, Severity severity, boolean ok) {
        return new OnboardingRun(id, "synthetic-payer", Environment.SANDBOX,
                List.of(new StepResult("discovery", Instant.parse("2026-10-01T12:00:00Z"), Duration.ZERO,
                        ok, "PLANTED body", Map.of("clientSecret", "PLANTED credential",
                        "exchanges", List.of(Map.of("requestBody", "PLANTED request", "responseBody", "PLANTED response"))))),
                List.of(new Finding("synthetic", severity, "PLANTED title", "PLANTED explanation", null, null)));
    }
}
