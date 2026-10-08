package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;

import java.time.Instant;
import java.util.Map;

/** Only the identifiers, timing and outcome needed to browse retained runs. */
public record RunSummary(String runId, String payerId, String environment, String startedAt,
                         String verdict, Map<Severity, Long> counts) {
    public static RunSummary of(OnboardingRun run) {
        RunReport report = RunReport.of(run, null, null, Instant.EPOCH, "unknown");
        return new RunSummary(run.runId(), run.payerId(), report.environment(), report.startedAt(),
                report.verdict().status(), Map.copyOf(report.counts()));
    }
}
