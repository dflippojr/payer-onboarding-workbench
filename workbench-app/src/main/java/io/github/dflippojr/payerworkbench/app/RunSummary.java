package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;

import java.util.Collections;
import java.util.Map;

/**
 * Only the identifiers, timing and outcome needed to browse retained runs. Built from the raw run and the
 * shared {@link RunVerdict} policy, never from a {@link RunReport}: no step details are converted or redacted.
 */
public record RunSummary(String runId, String payerId, String environment, String startedAt,
                         String verdict, Map<Severity, Long> counts) {
    public static RunSummary of(OnboardingRun run) {
        RunVerdict verdict = RunVerdict.of(run);
        return new RunSummary(run.runId(), run.payerId(), run.environment().name(),
                run.steps().isEmpty() ? null : run.steps().getFirst().startedAt().toString(),
                verdict.status(), Collections.unmodifiableMap(verdict.counts()));
    }
}
