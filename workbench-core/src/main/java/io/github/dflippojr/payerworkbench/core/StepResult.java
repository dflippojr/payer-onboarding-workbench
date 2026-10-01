package io.github.dflippojr.payerworkbench.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The outcome of one step of an onboarding run, such as fetching discovery,
 * obtaining a token or calling a hook.
 *
 * @param stepId stable identifier of the step, e.g. {@code discovery}
 * @param startedAt when the step started
 * @param elapsed how long it took
 * @param ok whether the step completed successfully
 * @param summary one-line human-readable outcome
 * @param details extra step-specific values for display; must not contain secret
 *     material. Copied into an unmodifiable map that keeps insertion order.
 */
public record StepResult(
        String stepId,
        Instant startedAt,
        Duration elapsed,
        boolean ok,
        String summary,
        Map<String, Object> details
) {
    public StepResult {
        Objects.requireNonNull(stepId, "stepId");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(elapsed, "elapsed");
        details = details == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(details));
    }
}
