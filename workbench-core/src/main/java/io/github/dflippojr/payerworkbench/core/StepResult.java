package io.github.dflippojr.payerworkbench.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * The outcome of one step of an onboarding run, such as fetching discovery,
 * obtaining a token or calling a hook.
 *
 * <p>The summary and details often quote what the payer sent, which may echo the credentials it
 * received, so the constructor passes both through {@link Redactor} as a safety net, as
 * {@link Finding} does its text.
 *
 * @param stepId stable identifier of the step, e.g. {@code discovery}
 * @param startedAt when the step started
 * @param elapsed how long it took
 * @param ok whether the step completed successfully
 * @param summary one-line human-readable outcome, redacted
 * @param details extra step-specific values for display; must not contain secret material, and must be
 *     JSON-shaped plain data: strings, numbers, booleans, {@code null}, maps with string keys and lists
 *     ({@link Redactor#redactTree(Object)}, #377), so a caller converts a record or an enum first.
 *     Redacted through it into an unmodifiable map that keeps insertion order.
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
        summary = Redactor.redact(summary);
        details = details == null ? Map.of() : redactedDetails(details);
    }

    /** The details redacted; if they are not JSON-shaped plain data, one {@code details} entry holding the mask. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> redactedDetails(Map<String, Object> details) {
        return Redactor.redactTree(details) instanceof Map<?, ?> safe
                ? (Map<String, Object>) safe
                : Map.of("details", Redactor.MASK);
    }
}
