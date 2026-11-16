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
 * {@link Finding} does its text, and the step id too, as caller text.
 *
 * @param stepId stable identifier of the step, e.g. {@code discovery}, redacted
 * @param startedAt when the step started
 * @param elapsed how long it took
 * @param ok whether the step completed successfully
 * @param summary one-line human-readable outcome, redacted
 * @param details extra step-specific values for display; must not contain secret material.
 *     Copied, through {@link Redactor#redactTree(Object)}, into an unmodifiable map that keeps
 *     insertion order; keys at every depth are redacted as text too. Only strings, maps, lists and
 *     exact JDK scalars keep their shape: any other value, a record or an enum included, becomes
 *     its redacted text, so callers pass the JSON form.
 */
public record StepResult(
        String stepId,
        Instant startedAt,
        Duration elapsed,
        boolean ok,
        String summary,
        Map<String, Object> details
) {
    @SuppressWarnings("java:S1181") // The outermost boundary (#360): any Throwable masks the step's text.
    public StepResult {
        // These three name a missing parameter only, in a fixed message; they read no caller text.
        Objects.requireNonNull(stepId, "stepId");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(elapsed, "elapsed");
        try {
            stepId = Redactor.redact(stepId);
            summary = Redactor.redact(summary);
            details = details == null ? Map.of() : redactedDetails(details);
        } catch (Throwable e) {
            // The outermost fail-closed boundary: every text is masked, and nothing of the exception is kept.
            stepId = Redactor.MASK;
            summary = Redactor.MASK;
            details = Map.of("details", Redactor.MASK);
        }
    }

    /** The redacted details, or one masked entry where the details as a whole could not be read. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> redactedDetails(Map<String, Object> details) {
        return Redactor.redactTree(details) instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of("details", Redactor.MASK);
    }
}
