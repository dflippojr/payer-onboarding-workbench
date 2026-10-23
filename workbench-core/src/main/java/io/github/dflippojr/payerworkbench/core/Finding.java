package io.github.dflippojr.payerworkbench.core;

import java.util.Objects;

/**
 * One result from a {@link DiagnosticCheck}, written for a person reading the report.
 *
 * <p>No text field may contain secret material; since a check may quote what the payer sent,
 * which may echo the credentials it received, the constructor passes {@code title},
 * {@code explanation}, {@code evidence} and {@code suggestedFix} through
 * {@link Redactor#redact(String)} as a safety net. Each is then cut to
 * {@link TextLimit#MAX_FINDING_CHARS}.
 *
 * @param checkId the {@link DiagnosticCheck#id()} that produced this finding
 * @param severity how serious it is
 * @param title one-line summary, redacted
 * @param explanation what went wrong (or right) and why it matters, in plain language, redacted
 * @param evidence the observed data that supports the finding, already redacted; may be {@code null}
 * @param suggestedFix what to change to resolve it, redacted; may be {@code null} for {@link Severity#PASS}
 */
public record Finding(
        String checkId,
        Severity severity,
        String title,
        String explanation,
        String evidence,
        String suggestedFix
) {
    public Finding {
        Objects.requireNonNull(checkId, "checkId");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(title, "title");
        // Redact before cutting, so a cut never leaves part of a secret the redactor no longer recognizes.
        title = redactedAndCut(title);
        explanation = redactedAndCut(explanation);
        evidence = redactedAndCut(evidence);
        suggestedFix = redactedAndCut(suggestedFix);
    }

    private static String redactedAndCut(String text) {
        return TextLimit.cut(Redactor.redact(text), TextLimit.MAX_FINDING_CHARS);
    }
}
