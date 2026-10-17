package io.github.dflippojr.payerworkbench.core;

import java.util.Objects;

/**
 * One result from a {@link DiagnosticCheck}, written for a person reading the report.
 *
 * <p>{@code evidence} must never contain secret material; the constructor passes it
 * through {@link Redactor#redact(String)} as a safety net. Each text field is then cut to
 * {@link TextLimit#MAX_FINDING_CHARS}, since a check may quote what the payer sent.
 *
 * @param checkId the {@link DiagnosticCheck#id()} that produced this finding
 * @param severity how serious it is
 * @param title one-line summary
 * @param explanation what went wrong (or right) and why it matters, in plain language
 * @param evidence the observed data that supports the finding, already redacted; may be {@code null}
 * @param suggestedFix what to change to resolve it; may be {@code null} for {@link Severity#PASS}
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
        evidence = TextLimit.cut(Redactor.redact(evidence), TextLimit.MAX_FINDING_CHARS);
        title = TextLimit.cut(title, TextLimit.MAX_FINDING_CHARS);
        explanation = TextLimit.cut(explanation, TextLimit.MAX_FINDING_CHARS);
        suggestedFix = TextLimit.cut(suggestedFix, TextLimit.MAX_FINDING_CHARS);
    }
}
