package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Redactor;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * A shareable diagnostic report of one {@link OnboardingRun}, the model behind every
 * export format. Every string in it has been through {@link Redactor} and every
 * field named like a secret is masked, so a renderer cannot leak credential
 * material even if a step put some in its details by mistake.
 *
 * @param title               report heading
 * @param disclaimer          what the run was made against and what it does not show: {@link #DISCLAIMER_TEXT}
 *                            for a synthetic payer, {@link #CUSTOM_DISCLAIMER_TEXT} for a user-supplied endpoint
 * @param generatedAt         when the report was produced (ISO-8601)
 * @param workbenchVersion    the workbench build that produced it
 * @param runId               the run reported on
 * @param correlationId       the {@code X-Request-Id} the run sent on every payer call, for finding it in
 *                            the payer's logs (the run id)
 * @param verdict             the one-line outcome
 * @param payer               which payer: a synthetic one or the custom endpoint
 * @param environment         which of its environments
 * @param igVersion           the CRD IG version the connection expected
 * @param advertisedIgVersion the CRD IG version the payer serves
 * @param startedAt           when the first step started (ISO-8601)
 * @param counts              findings per severity, most severe first
 * @param steps               the step timeline, in order
 * @param findings            findings, most severe first
 */
public record RunReport(
        String title,
        String disclaimer,
        String generatedAt,
        String workbenchVersion,
        String runId,
        String correlationId,
        Verdict verdict,
        Payer payer,
        String environment,
        String igVersion,
        String advertisedIgVersion,
        String startedAt,
        Map<Severity, Long> counts,
        List<Step> steps,
        List<Finding> findings
) {

    public static final String DISCLAIMER_TEXT = "Synthetic data only. This run was made against a synthetic mock payer "
            + "with synthetic requests; passing it does not demonstrate interoperability with any real payer, and the "
            + "report contains no real patient, provider or payer data. Tokens, secrets, keys and signatures are "
            + "redacted.";

    /** A custom endpoint's report holds what that endpoint really sent, so {@link #DISCLAIMER_TEXT} is false for it. */
    public static final String CUSTOM_DISCLAIMER_TEXT = "This run was made against a user-supplied endpoint with "
            + "synthetic requests; the report includes that endpoint's responses with credentials redacted. Passing "
            + "it does not by itself establish interoperability.";

    /** Overall outcome: {@code PASS}, {@code PASS_WITH_WARNINGS} or {@code FAIL}. */
    public record Verdict(String status, String headline, String brokeAt) {
    }

    public record Payer(String payerId, String displayName) {
    }

    /**
     * One step of the timeline.
     *
     * @param status    {@code passed}, {@code failed} or {@code skipped}
     * @param exchanges one line per HTTP exchange, e.g. {@code GET http://… → HTTP 200 · 12 ms}
     * @param details   the step's details, redacted
     */
    public record Step(
            String stepId,
            String title,
            String status,
            String startedAt,
            long elapsedMs,
            String summary,
            List<String> exchanges,
            Map<String, Object> details
    ) {
    }

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    /**
     * Builds the report.
     *
     * @param payerDisplayName    the payer's display name, or {@code null} to use the resolved connection's
     * @param advertisedIgVersion the IG version the payer serves, or {@code null} if unknown
     */
    public static RunReport of(OnboardingRun run, String payerDisplayName, String advertisedIgVersion,
                               Instant generatedAt, String workbenchVersion) {
        List<Step> steps = run.steps().stream().map(RunReport::step).toList();
        Map<String, Object> connection = steps.stream()
                .filter(s -> s.stepId().equals(OnboardingRunner.RESOLVE))
                .findFirst()
                .map(s -> s.details().get("connection"))
                .filter(Map.class::isInstance)
                .map(c -> asMap(c))
                .orElse(Map.of());
        String displayName = payerDisplayName != null ? payerDisplayName : (String) connection.get("displayName");

        List<Finding> findings = run.findings().stream()
                .sorted(Comparator.comparing(Finding::severity).reversed())
                .map(f -> new Finding(f.checkId(), f.severity(), redact(f.title()), redact(f.explanation()),
                        f.evidence(), redact(f.suggestedFix())))
                .toList();
        RunVerdict summary = RunVerdict.of(run);

        return new RunReport(
                "Payer onboarding report: " + (displayName == null ? run.payerId() : displayName),
                RunRequest.CUSTOM_PAYER_ID.equals(run.payerId()) ? CUSTOM_DISCLAIMER_TEXT : DISCLAIMER_TEXT,
                generatedAt.toString(),
                workbenchVersion,
                run.runId(),
                run.runId(),
                summary.reportVerdict(),
                new Payer(run.payerId(), displayName),
                run.environment().name(),
                (String) connection.get("igVersion"),
                advertisedIgVersion,
                run.steps().isEmpty() ? null : run.steps().getFirst().startedAt().toString(),
                summary.counts(),
                steps,
                findings);
    }

    private static Step step(StepResult step) {
        Map<String, Object> details = asMap(Redactor.redactTree(MAPPER.convertValue(step.details(), Map.class)));
        List<String> exchanges = new ArrayList<>();
        if (details.get("exchanges") instanceof List<?> list) {
            for (Object x : list) {
                if (x instanceof Map<?, ?> e) {
                    exchanges.add(exchangeLine(e));
                }
            }
        }
        return new Step(step.stepId(), RunVerdict.title(step.stepId()),
                RunVerdict.stepStatus(step),
                step.startedAt().toString(), step.elapsed().toMillis(), redact(step.summary()),
                List.copyOf(exchanges), details);
    }

    private static String exchangeLine(Map<?, ?> e) {
        Object status = e.get("status");
        boolean responded = status instanceof Number n && n.intValue() > 0;
        return e.get("method") + " " + e.get("url") + " → "
                + (responded ? "HTTP " + status : "no response")
                + (e.get("latencyMs") == null ? "" : " · " + e.get("latencyMs") + " ms")
                + (e.get("transportError") == null ? "" : " (" + e.get("transportError") + ")");
    }

    private static String redact(String text) {
        return Redactor.redact(text);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value == null ? Map.of() : (Map<String, Object>) value;
    }
}
