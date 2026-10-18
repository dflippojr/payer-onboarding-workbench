package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * {@code response.schema}: each hook call returned HTTP 2xx with a CDS Hooks
 * response whose cards have the required fields ({@code summary},
 * {@code indicator}, {@code source.label}) and a valid {@code indicator}
 * ({@code info}, {@code warning} or {@code critical}). A card with suggestions also needs a
 * {@code selectionBehavior} of {@code at-most-one} or {@code any} (CDS Hooks 2.0 Card; HL7 tools invariant
 * {@code cds-resp-6}). Authentication and throttling errors that dedicated checks explain are left to those checks.
 */
public final class ResponseSchemaCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "response.schema";

    static final Set<String> INDICATORS = Set.of("info", "warning", "critical");
    static final Set<String> SELECTION_BEHAVIORS = Set.of("at-most-one", "any");
    static final int MAX_SUMMARY = 140;

    @Override
    public String id() {
        return CHECK_ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        int cardCount = 0;
        int okCalls = 0;
        for (HookResponse hook : obs.hookResponses()) {
            HttpExchange exchange = hook.exchange();
            String label = hook.serviceId() + (hook.sampleId() == null ? "" : " (sample " + hook.sampleId() + ")");
            if (!exchange.responded()) {
                // Transport failures are reported by tls.handshake and perf.latency.
                continue;
            }
            if (JwtAudienceCheck.explains(hook) || HookRejectedCheck.explains(hook) || RateLimitCheck.explains(hook)) {
                // Authentication and throttling have dedicated findings.
                continue;
            }
            if (!Support.isSuccess(exchange.status())) {
                findings.add(new Finding(CHECK_ID, Severity.FAIL, "Hook call to " + label + " returned HTTP " + exchange.status(),
                        "The payer answered the hook call with an error status instead of a CDS Hooks response, "
                                + "so there are no cards (the messages a payer shows the clinician) to check.",
                        Support.describe(exchange),
                        exchange.status() == 401 || exchange.status() == 403
                                ? "Check the access token sent on hook calls and the auth.* findings."
                                : "Compare the request (hook, context and prefetch) with the payer's onboarding "
                                        + "guide; the response body usually names the field it rejected."));
                continue;
            }
            Optional<JsonNode> json = Support.parseJson(exchange.responseBody());
            if (json.isEmpty() || !json.get().isObject()) {
                findings.add(fail(label, "response body is not a JSON object", exchange));
                continue;
            }
            CappedLines problems = new CappedLines();
            CappedLines warnings = new CappedLines();
            JsonNode cards = json.get().get("cards");
            if (cards == null || !cards.isArray()) {
                problems.add("missing required \"cards\" array (send [] when there is nothing to say)");
            } else {
                for (int i = 0; i < cards.size(); i++) {
                    cardCount++;
                    validateCard(cards.get(i), "cards[" + i + "]", problems, warnings);
                }
            }
            if (!problems.isEmpty()) {
                findings.add(fail(label, problems.join("\n"), exchange));
            } else if (!warnings.isEmpty()) {
                findings.add(new Finding(CHECK_ID, Severity.WARN, "Cards from " + label + " bend the CDS Hooks rules",
                        "The response is usable, but some cards break CDS Hooks recommendations that EHRs rely on "
                                + "when displaying them, so they may be truncated or shown oddly.",
                        warnings.join("\n") + "\n" + Support.describe(exchange),
                        "Ask the payer to fix the listed fields; the library will still parse the cards."));
            } else {
                okCalls++;
            }
        }
        if (findings.isEmpty() && okCalls > 0) {
            findings.add(new Finding(CHECK_ID, Severity.PASS, "Hook responses are well-formed",
                    "Every hook response was valid CDS Hooks JSON, and every card had a summary, a valid "
                            + "indicator, a source label and, when it offered suggestions, a selection behavior.",
                    okCalls + " response(s), " + cardCount + " card(s) checked", null));
        }
        return findings;
    }

    private static void validateCard(JsonNode card, String path, CappedLines problems, CappedLines warnings) {
        if (!card.isObject()) {
            problems.add(path + " is not a JSON object");
            return;
        }
        JsonNode summary = card.get("summary");
        if (summary == null || !summary.isTextual() || summary.asText().isBlank()) {
            problems.add(path + ".summary is missing");
        } else if (summary.asText().length() > MAX_SUMMARY) {
            warnings.add(path + ".summary is " + summary.asText().length() + " characters (limit " + MAX_SUMMARY + ")");
        }
        JsonNode indicator = card.get("indicator");
        if (indicator == null || !indicator.isTextual()) {
            problems.add(path + ".indicator is missing");
        } else if (!INDICATORS.contains(indicator.asText())) {
            problems.add(path + ".indicator is \"" + indicator.asText() + "\" (must be info, warning or critical)");
        }
        JsonNode source = card.get("source");
        if (source == null || !source.isObject()) {
            problems.add(path + ".source is missing");
        } else if (!source.path("label").isTextual() || source.path("label").asText().isBlank()) {
            problems.add(path + ".source.label is missing");
        }
        JsonNode behavior = card.get("selectionBehavior");
        if (behavior != null && !SELECTION_BEHAVIORS.contains(behavior.asText())) {
            problems.add(path + ".selectionBehavior is \"" + behavior.asText() + "\" (must be at-most-one or any)");
        } else if (behavior == null && card.path("suggestions").isArray() && !card.path("suggestions").isEmpty()) {
            problems.add(path + ".selectionBehavior is missing (required when the card has suggestions)");
        }
    }

    private static Finding fail(String label, String problems, HttpExchange exchange) {
        return new Finding(CHECK_ID, Severity.FAIL, "Invalid CDS Hooks response from " + label,
                "The response does not follow the CDS Hooks card format. Each card (a message the payer wants "
                        + "shown to the clinician) needs a summary, an indicator of info, warning or critical, "
                        + "and a source label naming the payer, and a card with suggestions needs a selection "
                        + "behavior (at-most-one or any); EHRs may drop or refuse cards that lack them.",
                problems + "\n" + Support.describe(exchange),
                "Send the payer the listed problems; until fixed, expect these cards to be dropped. If the payer "
                        + "uses another indicator word (e.g. \"hard-stop\"), ask them to map it to critical.");
    }
}
