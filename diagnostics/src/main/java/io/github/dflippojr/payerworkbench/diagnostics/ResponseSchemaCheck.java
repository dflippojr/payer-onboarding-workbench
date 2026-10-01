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
 * ({@code info}, {@code warning} or {@code critical}).
 */
public final class ResponseSchemaCheck implements DiagnosticCheck {

    public static final String ID = "response.schema";

    static final Set<String> INDICATORS = Set.of("info", "warning", "critical");
    static final int MAX_SUMMARY = 140;

    @Override
    public String id() {
        return ID;
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
            if (!Support.isSuccess(exchange.status())) {
                findings.add(new Finding(ID, Severity.FAIL, "Hook call to " + label + " returned HTTP " + exchange.status(),
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
                findings.add(fail(label, List.of("response body is not a JSON object"), exchange));
                continue;
            }
            List<String> problems = new ArrayList<>();
            List<String> warnings = new ArrayList<>();
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
                findings.add(fail(label, problems, exchange));
            } else if (!warnings.isEmpty()) {
                findings.add(new Finding(ID, Severity.WARN, "Cards from " + label + " bend the CDS Hooks rules",
                        "The response is usable, but some cards break CDS Hooks recommendations that EHRs rely on "
                                + "when displaying them, so they may be truncated or shown oddly.",
                        String.join("\n", warnings) + "\n" + Support.describe(exchange),
                        "Ask the payer to fix the listed fields; the library will still parse the cards."));
            } else {
                okCalls++;
            }
        }
        if (findings.isEmpty() && okCalls > 0) {
            findings.add(new Finding(ID, Severity.PASS, "Hook responses are well-formed",
                    "Every hook response was valid CDS Hooks JSON, and every card had a summary, a valid "
                            + "indicator and a source label.",
                    okCalls + " response(s), " + cardCount + " card(s) checked", null));
        }
        return findings;
    }

    private static void validateCard(JsonNode card, String path, List<String> problems, List<String> warnings) {
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
    }

    private static Finding fail(String label, List<String> problems, HttpExchange exchange) {
        return new Finding(ID, Severity.FAIL, "Invalid CDS Hooks response from " + label,
                "The response does not follow the CDS Hooks card format. Each card (a message the payer wants "
                        + "shown to the clinician) needs a summary, an indicator of info, warning or critical, "
                        + "and a source label naming the payer; EHRs may drop or refuse cards that lack them.",
                String.join("\n", problems) + "\n" + Support.describe(exchange),
                "Send the payer the listed problems; until fixed, expect these cards to be dropped. If the payer "
                        + "uses another indicator word (e.g. \"hard-stop\"), ask them to map it to critical.");
    }
}
