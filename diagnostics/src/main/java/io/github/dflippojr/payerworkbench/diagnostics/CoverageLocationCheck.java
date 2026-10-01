package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code response.coverage-location}: where the payer puts CRD coverage
 * information. CRD 2.x returns it as {@code systemActions} that update the order;
 * some payers put it in card suggestions instead. The router's library reads both,
 * so this is informational.
 */
public final class CoverageLocationCheck implements DiagnosticCheck {

    public static final String ID = "response.coverage-location";

    /** The CRD coverage-information extension URL. */
    public static final String COVERAGE_INFORMATION_URL =
            "http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<String> inSystemActions = new ArrayList<>();
        List<String> inSuggestions = new ArrayList<>();
        for (HookResponse hook : obs.hookResponses()) {
            if (!Support.isSuccess(hook.exchange().status())) {
                continue;
            }
            JsonNode json = Support.parseJson(hook.exchange().responseBody()).orElse(null);
            if (json == null) {
                continue;
            }
            JsonNode actions = json.path("systemActions");
            for (int i = 0; i < actions.size(); i++) {
                if (hasCoverageInfo(actions.get(i).path("resource"))) {
                    inSystemActions.add(hook.serviceId() + ": systemActions[" + i + "]");
                }
            }
            JsonNode cards = json.path("cards");
            for (int c = 0; c < cards.size(); c++) {
                JsonNode suggestions = cards.get(c).path("suggestions");
                for (int s = 0; s < suggestions.size(); s++) {
                    JsonNode suggestionActions = suggestions.get(s).path("actions");
                    for (int a = 0; a < suggestionActions.size(); a++) {
                        if (hasCoverageInfo(suggestionActions.get(a).path("resource"))) {
                            inSuggestions.add(hook.serviceId() + ": cards[" + c + "].suggestions[" + s
                                    + "].actions[" + a + "]");
                        }
                    }
                }
            }
        }
        if (!inSuggestions.isEmpty()) {
            return List.of(new Finding(ID, Severity.INFO, "Coverage information delivered in card suggestions",
                    "The payer returns its coverage determination (the CRD coverage-information extension saying "
                            + "whether prior authorization or documentation is needed) inside a card suggestion "
                            + "the clinician must accept, rather than as a systemAction the EHR applies "
                            + "automatically as CRD 2.x expects. The router's library reads both places, but EHRs "
                            + "and other clients that only read systemActions will miss it.",
                    "found in suggestions: " + String.join(", ", inSuggestions)
                            + (inSystemActions.isEmpty() ? "" : "\nfound in systemActions: " + String.join(", ", inSystemActions)),
                    "No change is needed for this library. If other clients will consume this payer, ask the payer "
                            + "to also send coverage information as an update systemAction on the order."));
        }
        if (!inSystemActions.isEmpty()) {
            return List.of(new Finding(ID, Severity.PASS, "Coverage information delivered in systemActions",
                    "The payer returns coverage information as systemActions, the location CRD 2.x specifies.",
                    "found in systemActions: " + String.join(", ", inSystemActions), null));
        }
        return List.of();
    }

    /** Whether {@code node} or anything under it is a coverage-information extension. */
    private static boolean hasCoverageInfo(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return false;
        }
        if (node.isObject()) {
            if (COVERAGE_INFORMATION_URL.equals(node.path("url").asText(null))) {
                return true;
            }
            for (JsonNode child : node) {
                if (hasCoverageInfo(child)) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                if (hasCoverageInfo(child)) {
                    return true;
                }
            }
        }
        return false;
    }
}
