package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.List;
import java.util.Set;

/**
 * {@code response.coverage-location}: where the payer puts CRD coverage
 * information. CRD 2.x returns it as {@code systemActions} that update the order;
 * some payers put it in card suggestions instead. The router's library reads both,
 * so that is informational. Either way the extension must sit in the action
 * resource's own {@code extension} list, on a resource type the CRD 2.2.1
 * extension's context allows; anywhere else the library does not read it, so the
 * check fails.
 */
public final class CoverageLocationCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "response.coverage-location";

    /** The CRD coverage-information extension URL. */
    public static final String COVERAGE_INFORMATION_URL =
            "http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information";

    /** The resource types in the CRD 2.2.1 extension's {@code context}. */
    static final Set<String> CONTEXT = Set.of("Appointment", "CommunicationRequest", "Encounter", "DeviceRequest",
            "MedicationRequest", "NutritionOrder", "QuestionnaireResponse", "ServiceRequest", "VisionPrescription");

    @Override
    public String id() {
        return CHECK_ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        CappedLines inSystemActions = new CappedLines();
        CappedLines inSuggestions = new CappedLines();
        CappedLines misplaced = new CappedLines();
        for (HookResponse hook : obs.hookResponses()) {
            if (!Support.isSuccess(hook.exchange().status())) {
                continue;
            }
            JsonNode json = Support.parseJson(hook.exchange().responseBody()).orElse(null);
            if (json == null) {
                continue;
            }
            JsonNode actions = json.path("systemActions");
            for (int i = 0; actions.isArray() && i < actions.size(); i++) {
                String path = hook.serviceId() + ": systemActions[" + i + "]";
                if (classify(actions.get(i).path("resource"), path, misplaced)) {
                    inSystemActions.add(path);
                }
            }
            JsonNode cards = json.path("cards");
            for (int c = 0; cards.isArray() && c < cards.size(); c++) {
                JsonNode suggestions = cards.get(c).path("suggestions");
                for (int s = 0; suggestions.isArray() && s < suggestions.size(); s++) {
                    JsonNode suggestionActions = suggestions.get(s).path("actions");
                    for (int a = 0; suggestionActions.isArray() && a < suggestionActions.size(); a++) {
                        String path = hook.serviceId() + ": cards[" + c + "].suggestions[" + s + "].actions[" + a + "]";
                        if (classify(suggestionActions.get(a).path("resource"), path, misplaced)) {
                            inSuggestions.add(path);
                        }
                    }
                }
            }
        }
        if (!misplaced.isEmpty()) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Coverage information attached where CRD does not allow it",
                    "The payer sends a coverage determination (the CRD coverage-information extension), but not in "
                            + "the action resource's own extension list on an order, appointment or encounter as the "
                            + "CRD 2.2.1 extension's context requires. The router's library and EHRs read it only "
                            + "there, so this determination is lost.",
                    "misplaced: " + misplaced.join(", ")
                            + (inSystemActions.isEmpty() ? "" : "\nfound in systemActions: " + inSystemActions.join(", "))
                            + (inSuggestions.isEmpty() ? "" : "\nfound in suggestions: " + inSuggestions.join(", ")),
                    "Ask the payer to put the extension in the extension list of the order resource it returns, "
                            + "not on an element inside it or on another resource type."));
        }
        if (!inSuggestions.isEmpty()) {
            return List.of(new Finding(CHECK_ID, Severity.INFO, "Coverage information delivered in card suggestions",
                    "The payer returns its coverage determination (the CRD coverage-information extension saying "
                            + "whether prior authorization or documentation is needed) inside a card suggestion "
                            + "the clinician must accept, rather than as a systemAction the EHR applies "
                            + "automatically as CRD 2.x expects. The router's library reads both places, but EHRs "
                            + "and other clients that only read systemActions will miss it.",
                    "found in suggestions: " + inSuggestions.join(", ")
                            + (inSystemActions.isEmpty() ? "" : "\nfound in systemActions: " + inSystemActions.join(", ")),
                    "No change is needed for this library. If other clients will consume this payer, ask the payer "
                            + "to also send coverage information as an update systemAction on the order."));
        }
        if (!inSystemActions.isEmpty()) {
            return List.of(new Finding(CHECK_ID, Severity.PASS, "Coverage information delivered in systemActions",
                    "The payer returns coverage information as systemActions, the location CRD 2.x specifies.",
                    "found in systemActions: " + inSystemActions.join(", "), null));
        }
        return List.of();
    }

    /**
     * Whether {@code resource} carries coverage information where CRD allows it: in its own
     * {@code extension} list, on a resource type in the extension's context. Every other
     * coverage-information extension under it is added to {@code misplaced}.
     */
    private static boolean classify(JsonNode resource, String path, CappedLines misplaced) {
        boolean placed = false;
        boolean allowed = CONTEXT.contains(resource.path("resourceType").asText());
        String owner = path + ".resource";
        for (var fields = resource.fields(); fields.hasNext(); ) {
            var field = fields.next();
            JsonNode value = field.getValue();
            if (field.getKey().equals("extension") && value.isArray()) {
                for (int i = 0; i < value.size(); i++) {
                    String at = owner + ".extension[" + i + "]";
                    if (!isCoverageInfo(value.get(i))) {
                        collectMisplaced(value.get(i), at, misplaced);
                    } else if (allowed) {
                        placed = true;
                    } else {
                        misplaced.add(at + " (on a " + resource.path("resourceType").asText("resource without a type") + ")");
                    }
                }
            } else {
                collectMisplaced(value, owner + "." + field.getKey(), misplaced);
            }
        }
        return placed;
    }

    /** Adds every coverage-information extension at or under {@code node}. */
    private static void collectMisplaced(JsonNode node, String path, CappedLines misplaced) {
        if (isCoverageInfo(node)) {
            misplaced.add(path);
        } else if (node.isObject()) {
            node.fields().forEachRemaining(f -> collectMisplaced(f.getValue(), path + "." + f.getKey(), misplaced));
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectMisplaced(node.get(i), path + "[" + i + "]", misplaced);
            }
        }
    }

    private static boolean isCoverageInfo(JsonNode node) {
        return node.isObject() && COVERAGE_INFORMATION_URL.equals(node.path("url").asText(null));
    }
}
