package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformationValidator;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;

/** Validates every coverage-information extension in action resources using the router's CRD 2.2.1 rules. */
public final class CoverageInformationCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "response.coverage-information";

    private record Result(String location, List<CoverageInformationValidator.Violation> violations) { }

    @Override
    public String id() {
        return CHECK_ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Result> results = new ArrayList<>();
        for (HookResponse hook : obs.hookResponses()) {
            if (!Support.isSuccess(hook.exchange().status())) {
                continue;
            }
            JsonNode json = Support.parseJson(hook.exchange().responseBody()).orElse(null);
            if (json == null) {
                continue;
            }
            collectResponse(json, hook.serviceId(), results);
        }
        if (results.isEmpty()) {
            return List.of();
        }
        return List.of(finding(results));
    }

    private static void collectResponse(JsonNode json, String serviceId, List<Result> results) {
        String prefix = serviceId + ": ";
        collectActions(json.path("systemActions"), prefix + "systemActions", results);
        JsonNode cards = json.path("cards");
        for (int c = 0; c < cards.size(); c++) {
            JsonNode suggestions = cards.get(c).path("suggestions");
            for (int s = 0; s < suggestions.size(); s++) {
                collectActions(suggestions.get(s).path("actions"),
                        prefix + "cards[" + c + "].suggestions[" + s + "].actions", results);
            }
        }
    }

    private static Finding finding(List<Result> results) {
        Severity severity = Severity.PASS;
        List<String> evidence = new ArrayList<>();
        for (Result result : results) {
            if (result.violations().isEmpty()) {
                evidence.add(result.location() + ": conformant");
            }
            for (var violation : result.violations()) {
                Severity mapped = violation.severity() == CoverageInformationValidator.Severity.ERROR
                        ? Severity.FAIL : Severity.WARN;
                if (mapped.compareTo(severity) > 0) {
                    severity = mapped;
                }
                evidence.add(result.location() + ": " + violation.severity() + " "
                        + violation.path() + " - " + violation.message());
            }
        }
        return new Finding(CHECK_ID, severity, "Coverage information content: " + severity,
                "The router validator checked each coverage-information extension against Da Vinci CRD 2.2.1. "
                        + "Errors fail the check; compatibility warnings, including the legacy identifier name, warn.",
                String.join("\n", evidence), severity == Severity.PASS ? null
                        : "Ask the payer to correct the listed extension fields to match the CRD 2.2.1 profile.");
    }

    private static void collectActions(JsonNode actions, String path, List<Result> results) {
        for (int i = 0; i < actions.size(); i++) {
            collect(actions.get(i).path("resource"), path + "[" + i + "].resource", "unknown resource", results);
        }
    }

    private static void collect(JsonNode node, String path, String resource, List<Result> results) {
        if (node.isObject()) {
            String owner = node.hasNonNull("resourceType")
                    ? node.path("resourceType").asText() + "/" + node.path("id").asText("(no id)") : resource;
            if (CoverageLocationCheck.COVERAGE_INFORMATION_URL.equals(node.path("url").asText())) {
                results.add(new Result(owner + " at " + path, CoverageInformationValidator.validate(node)));
            }
            node.fields().forEachRemaining(field ->
                    collect(field.getValue(), path + "." + field.getKey(), owner, results));
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collect(node.get(i), path + "[" + i + "]", resource, results);
            }
        }
    }
}
