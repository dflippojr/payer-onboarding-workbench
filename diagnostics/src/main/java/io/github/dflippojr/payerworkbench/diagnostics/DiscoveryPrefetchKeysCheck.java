package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code discovery.prefetch-keys}: reports prefetch keys other than the standard
 * CRD ones the router's client library builds ({@code patient}, {@code encounter},
 * {@code coverage}) and maps each to the standard key it most likely means. This
 * is informational: payers may name their keys freely.
 */
public final class DiscoveryPrefetchKeysCheck implements DiagnosticCheck {

    public static final String ID = "discovery.prefetch-keys";

    /** The keys {@code CrdPrefetch} in the router's client SDK provides. */
    public static final Set<String> STANDARD_KEYS = Set.of("patient", "encounter", "coverage");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        HttpExchange discovery = obs.discovery();
        if (discovery == null || discovery.status() != 200) {
            return List.of();
        }
        JsonNode services = Support.parseJson(discovery.responseBody())
                .map(json -> json.path("services"))
                .filter(JsonNode::isArray)
                .orElse(null);
        if (services == null || services.isEmpty()) {
            return List.of();
        }
        List<String> mapped = new ArrayList<>();
        List<String> unmapped = new ArrayList<>();
        int keyCount = 0;
        for (JsonNode service : services) {
            String serviceId = service.path("id").asText("(no id)");
            for (Map.Entry<String, JsonNode> e : service.path("prefetch").properties()) {
                keyCount++;
                if (STANDARD_KEYS.contains(e.getKey())) {
                    continue;
                }
                String template = e.getValue().asText("");
                String standard = standardKeyFor(template);
                String line = serviceId + ": \"" + e.getKey() + "\" = " + template;
                if (standard != null) {
                    mapped.add(line + "  =>  " + standard);
                } else {
                    unmapped.add(line);
                }
            }
        }
        if (mapped.isEmpty() && unmapped.isEmpty()) {
            return List.of(new Finding(ID, Severity.PASS,
                    keyCount == 0 ? "No prefetch templates requested" : "Prefetch keys are standard",
                    keyCount == 0
                            ? "The payer asks for no prefetch data (FHIR resources the client sends along with "
                                    + "the hook call), so nothing needs mapping."
                            : "Every prefetch key (the name for a FHIR resource the client sends along with the "
                                    + "hook call) is one of the standard CRD keys the library fills in.",
                    null, null));
        }
        StringBuilder evidence = new StringBuilder();
        if (!mapped.isEmpty()) {
            evidence.append("mapped to standard keys:\n  ").append(String.join("\n  ", mapped));
        }
        if (!unmapped.isEmpty()) {
            if (!evidence.isEmpty()) {
                evidence.append('\n');
            }
            evidence.append("no standard equivalent:\n  ").append(String.join("\n  ", unmapped));
        }
        String fix = "When building the request, put the resource under the payer's key name (CrdPrefetch.builder()"
                + ".put(\"<payer key>\", resource)) instead of, or as well as, the standard key"
                + (unmapped.isEmpty() ? "." : "; for keys with no standard equivalent, run the payer's FHIR query "
                        + "yourself and add the result under that key.");
        return List.of(new Finding(ID, Severity.INFO, "Payer uses non-standard prefetch keys",
                "Prefetch is data the client sends with a hook call so the payer need not query it back. "
                        + "This payer names some prefetch entries differently from the standard CRD keys "
                        + "(patient, encounter, coverage), so the standard keys alone will not satisfy it; the "
                        + "mapping below shows what each key most likely corresponds to.",
                evidence.toString(), fix));
    }

    /** The standard key whose resource type the FHIR query template asks for, or {@code null}. */
    static String standardKeyFor(String template) {
        String t = template.strip();
        if (t.startsWith("Patient/") || t.startsWith("Patient?")) {
            return "patient";
        }
        if (t.startsWith("Encounter/") || t.startsWith("Encounter?")) {
            return "encounter";
        }
        if (t.startsWith("Coverage?") || t.startsWith("Coverage/")) {
            return "coverage";
        }
        return null;
    }
}
