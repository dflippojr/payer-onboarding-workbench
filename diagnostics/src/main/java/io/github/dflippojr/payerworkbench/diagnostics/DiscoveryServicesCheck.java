package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * {@code discovery.services}: discovery advertises at least one Da Vinci CRD hook,
 * including every hook the caller needs.
 */
public final class DiscoveryServicesCheck implements DiagnosticCheck {

    public static final String ID = "discovery.services";

    /** The hooks CRD defines services for. */
    public static final Set<String> CRD_HOOKS = Set.of(
            "appointment-book", "encounter-start", "encounter-discharge",
            "order-dispatch", "order-select", "order-sign");

    private final Set<String> requiredHooks;

    public DiscoveryServicesCheck(Set<String> requiredHooks) {
        this.requiredHooks = requiredHooks == null ? Set.of() : Set.copyOf(requiredHooks);
    }

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
        if (services == null) {
            return List.of();
        }
        Set<String> advertised = new TreeSet<>();
        List<String> lines = new ArrayList<>();
        for (JsonNode service : services) {
            String hook = service.path("hook").asText("");
            advertised.add(hook);
            lines.add(service.path("id").asText("(no id)") + " -> " + (hook.isEmpty() ? "(no hook)" : hook));
        }
        String evidence = "advertised services: " + (lines.isEmpty() ? "none" : String.join(", ", lines));

        Set<String> crd = new TreeSet<>(advertised);
        crd.retainAll(CRD_HOOKS);
        if (crd.isEmpty()) {
            return List.of(new Finding(ID, Severity.FAIL, "No CRD hooks advertised",
                    "The payer's discovery document lists no services for the hooks Coverage Requirements "
                            + "Discovery (CRD) uses, such as order-sign. CRD is the Da Vinci standard for asking "
                            + "a payer whether an order needs prior authorization or documentation, so there is "
                            + "nothing for the client to call.",
                    evidence,
                    "Ask the payer to enable CRD services for this client and environment; if they host CRD "
                            + "under a different base URL, update the connection record to that URL."));
        }
        Set<String> missing = new TreeSet<>(requiredHooks);
        missing.removeAll(advertised);
        if (!missing.isEmpty()) {
            return List.of(new Finding(ID, Severity.FAIL, "Required hooks not advertised: " + String.join(", ", missing),
                    "The payer offers CRD services, but not for every hook this integration needs. Calls for "
                            + "the missing hooks will have no service to go to.",
                    evidence + "; required: " + String.join(", ", new TreeSet<>(requiredHooks)),
                    "Ask the payer whether they support " + String.join(", ", missing)
                            + " in this environment, or drop it from the hooks this integration calls."));
        }
        return List.of(new Finding(ID, Severity.PASS, "CRD hooks advertised: " + String.join(", ", crd),
                "Discovery lists CRD services" + (requiredHooks.isEmpty() ? "." : ", including every required hook."),
                evidence, null));
    }
}
