package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * {@code discovery.services}: discovery advertises at least one Da Vinci CRD hook,
 * including every hook the caller needs.
 */
public final class DiscoveryServicesCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "discovery.services";

    /** The hooks CRD defines services for. */
    public static final Set<String> CRD_HOOKS = Set.of(
            "appointment-book", "encounter-start", "encounter-discharge",
            "order-dispatch", "order-select", "order-sign");

    private static final Pattern URL_SAFE_ID = Pattern.compile("[A-Za-z0-9._~-]+");

    private final Set<String> requiredHooks;

    public DiscoveryServicesCheck(Set<String> requiredHooks) {
        this.requiredHooks = requiredHooks == null ? Set.of() : Set.copyOf(requiredHooks);
    }

    /**
     * Whether a service id can be the last segment of {@code /cds-services/{id}}: unreserved URL
     * characters only, so it needs no escaping and cannot change the request's path, query or host.
     */
    public static boolean isUrlSafeServiceId(String id) {
        return id != null && URL_SAFE_ID.matcher(id).matches() && !id.equals(".") && !id.equals("..");
    }

    @Override
    public String id() {
        return CHECK_ID;
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
        CappedLines lines = new CappedLines();
        for (JsonNode service : services) {
            String hook = service.path("hook").asText("");
            advertised.add(hook);
            lines.add(service.path("id").asText("(no id)") + " -> " + (hook.isEmpty() ? "(no hook)" : hook));
        }
        String evidence = "advertised services: " + (lines.isEmpty() ? "none" : lines.join(", "));

        Set<String> crd = new TreeSet<>(advertised);
        crd.retainAll(CRD_HOOKS);
        if (crd.isEmpty()) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "No CRD hooks advertised",
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
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Required hooks not advertised: " + String.join(", ", missing),
                    "The payer offers CRD services, but not for every hook this integration needs. Calls for "
                            + "the missing hooks will have no service to go to.",
                    evidence + "; required: " + String.join(", ", new TreeSet<>(requiredHooks)),
                    "Ask the payer whether they support " + String.join(", ", missing)
                            + " in this environment, or drop it from the hooks this integration calls."));
        }
        for (String hook : new TreeSet<>(requiredHooks)) {
            for (JsonNode service : services) {
                if (hook.equals(service.path("hook").asText(""))) {
                    // The client calls the first service for a hook, so that is the id that must be usable.
                    String id = service.path("id").asText("");
                    if (!isUrlSafeServiceId(id)) {
                        return List.of(unusableId(hook, id, evidence));
                    }
                    break;
                }
            }
        }
        return List.of(new Finding(CHECK_ID, Severity.PASS, "CRD hooks advertised: " + String.join(", ", crd),
                "Discovery lists CRD services" + (requiredHooks.isEmpty() ? "." : ", including every required hook."),
                evidence, null));
    }

    private static Finding unusableId(String hook, String id, String evidence) {
        return new Finding(CHECK_ID, Severity.FAIL, "Service id for " + hook + " is not URL-safe: '" + id + "'",
                "A CDS service is called at /cds-services/{id}, so its id has to be usable as one URL path "
                        + "segment. This one has characters that are not allowed there, so the client cannot "
                        + "build the request URL and never sent the hook.",
                evidence + "; unusable id: '" + id + "'",
                "Ask the payer to advertise an id made only of letters, digits, '-', '_', '.' or '~' for "
                        + hook + ".");
    }
}
