package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.Redactor;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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

    /** Entries that are not objects named one by one in a title; more are only counted. */
    private static final int MAX_NAMED = 5;

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

    /**
     * The service a run calls for a hook, which is the first one listed for it, however many follow.
     * The runner and this check both go through here, so they cannot judge different services.
     */
    public static Optional<JsonNode> firstService(JsonNode services, String hook) {
        for (JsonNode service : services) {
            if (hook.equals(service.path("hook").asText(""))) {
                return Optional.of(service);
            }
        }
        return Optional.empty();
    }

    /** A service's id, or {@code null} when it is missing or is not a string. */
    public static String stringId(JsonNode service) {
        JsonNode id = service.path("id");
        return id.isTextual() ? id.textValue() : null;
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
        List<String> named = new ArrayList<>();
        int notObjects = 0;
        CappedLines notObjectLines = new CappedLines();
        for (int i = 0; i < services.size(); i++) {
            JsonNode service = services.get(i);
            if (!service.isObject()) {
                notObjects++;
                // One past the most a title names, so the title can tell when it must only count.
                if (named.size() <= MAX_NAMED) {
                    named.add("services[" + i + "]");
                }
                notObjectLines.add("services[" + i + "]: " + service.getNodeType().name().toLowerCase(Locale.ROOT));
                continue;
            }
            String hook = service.path("hook").asText("");
            advertised.add(hook);
            String id = stringId(service);
            lines.add((id == null ? "(no id)" : id) + " -> " + (hook.isEmpty() ? "(no hook)" : hook));
        }
        String evidence = "advertised services: " + (lines.isEmpty() ? "none" : lines.join(", "));
        if (notObjects > 0) {
            // First, so the advertised services, which can be long, never push the named entries past the
            // finding's evidence limit.
            return List.of(notObjects(named, notObjects, "not objects: " + notObjectLines.join(", ") + "; " + evidence));
        }

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
        // Only a run with no hook exchange may say the hook was not sent.
        String consequence = obs.hookResponses().isEmpty() ? "so the client cannot build the request URL and never "
                + "sent the hook." : "so the client cannot build the request URL.";
        for (String hook : new TreeSet<>(requiredHooks)) {
            // Every required hook is advertised by now, so a null id means its first service has none.
            String id = firstService(services, hook).map(DiscoveryServicesCheck::stringId).orElse(null);
            if (id == null) {
                return List.of(noId(hook, consequence, evidence));
            }
            // The body is redacted, and a JWT-shaped id loses its URL-safe last part to the mask. The run called
            // the original, so only the part the mask left is judged.
            if (!isUrlSafeServiceId(id.replace(Redactor.MASK, "x"))) {
                return List.of(unusableId(hook, id, consequence, evidence));
            }
        }
        return List.of(new Finding(CHECK_ID, Severity.PASS, "CRD hooks advertised: " + String.join(", ", crd),
                "Discovery lists CRD services" + (requiredHooks.isEmpty() ? "." : ", including every required hook."),
                evidence, null));
    }

    private static Finding notObjects(List<String> named, int count, String evidence) {
        String title = named.size() == 1 ? named.getFirst() + " is not a JSON object"
                : named.size() <= MAX_NAMED ? String.join(", ", named) + " are not JSON objects"
                : count + " entries in services are not JSON objects";
        return new Finding(CHECK_ID, Severity.FAIL, title,
                "CDS Hooks Discovery says services is an array of service objects, each with a hook, an id and "
                        + "optional prefetch templates. An entry that is null, a number, a string, a boolean or an "
                        + "array describes no service, and a CDS client may reject the whole discovery document "
                        + "over it, so the workbench does not call any of the listed services.",
                evidence,
                "Ask the payer to make every entry in services a JSON object describing one service, and to "
                        + "drop the entries named here.");
    }

    private static Finding noId(String hook, String consequence, String evidence) {
        return new Finding(CHECK_ID, Severity.FAIL, "The first " + hook + " service has no id",
                "CDS Hooks Discovery requires every service to have an id, a string, because a CDS service is "
                        + "called at /cds-services/{id}. The workbench calls the first service listed for a hook "
                        + "and does not move on to a later one. This one has no string id, " + consequence,
                evidence + "; service with no id: the first for " + hook,
                "Ask the payer to give their first " + hook + " service an id made only of letters, digits, '-', "
                        + "'_', '.' or '~', or to list the service they want called first.");
    }

    private static Finding unusableId(String hook, String id, String consequence, String evidence) {
        return new Finding(CHECK_ID, Severity.FAIL, "Service id for " + hook + " is not URL-safe: '" + id + "'",
                "A CDS service is called at /cds-services/{id}, so its id has to be usable as one URL path "
                        + "segment. This one has characters that are not allowed there, " + consequence,
                evidence + "; unusable id: '" + id + "'",
                "Ask the payer to advertise an id made only of letters, digits, '-', '_', '.' or '~' for "
                        + hook + ".");
    }
}
