package io.github.dflippojr.payerworkbench.samples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdPrefetch;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * The synthetic sample requests on the classpath under {@code samples/}.
 *
 * <p>Each sample is a directory holding {@code request.json} (the CDS Hooks
 * request as sent, with standard CRD prefetch keys) and {@code metadata.json}.
 * {@code samples/index.json} lists the ids in display order. Requests are
 * parsed into the {@code client-sdk} types, so a loaded sample can be handed
 * straight to {@code CdsHooksClient}.
 */
public final class SampleCatalog {
    static final String ROOT = "samples/";

    private final Map<String, SampleMetadata> metadata;

    public SampleCatalog() {
        Map<String, SampleMetadata> byId = new LinkedHashMap<>();
        for (JsonNode id : FhirResources.readClasspath(ROOT + "index.json")) {
            JsonNode json = FhirResources.readClasspath(ROOT + id.asText() + "/metadata.json");
            SampleMetadata meta = FhirResources.MAPPER.convertValue(json, SampleMetadata.class);
            if (!meta.id().equals(id.asText())) {
                throw new IllegalStateException("metadata.json for " + id.asText() + " has id " + meta.id());
            }
            byId.put(meta.id(), meta);
        }
        this.metadata = byId;
    }

    /** Metadata for every sample, in catalog order. */
    public List<SampleMetadata> list() {
        return List.copyOf(metadata.values());
    }

    /** Loads a sample with standard CRD prefetch keys. */
    public Sample load(String id) {
        return load(id, PrefetchVariant.STANDARD);
    }

    /**
     * Loads a sample with the given prefetch key style.
     *
     * @throws NoSuchElementException if there is no sample with this id
     */
    public Sample load(String id, PrefetchVariant variant) {
        SampleMetadata meta = metadata.get(id);
        if (meta == null) {
            throw new NoSuchElementException("No sample with id " + id + "; known: " + metadata.keySet());
        }
        CdsHookRequest request = parse(FhirResources.readClasspath(ROOT + id + "/request.json"));
        if (variant == PrefetchVariant.PAYER_B) {
            request = toPayerB(request);
        }
        return new Sample(meta, variant, request);
    }

    /**
     * Parses a CDS Hooks request into the {@code client-sdk} types, using a typed
     * {@link CrdHookContext} for the hooks it models (which also validates the
     * context) and a plain map for any other hook.
     */
    static CdsHookRequest parse(JsonNode json) {
        String hook = requiredText(json, "hook");
        String hookInstance = requiredText(json, "hookInstance");
        JsonNode ctx = json.path("context");
        if (!ctx.isObject()) {
            throw new IllegalArgumentException("context must be an object");
        }
        Object context = switch (hook) {
            case "order-sign" -> new CrdHookContext.OrderSign(text(ctx, "userId"), text(ctx, "patientId"),
                    text(ctx, "encounterId"), ctx.get("draftOrders"));
            case "order-select" -> new CrdHookContext.OrderSelect(text(ctx, "userId"), text(ctx, "patientId"),
                    text(ctx, "encounterId"), texts(ctx.path("selections")), ctx.get("draftOrders"));
            case "appointment-book" -> new CrdHookContext.AppointmentBook(text(ctx, "userId"),
                    text(ctx, "patientId"), text(ctx, "encounterId"), ctx.get("appointments"));
            default -> FhirResources.MAPPER.convertValue(ctx, Map.class);
        };
        CrdPrefetch.Builder prefetch = CrdPrefetch.builder();
        json.path("prefetch").fields().forEachRemaining(e -> prefetch.put(e.getKey(), e.getValue()));
        return new CdsHookRequest(hook, hookInstance, text(json, "fhirServer"), null, context, prefetch.build());
    }

    /** Re-keys a standard request's prefetch the way mock payer B expects; see {@link PrefetchVariant#PAYER_B}. */
    static CdsHookRequest toPayerB(CdsHookRequest request) {
        if (request.prefetch() == null) {
            return request;
        }
        CrdPrefetch.Builder prefetch = CrdPrefetch.builder();
        request.prefetch().forEach((key, value) ->
                prefetch.put(key.equals(CrdPrefetch.COVERAGE) ? "coverageBundle" : key, (JsonNode) value));

        List<JsonNode> deviceRequests = new ArrayList<>();
        if (request.context() instanceof CrdHookContext.OrderSign c) {
            collect(c.draftOrders(), "DeviceRequest", deviceRequests);
        } else if (request.context() instanceof CrdHookContext.OrderSelect c) {
            collect(c.draftOrders(), "DeviceRequest", deviceRequests);
        }
        if (!deviceRequests.isEmpty()) {
            prefetch.put("deviceRequestBundle", FhirResources.searchset(deviceRequests, includes(deviceRequests)));
        }
        return new CdsHookRequest(request.hook(), request.hookInstance(), request.fhirServer(),
                request.fhirAuthorization(), request.context(), prefetch.build());
    }

    /** The resources a DeviceRequest search with {@code _include} for patient, requester and insurance would add. */
    private static List<JsonNode> includes(List<JsonNode> deviceRequests) {
        Map<String, JsonNode> included = new LinkedHashMap<>();
        for (JsonNode dr : deviceRequests) {
            List<String> refs = new ArrayList<>();
            refs.add(dr.path("subject").path("reference").asText());
            refs.add(dr.path("requester").path("reference").asText());
            dr.path("insurance").forEach(i -> refs.add(i.path("reference").asText()));
            refs.forEach(ref -> FhirResources.resolve(ref).ifPresent(r -> included.putIfAbsent(ref, r)));
        }
        return List.copyOf(included.values());
    }

    private static void collect(JsonNode bundle, String resourceType, List<JsonNode> into) {
        for (JsonNode entry : bundle.path("entry")) {
            JsonNode resource = entry.path("resource");
            if (resourceType.equals(resource.path("resourceType").asText())) {
                into.add(((ObjectNode) resource).deepCopy());
            }
        }
    }

    private static String requiredText(JsonNode json, String field) {
        String value = text(json, field);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static String text(JsonNode json, String field) {
        JsonNode node = json.get(field);
        return node == null || node.isNull() ? null : node.asText();
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(n -> values.add(n.asText()));
        return values;
    }
}
