package io.github.dflippojr.payerworkbench.samples;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The shared synthetic FHIR R4 resources under {@code samples/fhir/}, and the
 * Bundle shapes the samples wrap them in. Every sample draws on this one pool,
 * which is what keeps IDs consistent across scenarios.
 */
final class FhirResources {
    static final ObjectMapper MAPPER = new ObjectMapper();

    /** Pretty printer with map keys (such as prefetch keys) sorted, so output is stable. */
    private static final ObjectWriter PRETTY = MAPPER.copy()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .writerWithDefaultPrettyPrinter();

    /** Base URL used for {@code fullUrl} in searchset Bundles. {@code example.org} is reserved for examples. */
    static final String FHIR_BASE = "https://ehr.example.org/fhir/";

    private static final List<String> FRAGMENTS = List.of(
            "patient", "practitioner", "coverage", "encounter",
            "devicerequest-hospital-bed", "devicerequest-home-oxygen", "devicerequest-cpap", "devicerequest-walker",
            "servicerequest-home-health-pt", "appointment-dme-fitting");

    private static final Map<String, JsonNode> POOL = loadPool();

    private FhirResources() { }

    /** A fresh copy of the fragment {@code samples/fhir/<name>.json}. */
    static ObjectNode load(String name) {
        return (ObjectNode) readClasspath("samples/fhir/" + name + ".json");
    }

    /** Looks up a fragment by its {@code Type/id} reference. */
    static Optional<JsonNode> resolve(String reference) {
        return Optional.ofNullable(POOL.get(reference)).map(JsonNode::deepCopy);
    }

    static String reference(JsonNode resource) {
        return resource.path("resourceType").asText() + "/" + resource.path("id").asText();
    }

    /** A {@code collection} Bundle, the shape CRD uses for {@code draftOrders} and {@code appointments}. */
    static ObjectNode collection(List<? extends JsonNode> resources) {
        ObjectNode bundle = bundle("collection");
        ArrayNode entries = bundle.putArray("entry");
        resources.forEach(r -> entries.addObject().set("resource", r));
        return bundle;
    }

    /** A {@code searchset} Bundle, the shape a prefetch query such as {@code Coverage?patient=...} returns. */
    static ObjectNode searchset(List<? extends JsonNode> matches, List<? extends JsonNode> includes) {
        ObjectNode bundle = bundle("searchset");
        bundle.put("total", matches.size());
        ArrayNode entries = bundle.putArray("entry");
        matches.forEach(r -> searchEntry(entries, r, "match"));
        includes.forEach(r -> searchEntry(entries, r, "include"));
        return bundle;
    }

    /** Pretty-printed JSON with LF line endings and stable map key order. */
    static String pretty(Object value) {
        try {
            return PRETTY.writeValueAsString(value).replace("\r\n", "\n");
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize " + value.getClass().getSimpleName(), e);
        }
    }

    static JsonNode readClasspath(String path) {
        try (InputStream in = FhirResources.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalArgumentException("No such resource on the classpath: " + path);
            }
            return MAPPER.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + path, e);
        }
    }

    private static ObjectNode bundle(String type) {
        ObjectNode bundle = MAPPER.createObjectNode();
        bundle.put("resourceType", "Bundle");
        bundle.put("type", type);
        return bundle;
    }

    private static void searchEntry(ArrayNode entries, JsonNode resource, String mode) {
        ObjectNode entry = entries.addObject();
        entry.put("fullUrl", FHIR_BASE + reference(resource));
        entry.set("resource", resource);
        entry.putObject("search").put("mode", mode);
    }

    private static Map<String, JsonNode> loadPool() {
        Map<String, JsonNode> pool = new LinkedHashMap<>();
        FRAGMENTS.forEach(name -> {
            ObjectNode resource = load(name);
            pool.put(reference(resource), resource);
        });
        return Map.copyOf(pool);
    }
}
