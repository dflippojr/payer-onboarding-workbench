package io.github.dflippojr.payerworkbench.samples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class SampleCatalogTest {
    private final SampleCatalog catalog = new SampleCatalog();

    @Test
    void listsAtLeastSixSamplesCoveringTheRequiredScenarios() {
        List<SampleMetadata> samples = catalog.list();
        assertTrue(samples.size() >= 6, "expected at least 6 samples, got " + samples.size());

        Map<String, Long> byHook = samples.stream()
                .collect(Collectors.groupingBy(SampleMetadata::hook, Collectors.counting()));
        assertTrue(byHook.getOrDefault("order-sign", 0L) >= 4, "order-sign samples: " + byHook);
        assertTrue(byHook.containsKey("order-select"), "order-select sample missing");
        assertTrue(byHook.containsKey("appointment-book"), "appointment-book sample missing");

        Set<String> codes = samples.stream().flatMap(s -> s.codes().stream()).collect(Collectors.toSet());
        assertTrue(codes.containsAll(Set.of("HCPCS E0250", "HCPCS E0424")), "codes: " + codes);
        assertTrue(samples.stream().anyMatch(s -> s.id().contains("missing-prefetch")));
    }

    @Test
    void everySampleHasTheRequiredCdsHooksFields() {
        for (SampleMetadata meta : catalog.list()) {
            for (PrefetchVariant variant : PrefetchVariant.values()) {
                JsonNode json = catalog.load(meta.id(), variant).toJson();
                String where = meta.id() + " (" + variant + ")";

                assertEquals(meta.hook(), json.path("hook").asText(), where + ": hook");
                String hookInstance = json.path("hookInstance").asText();
                assertEquals(hookInstance, UUID.fromString(hookInstance).toString(),
                        where + ": hookInstance must be a lower-case UUID");
                JsonNode context = json.path("context");
                assertTrue(context.isObject(), where + ": context must be an object");
                assertTrue(context.path("patientId").isTextual(), where + ": context.patientId");
                assertTrue(context.path("userId").isTextual(), where + ": context.userId");
                assertFalse(json.has("fhirAuthorization"), where + ": samples must not carry tokens");
            }
        }
    }

    @Test
    void hookInstancesAreUniqueAcrossSamples() {
        Set<String> seen = catalog.list().stream()
                .map(m -> catalog.load(m.id()).request().hookInstance())
                .collect(Collectors.toSet());
        assertEquals(catalog.list().size(), seen.size());
    }

    @Test
    void prefetchResourcesReferenceEachOtherConsistently() {
        for (SampleMetadata meta : catalog.list()) {
            for (PrefetchVariant variant : PrefetchVariant.values()) {
                assertConsistent(meta.id() + " (" + variant + ")", catalog.load(meta.id(), variant).toJson());
            }
        }
    }

    @Test
    void consistencyCheckCatchesAMismatchedReference() {
        ObjectNode json = (ObjectNode) catalog.load("order-sign-hospital-bed").toJson();
        ObjectNode coverage = (ObjectNode) json.at("/prefetch/coverage/entry/0/resource");
        coverage.putObject("beneficiary").put("reference", "Patient/someone-else");
        assertThrows(AssertionError.class, () -> assertConsistent("tampered", json));
    }

    @Test
    void everySampleRoundTripsThroughTheClientSdkTypes() throws Exception {
        for (SampleMetadata meta : catalog.list()) {
            JsonNode file = FhirResources.readClasspath(SampleCatalog.ROOT + meta.id() + "/request.json");

            CdsHookRequest request = SampleCatalog.parse(file);
            assertInstanceOf(CrdHookContext.class, request.context(), meta.id());
            assertEquals(meta.hook(), ((CrdHookContext) request.context()).hook(), meta.id());
            assertEquals(file, FhirResources.MAPPER.valueToTree(request), meta.id() + ": file -> SDK -> JSON");

            String wire = FhirResources.MAPPER.writeValueAsString(request);
            CdsHookRequest again = SampleCatalog.parse(FhirResources.MAPPER.readTree(wire));
            assertEquals(request, again, meta.id() + ": JSON -> SDK -> JSON -> SDK");
        }
    }

    @Test
    void committedRequestFilesMatchSampleFactory() {
        Map<String, CdsHookRequest> built = SampleFactory.all();
        assertEquals(catalog.list().stream().map(SampleMetadata::id).toList(), List.copyOf(built.keySet()),
                "index.json and SampleFactory.all() must list the same samples in the same order");
        built.forEach((id, request) -> assertEquals(
                FhirResources.MAPPER.valueToTree(request),
                FhirResources.readClasspath(SampleCatalog.ROOT + id + "/request.json"),
                id + ": request.json is stale; regenerate with SampleFactory.main"));
    }

    @Test
    void payerBVariantUsesFabrikamPrefetchKeys() {
        Sample sample = catalog.load("order-sign-hospital-bed", PrefetchVariant.PAYER_B);
        assertEquals(PrefetchVariant.PAYER_B, sample.variant());
        Map<String, Object> prefetch = sample.request().prefetch();
        assertEquals(Set.of("patient", "encounter", "coverageBundle", "deviceRequestBundle"), prefetch.keySet());

        JsonNode deviceRequests = (JsonNode) prefetch.get("deviceRequestBundle");
        assertEquals("searchset", deviceRequests.path("type").asText());
        Map<String, String> modes = new LinkedHashMap<>();
        deviceRequests.path("entry").forEach(e ->
                modes.put(FhirResources.reference(e.path("resource")), e.at("/search/mode").asText()));
        assertEquals(Map.of(
                "DeviceRequest/devreq-hospital-bed", "match",
                "Patient/pat-synthetic-001", "include",
                "Practitioner/pract-synthetic-001", "include",
                "Coverage/cov-synthetic-001", "include"), modes);

        Map<String, Object> standard = catalog.load("order-sign-hospital-bed").request().prefetch();
        assertEquals(standard.get("coverage"), prefetch.get("coverageBundle"));
        assertEquals(sample.request().context(), catalog.load("order-sign-hospital-bed").request().context());
    }

    @Test
    void payerBVariantLeavesMissingPrefetchMissingAndSkipsDeviceRequestsWhenThereAreNone() {
        assertNull(catalog.load("order-sign-missing-prefetch", PrefetchVariant.PAYER_B).request().prefetch());
        assertEquals(Set.of("patient", "coverageBundle"),
                catalog.load("appointment-book-dme-fitting", PrefetchVariant.PAYER_B).request().prefetch().keySet());
    }

    @Test
    void identitiesAreObviouslySynthetic() {
        for (SampleMetadata meta : catalog.list()) {
            JsonNode json = catalog.load(meta.id(), PrefetchVariant.PAYER_B).toJson();
            for (JsonNode identifier : json.findValues("identifier")) {
                for (JsonNode id : identifier) {
                    if ("http://hl7.org/fhir/sid/us-npi".equals(id.path("system").asText())) {
                        assertEquals("9999999999", id.path("value").asText(), meta.id() + ": placeholder NPI only");
                    }
                }
            }
            for (JsonNode name : json.findValues("family")) {
                assertEquals("Synthetic", name.asText(), meta.id() + ": synthetic family names only");
            }
        }
    }

    @Test
    void withNewHookInstanceChangesOnlyTheHookInstance() {
        Sample sample = catalog.load("order-sign-home-oxygen");
        Sample fresh = sample.withNewHookInstance();
        assertNotEquals(sample.request().hookInstance(), fresh.request().hookInstance());
        UUID.fromString(fresh.request().hookInstance());
        assertEquals(sample.request().context(), fresh.request().context());
        assertEquals(sample.request().prefetch(), fresh.request().prefetch());
    }

    @Test
    void unknownSampleIdIsRejected() {
        assertThrows(NoSuchElementException.class, () -> catalog.load("no-such-sample"));
    }

    /**
     * Every Patient, Encounter and Practitioner reference must match the context,
     * prefetch must hold the context's own patient and encounter, and when prefetch
     * is sent every reference must resolve inside the request.
     */
    private static void assertConsistent(String where, JsonNode request) {
        JsonNode context = request.path("context");
        String patient = "Patient/" + context.path("patientId").asText();
        String encounter = context.has("encounterId") ? "Encounter/" + context.path("encounterId").asText() : null;
        String user = context.path("userId").asText();

        Map<String, JsonNode> resources = new LinkedHashMap<>();
        collect(where, context.path("draftOrders"), resources);
        collect(where, context.path("appointments"), resources);
        JsonNode prefetch = request.path("prefetch");
        prefetch.forEach(value -> collect(where, value, resources));

        if (prefetch.has("patient")) {
            assertEquals(patient, FhirResources.reference(prefetch.get("patient")), where + ": prefetch.patient");
        }
        if (prefetch.has("encounter")) {
            assertEquals(encounter, FhirResources.reference(prefetch.get("encounter")), where + ": prefetch.encounter");
        }
        context.path("selections").forEach(s ->
                assertTrue(resources.containsKey(s.asText()), where + ": selection " + s.asText() + " not in draftOrders"));

        for (JsonNode resource : resources.values()) {
            String owner = where + ": " + FhirResources.reference(resource);
            for (JsonNode ref : resource.findValues("reference")) {
                String target = ref.asText();
                if (target.startsWith("Patient/")) {
                    assertEquals(patient, target, owner + " references another patient");
                } else if (target.startsWith("Encounter/")) {
                    assertEquals(encounter, target, owner + " references another encounter");
                } else if (target.startsWith("Practitioner/")) {
                    assertEquals(user, target, owner + " references another practitioner");
                }
                if (!prefetch.isMissingNode() && !target.equals(user)) {
                    assertTrue(resources.containsKey(target), owner + " references " + target + ", not in the request");
                }
            }
        }
    }

    private static void collect(String where, JsonNode node, Map<String, JsonNode> into) {
        if (node.isMissingNode()) {
            return;
        }
        List<JsonNode> found = new ArrayList<>();
        if ("Bundle".equals(node.path("resourceType").asText())) {
            for (JsonNode entry : node.path("entry")) {
                found.add(entry.path("resource"));
                if (entry.has("fullUrl")) {
                    assertTrue(entry.get("fullUrl").asText().endsWith("/" + FhirResources.reference(entry.path("resource"))),
                            where + ": fullUrl " + entry.get("fullUrl").asText());
                }
            }
        } else {
            found.add(node);
        }
        for (JsonNode resource : found) {
            assertTrue(resource.path("id").isTextual(), where + ": resource without id");
            JsonNode previous = into.putIfAbsent(FhirResources.reference(resource), resource);
            if (previous != null) {
                assertEquals(previous, resource, where + ": two different copies of " + FhirResources.reference(resource));
            }
        }
    }
}
