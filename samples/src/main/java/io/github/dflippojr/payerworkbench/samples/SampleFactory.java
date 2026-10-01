package io.github.dflippojr.payerworkbench.samples;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdPrefetch;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds every sample request with the fhir-crd-router {@code client-sdk} types
 * ({@link CdsHookRequest}, {@link CrdHookContext}, {@link CrdPrefetch}), so each
 * method doubles as a usage example for that library.
 *
 * <p>The committed {@code samples/<id>/request.json} files are this class's
 * output; a test fails if they drift. After changing a sample, regenerate them
 * with {@link #main(String[])}.
 */
public final class SampleFactory {
    /** Context IDs shared by every sample; they match the fragments under {@code samples/fhir/}. */
    public static final String PATIENT_ID = "pat-synthetic-001";
    public static final String USER_ID = "Practitioner/pract-synthetic-001";
    public static final String ENCOUNTER_ID = "enc-synthetic-001";

    private SampleFactory() { }

    /** Every sample request, keyed by sample id, in catalog order. */
    public static Map<String, CdsHookRequest> all() {
        Map<String, CdsHookRequest> all = new LinkedHashMap<>();
        all.put("order-sign-hospital-bed", orderSignHospitalBed());
        all.put("order-sign-home-oxygen", orderSignHomeOxygen());
        all.put("order-sign-conditional-cpap", orderSignConditionalCpap());
        all.put("order-sign-missing-prefetch", orderSignMissingPrefetch());
        all.put("order-select-walker", orderSelectWalker());
        all.put("appointment-book-dme-fitting", appointmentBookDmeFitting());
        return all;
    }

    /** {@code order-sign} for a hospital bed (HCPCS E0250), with full standard prefetch. */
    public static CdsHookRequest orderSignHospitalBed() {
        var context = new CrdHookContext.OrderSign(USER_ID, PATIENT_ID, ENCOUNTER_ID,
                draftOrders("devicerequest-hospital-bed"));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000001", standardPrefetch(true));
    }

    /** {@code order-sign} for home oxygen (HCPCS E0424). */
    public static CdsHookRequest orderSignHomeOxygen() {
        var context = new CrdHookContext.OrderSign(USER_ID, PATIENT_ID, ENCOUNTER_ID,
                draftOrders("devicerequest-home-oxygen"));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000002", standardPrefetch(true));
    }

    /** {@code order-sign} for a CPAP device (HCPCS E0601), a code the mock payers treat as conditional. */
    public static CdsHookRequest orderSignConditionalCpap() {
        var context = new CrdHookContext.OrderSign(USER_ID, PATIENT_ID, ENCOUNTER_ID,
                draftOrders("devicerequest-cpap"));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000003", standardPrefetch(true));
    }

    /**
     * {@code order-sign} for the hospital bed with no {@code prefetch} and no
     * {@code fhirServer}, so the payer has no way to see the patient or coverage.
     */
    public static CdsHookRequest orderSignMissingPrefetch() {
        var context = new CrdHookContext.OrderSign(USER_ID, PATIENT_ID, ENCOUNTER_ID,
                draftOrders("devicerequest-hospital-bed"));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000004", null);
    }

    /** {@code order-select}: a walker (HCPCS E0143) just selected, alongside a draft physical therapy referral. */
    public static CdsHookRequest orderSelectWalker() {
        var context = new CrdHookContext.OrderSelect(USER_ID, PATIENT_ID, ENCOUNTER_ID,
                List.of("DeviceRequest/devreq-walker"),
                draftOrders("devicerequest-walker", "servicerequest-home-health-pt"));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000005", standardPrefetch(true));
    }

    /** {@code appointment-book} for a DME fitting visit, booked outside an encounter. */
    public static CdsHookRequest appointmentBookDmeFitting() {
        var context = new CrdHookContext.AppointmentBook(USER_ID, PATIENT_ID, null,
                FhirResources.collection(List.of(FhirResources.load("appointment-dme-fitting"))));
        return request(context, "5a0c1f6e-4b1d-4e0a-9c11-000000000006", standardPrefetch(false));
    }

    /**
     * Writes each sample's {@code request.json} under the given directory
     * (default {@code samples/src/main/resources/samples}, relative to the repo root).
     */
    public static void main(String[] args) throws IOException {
        Path root = Path.of(args.length > 0 ? args[0] : "samples/src/main/resources/samples");
        for (var sample : all().entrySet()) {
            Path file = root.resolve(sample.getKey()).resolve("request.json");
            Files.createDirectories(file.getParent());
            Files.writeString(file, FhirResources.pretty(sample.getValue()) + "\n", StandardCharsets.UTF_8);
            System.out.println("wrote " + file);
        }
    }

    /**
     * {@link CdsHookRequest#of(CrdHookContext, Map)} would pick a random
     * {@code hookInstance}; samples pin one so the committed files are stable.
     */
    private static CdsHookRequest request(CrdHookContext context, String hookInstance, Map<String, Object> prefetch) {
        return new CdsHookRequest(context.hook(), hookInstance, null, null, context, prefetch);
    }

    /** The CRD prefetch keys a spec-conformant payer advertises: {@code patient}, {@code coverage}, {@code encounter}. */
    private static Map<String, Object> standardPrefetch(boolean withEncounter) {
        var prefetch = CrdPrefetch.builder()
                .patient(FhirResources.load("patient"))
                .coverage(FhirResources.searchset(List.of(FhirResources.load("coverage")), List.of()));
        if (withEncounter) {
            prefetch.encounter(FhirResources.load("encounter"));
        }
        return prefetch.build();
    }

    private static JsonNode draftOrders(String... fragments) {
        return FhirResources.collection(Arrays.stream(fragments).map(FhirResources::load).toList());
    }
}
