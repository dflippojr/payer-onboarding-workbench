package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;

import java.util.List;

/** Obviously fake FHIR content for driving the mock payers. */
final class SyntheticData {

    static final String PATIENT_ID = "synthetic-pat-001";
    static final String COVERAGE_ID = "synthetic-cov-001";
    static final String USER_ID = "Practitioner/synthetic-prac-001";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SyntheticData() { }

    static ObjectNode deviceRequest(String id, String hcpcsCode) {
        ObjectNode order = MAPPER.createObjectNode()
                .put("resourceType", "DeviceRequest")
                .put("id", id)
                .put("status", "draft")
                .put("intent", "order");
        order.putObject("codeCodeableConcept").putArray("coding").addObject()
                .put("system", "https://bluebutton.cms.gov/resources/codesystem/hcpcs")
                .put("code", hcpcsCode);
        order.putObject("subject").put("reference", "Patient/" + PATIENT_ID);
        order.putArray("insurance").addObject().put("reference", "Coverage/" + COVERAGE_ID);
        return order;
    }

    /** Hospital bed (E0250), stationary oxygen (E0424) and a code neither payer lists (E0601). */
    static List<ObjectNode> standardOrders() {
        return List.of(deviceRequest("synthetic-dr-1", "E0250"),
                deviceRequest("synthetic-dr-2", "E0424"),
                deviceRequest("synthetic-dr-3", "E0601"));
    }

    static ObjectNode bundle(String type, List<ObjectNode> resources) {
        ObjectNode bundle = MAPPER.createObjectNode().put("resourceType", "Bundle").put("type", type);
        ArrayNode entries = bundle.putArray("entry");
        resources.forEach(r -> entries.addObject().set("resource", r));
        return bundle;
    }

    static ObjectNode patient() {
        ObjectNode patient = MAPPER.createObjectNode().put("resourceType", "Patient").put("id", PATIENT_ID);
        patient.putArray("name").addObject().put("family", "Testpatient").putArray("given").add("Synthetic");
        return patient;
    }

    static ObjectNode coverage() {
        ObjectNode coverage = MAPPER.createObjectNode()
                .put("resourceType", "Coverage").put("id", COVERAGE_ID).put("status", "active");
        coverage.putObject("beneficiary").put("reference", "Patient/" + PATIENT_ID);
        coverage.putArray("payor").addObject().put("display", "Synthetic Plan (not a real payer)");
        return coverage;
    }

    static ObjectNode coverageBundle() {
        return bundle("searchset", List.of(coverage()));
    }

    static CrdHookContext.OrderSign orderSign(List<ObjectNode> orders) {
        return new CrdHookContext.OrderSign(USER_ID, PATIENT_ID, null, bundle("collection", orders));
    }

    static CrdHookContext.OrderSelect orderSelect(List<ObjectNode> orders) {
        List<String> selections = orders.stream().map(o -> "DeviceRequest/" + o.get("id").asText()).toList();
        return new CrdHookContext.OrderSelect(USER_ID, PATIENT_ID, null, selections, bundle("collection", orders));
    }
}
