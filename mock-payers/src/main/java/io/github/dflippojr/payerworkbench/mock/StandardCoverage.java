package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;
import static io.github.dflippojr.payerworkbench.mock.MockPayer.*;

/** Shared synthetic CRD 2.2.1 determinations for Northwind and Tailspin. */
final class StandardCoverage {
    private StandardCoverage() { }
    private static final Map<String, CoverageDetermination> RULES = Map.of(
            "E0250", new CoverageDetermination("covered", "auth-needed", List.of(),
                    "Covered; prior authorization required"),
            "E0424", new CoverageDetermination("covered", "no-auth", List.of(),
                    "Covered; no prior authorization needed"));
    private static final CoverageDetermination OTHERWISE = new CoverageDetermination(
            "conditional", "no-auth", List.of("clinical"), "Coverage is conditional; clinical documentation needed");

    static ObjectNode response(MockPayer payer, MockPayer.ServiceDefinition service, ObjectNode hookRequest, String prefix) {
        String hookInstance = hookRequest.path("hookInstance").asText();
        JsonNode coverageBundle = hookRequest.path("prefetch").path("coverage");
        ObjectNode response = payer.mapper.createObjectNode();
        ArrayNode cards = response.putArray("cards");
        ArrayNode systemActions = response.putArray("systemActions");

        for (JsonNode order : draftOrders(hookRequest.path("context").path("draftOrders"))) {
            String code = orderCode(order);
            String label = orderLabel(order);
            CoverageDetermination determination = CoverageDetermination.lookup(RULES, code, OTHERWISE);
            String seed = hookInstance + "|" + label;
            if (service.hook().equals("order-select")) {
                cards.add(payer.card(seed, (code == null ? "Order" : code) + ": " + determination.summary(), "info",
                        "Preliminary guidance. " + payer.displayName() + " returns the coverage determination at order-sign.",
                        NorthwindPayer.CARD_TYPE_SYSTEM, "coverage-info", "Coverage Information"));
                continue;
            }
            String indicator = "auth-needed".equals(determination.paNeeded()) ? "warning" : "info";
            cards.add(payer.card(seed, (code == null ? "Order" : code) + ": " + determination.summary(), indicator,
                    "See the coverage information recorded on " + label + ".",
                    NorthwindPayer.CARD_TYPE_SYSTEM, "coverage-info", "Coverage Information"));
            ObjectNode action = systemActions.addObject();
            action.put("type", "update");
            action.put("description", "Record " + payer.displayName() + " coverage information on " + label);
            action.set("resource", payer.withCoverageInformation(order, determination, coverageReference(order, coverageBundle),
                    "coverage-assertion-id", prefix + "-" + label.replace('/', '-') + "-" + (code == null ? "NOCODE" : code)));
        }
        return response;
    }
}
