package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class CoverageInformationCheckTest {
    private final CoverageInformationCheck check = new CoverageInformationCheck();
    private final ObjectMapper mapper = new ObjectMapper();

    private ObjectNode resourceWith(String id, String assertionName, String covered) {
        ObjectNode resource = mapper.createObjectNode().put("resourceType", "DeviceRequest").put("id", id);
        ObjectNode ext = resource.putArray("extension").addObject()
                .put("url", CoverageLocationCheck.COVERAGE_INFORMATION_URL);
        var parts = ext.putArray("extension");
        parts.addObject().put("url", "coverage").putObject("valueReference").put("reference", "Coverage/synthetic");
        parts.addObject().put("url", "covered").put("valueCode", covered);
        parts.addObject().put("url", "date").put("valueDate", "2026-01-01");
        if (assertionName != null) {
            parts.addObject().put("url", assertionName).put("valueString", "synthetic-assertion");
        }
        return resource;
    }

    private ObjectNode response(ObjectNode systemResource, ObjectNode suggestionResource) {
        ObjectNode body = mapper.createObjectNode();
        if (systemResource != null) {
            body.putArray("systemActions").addObject().set("resource", systemResource);
        }
        if (suggestionResource != null) {
            body.putArray("cards").addObject().putArray("suggestions").addObject()
                    .putArray("actions").addObject().set("resource", suggestionResource);
        }
        return body;
    }

    @Test
    void conformantContentPassesInBothLocations() {
        var finding = assertOnly(check.evaluate(healthy().hookBody(response(
                resourceWith("system", "coverage-assertion-id", "covered"),
                resourceWith("suggestion", "coverage-assertion-id", "covered")).toString()).build()), Severity.PASS);
        assertEquals(check.id(), finding.checkId());
        assertTrue(finding.evidence().contains("DeviceRequest/system"));
        assertTrue(finding.evidence().contains("systemActions[0].resource.extension[0]"));
        assertTrue(finding.evidence().contains("cards[0].suggestions[0].actions[0].resource.extension[0]"));
        assertTrue(finding.evidence().contains("DeviceRequest/suggestion"));
    }

    @Test
    void legacyNameWarnsWithoutAnError() {
        var finding = assertOnly(check.evaluate(healthy().hookBody(response(null,
                resourceWith("legacy", "identifier", "covered")).toString()).build()), Severity.WARN);
        assertTrue(finding.evidence().contains("WARNING extension[identifier]"));
        assertTrue(finding.evidence().contains("pre-2.x name"));
        assertFalse(finding.evidence().contains("ERROR"));
    }

    @Test
    void everyExtensionIsCheckedAndErrorsOutrankWarningsAcrossHooks() {
        var first = response(resourceWith("legacy", "identifier", "covered"), null);
        var second = response(null, resourceWith("bad", null, "invalid-covered"));
        var badResource = (ObjectNode) second.at("/cards/0/suggestions/0/actions/0/resource");
        ((com.fasterxml.jackson.databind.node.ArrayNode) badResource.get("extension"))
                .add(resourceWith("extra", "identifier", "covered").path("extension").get(0));
        var run = healthy();
        run.hooks = List.of(orderSign(hook(200, first.toString(), 1)), orderSign(hook(200, second.toString(), 1)));
        var finding = assertOnly(check.evaluate(run.build()), Severity.FAIL);
        assertTrue(finding.evidence().contains("DeviceRequest/legacy"));
        assertTrue(finding.evidence().contains("DeviceRequest/bad"));
        assertTrue(finding.evidence().contains("extension[1]"));
        assertTrue(finding.evidence().contains("ERROR extension[coverage-assertion-id] - coverage-assertion-id is required"));
        assertTrue(finding.evidence().contains("ERROR extension[covered] - covered code 'invalid-covered'"));
        assertTrue(finding.evidence().contains("WARNING extension[identifier]"));
    }

    @Test
    void nestedResourcesRetainTheirOwnIdentity() {
        var bundle = mapper.createObjectNode().put("resourceType", "Bundle").put("id", "orders");
        bundle.putArray("entry").addObject().set("resource", resourceWith("nested", null, "covered"));
        var finding = assertOnly(check.evaluate(healthy().hookBody(response(bundle, null).toString()).build()), Severity.FAIL);
        assertTrue(finding.evidence().contains("DeviceRequest/nested"));
        assertTrue(finding.evidence().contains("entry[0].resource.extension[0]"));
    }

    @Test
    void absentInvalidOrUnsuccessfulResponsesProduceNoFinding() {
        assertTrue(check.evaluate(healthy().hookBody("{}").build()).isEmpty());
        assertTrue(check.evaluate(healthy().hookBody("not json").build()).isEmpty());
        var run = healthy();
        run.hooks = List.of(orderSign(hook(500, response(resourceWith("ignored", null, "bad"), null).toString(), 1)));
        assertTrue(check.evaluate(run.build()).isEmpty());
    }
}
