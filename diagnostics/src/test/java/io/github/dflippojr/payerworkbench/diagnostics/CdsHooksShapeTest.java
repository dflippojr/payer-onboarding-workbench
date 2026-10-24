package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.payerworkbench.core.Finding;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A payer that sends a JSON object where CDS Hooks requires an array must not crash a check. A crash
 * is reported as "could not run", which blames the workbench for the payer's response (issue #216).
 */
class CdsHooksShapeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String CARD = "{\"summary\":\"s\",\"indicator\":\"info\",\"source\":{\"label\":\"x\"},"
            + "\"selectionBehavior\":\"any\"";

    static Stream<Arguments> objectInPlaceOfAnArray() {
        return Stream.of(
                Arguments.of("cards", "{\"cards\":{\"a\":{}}}"),
                Arguments.of("systemActions", "{\"cards\":[],\"systemActions\":{\"a\":{\"type\":\"update\"}}}"),
                Arguments.of("suggestions", "{\"cards\":[" + CARD + ",\"suggestions\":{\"a\":{}}}]}"),
                Arguments.of("actions", "{\"cards\":[" + CARD + ",\"suggestions\":[{\"label\":\"l\","
                        + "\"actions\":{\"a\":{}}}]}]}"));
    }

    @ParameterizedTest(name = "{0} sent as an object")
    @MethodSource("objectInPlaceOfAnArray")
    void objectInPlaceOfAnArrayDoesNotCrashAnyCheck(String field, String body) {
        assertNoInternalError(new DiagnosticEngine().run(healthy().hookBody(body).build()));
    }

    /**
     * Class-level check: every array in the baseline hook responses, at any depth, replaced in turn by an
     * object, a string, a number or a boolean. Any check that indexes a JSON node without testing that it
     * is an array fails here, whichever field the payer got wrong.
     */
    @TestFactory
    Stream<DynamicTest> arrayPositionsTolerateAnyOtherJsonType() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (String fixture : List.of("order-sign-healthy.json", "order-sign-coverage-in-suggestions.json")) {
            JsonNode baseline = MAPPER.readTree(resource(fixture));
            List<String> arrays = new ArrayList<>();
            collectArrayPointers(baseline, "", arrays);
            assertFalse(arrays.isEmpty(), fixture);
            for (String pointer : arrays) {
                for (String replacement : List.of("{\"a\":{}}", "\"x\"", "1", "true")) {
                    String name = fixture + " " + pointer + " as " + replacement;
                    tests.add(DynamicTest.dynamicTest(name, () -> {
                        JsonNode body = replaceAt(baseline, pointer, MAPPER.readTree(replacement));
                        assertNoInternalError(new DiagnosticEngine().run(healthy().hookBody(body.toString()).build()));
                    }));
                }
            }
        }
        return tests.stream();
    }

    private static void assertNoInternalError(List<Finding> findings) {
        assertTrue(findings.stream().noneMatch(f -> f.title().endsWith("could not run")), findings::toString);
    }

    private static void collectArrayPointers(JsonNode node, String pointer, List<String> out) {
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> collectArrayPointers(e.getValue(), pointer + "/" + e.getKey(), out));
        } else if (node.isArray()) {
            out.add(pointer);
            for (int i = 0; i < node.size(); i++) {
                collectArrayPointers(node.get(i), pointer + "/" + i, out);
            }
        }
    }

    private static JsonNode replaceAt(JsonNode root, String pointer, JsonNode value) {
        JsonNode copy = root.deepCopy();
        JsonPointer at = JsonPointer.compile(pointer);
        JsonNode parent = copy.at(at.head());
        if (parent.isObject()) {
            ((ObjectNode) parent).set(at.last().getMatchingProperty(), value);
        } else {
            ((ArrayNode) parent).set(at.last().getMatchingIndex(), value);
        }
        return copy;
    }
}
