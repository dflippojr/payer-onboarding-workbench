package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.ORDER_SIGN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertOnly;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.resource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ResponseChecksTest {

    @Nested
    class IgVersion {
        private final IgVersionCheck check = new IgVersionCheck();

        @Test
        void matchingVersionPasses() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void minorDifferenceWarns() {
            var run = healthy();
            run.connection = Fixtures.connection("2.1.0", false);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertTrue(f.title().contains("payer 2.0.1, record 2.1.0"));
        }

        @Test
        void majorDifferenceFails() {
            var run = healthy();
            run.connection = Fixtures.connection("1.0.0", false);
            assertOnly(check.evaluate(run.build()), Severity.FAIL);
        }

        @ParameterizedTest(name = "record {0}, payer {1} -> {2}")
        @CsvSource({
                "2.0, 2.0.0, PASS",
                "2, 2.0.0, PASS",
                "v2.0, 2.0.0, PASS",
                "2.0.0, 2.0, PASS",
                "2.1.0, 2.1, PASS",
                "2.0, 2.0.1, WARN",
                "2.0.0-ballot, 2.0.0, WARN",
                "2.0.0-ballot, 2.0-ballot, PASS",
                "1.0.0, 2.0.0, FAIL",
                "2.10, 2.1, WARN"})
        void trailingZeroComponentsDoNotMakeVersionsDiffer(String record, String payer, Severity expected) {
            var run = healthy();
            run.connection = Fixtures.connection(record, false);
            run.discovery = discovery(200, "{\"services\":[],\"extension\":{\"igVersion\":\"" + payer + "\"}}");
            Finding f = assertOnly(check.evaluate(run.build()), expected);
            if (expected == Severity.PASS) {
                assertEquals("CRD IG version matches (" + payer + ")", f.title());
            } else {
                assertEquals("CRD IG version mismatch: payer " + payer + ", record " + record, f.title());
            }
        }

        @Test
        void readsVersionFromVersionedProfileInHookResponse() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\"}]}");
            run.hookBody("""
                    {"cards":[],"systemActions":[{"type":"update","resource":{"resourceType":"ServiceRequest",
                    "meta":{"profile":["http://hl7.org/fhir/us/davinci-crd/StructureDefinition/profile-servicerequest|2.2.0"]}}}]}""");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertTrue(f.evidence().contains("payer: 2.2.0 (from versioned profile"), f::evidence);
        }

        @Test
        void unreportedVersionIsInfo() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\"}]}");
            assertOnly(check.evaluate(run.build()), Severity.INFO);
        }

        @Test
        void recordWithoutVersionIsInfo() {
            var run = healthy();
            run.connection = Fixtures.connection(null, false);
            assertEquals("Connection record has no igVersion", assertOnly(check.evaluate(run.build()), Severity.INFO).title());
        }
    }

    @Nested
    class Schema {
        private final ResponseSchemaCheck check = new ResponseSchemaCheck();

        @Test
        void wellFormedCardsPass() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void invalidIndicatorAndMissingFieldsFail() {
            var run = healthy().hookBody("""
                    {"cards":[
                      {"summary":"PA required","indicator":"hard-stop","source":{"label":"Synthetic Health Plan"}},
                      {"indicator":"info","source":{}}
                    ]}""");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("cards[0].indicator is \"hard-stop\""), f::evidence);
            assertTrue(f.evidence().contains("cards[1].summary is missing"));
            assertTrue(f.evidence().contains("cards[1].source.label is missing"));
        }

        @Test
        void manyBadCardsNameTheFirstProblemsAndCountTheRest() {
            // 200k empty cards would be 600k problem lines; the evidence keeps a few (#162).
            var run = healthy().hookBody("{\"cards\":[" + "{},".repeat(199_999) + "{}]}");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().startsWith("cards[0].summary is missing\ncards[0].indicator is missing"), f::evidence);
            assertEquals(CappedLines.MAX, f.evidence().lines().filter(l -> l.startsWith("cards[")).count(), f::evidence);
            assertTrue(f.evidence().contains("\nand " + (600_000 - CappedLines.MAX) + " more\n"), f::evidence);
            assertTrue(f.evidence().length() < 2_000, () -> f.evidence().length() + " characters");
        }

        @Test
        void missingCardsArrayFails() {
            var run = healthy().hookBody("{\"systemActions\":[]}");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().contains("\"cards\" array"));
        }

        @Test
        void nullCardFails() {
            var run = healthy().hookBody("{\"cards\":[null]}");
            assertEquals("cards[0] is not a JSON object",
                    assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().lines().findFirst().orElseThrow());
        }

        @ParameterizedTest(name = "systemActions {0}")
        @CsvSource(delimiter = '|', value = {
                "[null]|systemActions[0] is not a JSON object",
                "[{\"type\":\"delete\",\"description\":\"d\",\"resourceId\":\"Task/1\"},7]|systemActions[1] is not a JSON object",
                "{}|\"systemActions\" is not an array"})
        void malformedSystemActionsFail(String actions, String problem) {
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":" + actions + "}");
            assertEquals(problem,
                    assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().lines().findFirst().orElseThrow());
        }

        @Test
        void nullSystemActionsIsAbsent() {
            // The CRD reference server writes every unset field as null.
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":null}");
            assertOnly(check.evaluate(run.build()), Severity.PASS);
        }

        @Test
        void systemActionWithoutDescriptionOrResourceFails() {
            // #263: a null resource is an absent one, so this action has neither a description nor a resource.
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":[{\"type\":\"update\",\"resource\":null}]}");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("systemActions[0].description is missing"), f::evidence);
            assertTrue(f.evidence().contains("systemActions[0].resource is missing (required for update)"), f::evidence);
            assertTrue(f.explanation().contains("CDS Hooks 2.0 Action"), f::explanation);
        }

        /** A card with one suggestion whose actions are {@code actions}. */
        private static String suggestionCard(String actions) {
            return "{\"summary\":\"a\",\"indicator\":\"info\",\"source\":{\"label\":\"P\"},\"selectionBehavior\":\"any\","
                    + "\"suggestions\":[{\"label\":\"Save\",\"actions\":" + actions + "}]}";
        }

        @ParameterizedTest(name = "{0} -> {1}")
        @CsvSource(delimiter = '|', value = {
                "{\"type\":\"modify\",\"description\":\"d\",\"resource\":{}}|.type is \"modify\" (must be create, update or delete)",
                "{\"type\":7,\"description\":\"d\",\"resource\":{}}|.type is missing",
                "{\"description\":\"d\",\"resource\":{}}|.type is missing",
                "{\"type\":\"create\",\"resource\":{}}|.description is missing",
                "{\"type\":\"create\",\"description\":\" \",\"resource\":{}}|.description is missing",
                "{\"type\":\"create\",\"description\":7,\"resource\":{}}|.description is missing",
                "{\"type\":\"create\",\"description\":\"d\"}|.resource is missing (required for create)",
                "{\"type\":\"update\",\"description\":\"d\",\"resource\":\"Task/1\"}|.resource is not a JSON object",
                "7|' is not a JSON object'"})
        void invalidActionsFailInSystemActionsAndSuggestions(String action, String problem) {
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":[" + action + "]}");
            assertEquals("systemActions[0]" + problem,
                    assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().lines().findFirst().orElseThrow());
            run.hookBody("{\"cards\":[" + suggestionCard("[" + action + "]") + "]}");
            assertEquals("cards[0].suggestions[0].actions[0]" + problem,
                    assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().lines().findFirst().orElseThrow());
        }

        @Test
        void validActionsPass() {
            String actions = "[{\"type\":\"create\",\"description\":\"c\",\"resource\":{\"resourceType\":\"Task\"}},"
                    + "{\"type\":\"update\",\"description\":\"u\",\"resource\":{\"resourceType\":\"Task\"},\"resourceId\":null},"
                    + "{\"type\":\"delete\",\"description\":\"d\",\"resourceId\":\"Task/1\",\"resource\":null}]";
            var run = healthy().hookBody("{\"cards\":[" + suggestionCard(actions) + "],\"systemActions\":" + actions + "}");
            assertOnly(check.evaluate(run.build()), Severity.PASS);
        }

        @ParameterizedTest(name = "{0} -> {1}")
        @CsvSource(delimiter = '|', value = {
                "{\"type\":\"delete\",\"description\":\"d\"}|systemActions[0].resourceId is missing (should be sent for delete)",
                "{\"type\":\"delete\",\"description\":\"d\",\"resourceId\":7}|systemActions[0].resourceId is missing (should be sent for delete)",
                "{\"type\":\"delete\",\"description\":\"d\",\"resourceId\":\"Task/1\",\"resource\":{}}|systemActions[0].resource is sent with delete (send resourceId instead)"})
        void deleteWithoutResourceIdWarns(String action, String problem) {
            // CDS Hooks 2.0 says SHOULD, and the HL7 tools model's cds-resp-2 is a warning.
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":[" + action + "]}");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertEquals(problem, f.evidence().lines().findFirst().orElseThrow());
            assertTrue(f.explanation().contains("actions"), f::explanation);
        }

        @Test
        void longSummaryWarns() {
            var run = healthy().hookBody("{\"cards\":[{\"summary\":\"" + "x".repeat(141)
                    + "\",\"indicator\":\"info\",\"source\":{\"label\":\"Synthetic Health Plan\"}}]}");
            assertOnly(check.evaluate(run.build()), Severity.WARN);
        }

        @Test
        void cardWithSuggestionsNeedsAValidSelectionBehavior() {
            var run = healthy().hookBody("""
                    {"cards":[
                      {"summary":"a","indicator":"info","source":{"label":"P"},"suggestions":[{"label":"Save"}]},
                      {"summary":"b","indicator":"info","source":{"label":"P"},"suggestions":[{"label":"Save"}],
                       "selectionBehavior":"all"},
                      {"summary":"c","indicator":"info","source":{"label":"P"},"suggestions":[{"label":"Save"}],
                       "selectionBehavior":"at-most-one"},
                      {"summary":"d","indicator":"info","source":{"label":"P"},"suggestions":[]}
                    ]}""");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("cards[0].selectionBehavior is missing"), f::evidence);
            assertTrue(f.evidence().contains("cards[1].selectionBehavior is \"all\""), f::evidence);
            assertFalse(f.evidence().contains("cards[2]"), f::evidence);
            assertFalse(f.evidence().contains("cards[3]"), f::evidence);
        }

        @Test
        void nullSelectionBehaviorIsAbsent() {
            // The CRD reference server writes every unset field as JSON null.
            var run = healthy().hookBody("""
                    {"cards":[{"summary":"a","indicator":"info","source":{"label":"P","icon":null},
                      "suggestions":null,"selectionBehavior":null,"links":null}],"systemActions":[]}""");
            assertOnly(check.evaluate(run.build()), Severity.PASS);
            run.hookBody("""
                    {"cards":[{"summary":"a","indicator":"info","source":{"label":"P"},
                      "suggestions":[{"label":"Save"}],"selectionBehavior":null}]}""");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("cards[0].selectionBehavior is missing"), f::evidence);
        }

        @ParameterizedTest(name = "suggestions {0}")
        @CsvSource(delimiter = '|', value = {
                "{\"a\":{}}|cards[0].suggestions is not an array",
                "\"Save\"|cards[0].suggestions is not an array",
                "[{\"label\":\"Save\",\"actions\":{\"a\":{}}}]|cards[0].suggestions[0].actions is not an array",
                "[{\"label\":\"Save\",\"actions\":\"update\"}]|cards[0].suggestions[0].actions is not an array"})
        void suggestionsAndActionsMustBeLists(String suggestions, String problem) {
            var run = healthy().hookBody("{\"cards\":[{\"summary\":\"a\",\"indicator\":\"info\","
                    + "\"source\":{\"label\":\"P\"},\"selectionBehavior\":\"any\",\"suggestions\":" + suggestions + "}]}");
            assertEquals(problem,
                    assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().lines().findFirst().orElseThrow());
        }

        @Test
        void nullActionsOnASuggestionIsAbsent() {
            var run = healthy().hookBody("{\"cards\":[{\"summary\":\"a\",\"indicator\":\"info\","
                    + "\"source\":{\"label\":\"P\"},\"selectionBehavior\":\"any\","
                    + "\"suggestions\":[{\"label\":\"Save\",\"actions\":null}]}]}");
            assertOnly(check.evaluate(run.build()), Severity.PASS);
        }

        @Test
        void errorStatusFails() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(500, "{\"error\":\"internal\"}", 300))));
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.FAIL).title().contains("HTTP 500"));
        }

        @Test
        void audienceRejectionIsLeftToJwtAudience() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(401,
                    "{\"error\":\"unauthorized\",\"error_description\":\"aud must be exactly "
                            + "'https://crd.elsewhere.test/cds-services/crd-order-sign'\"}", 300), ORDER_SIGN_URL)));
            assertEquals(List.of(), check.evaluate(run.build()));
        }

        @Test
        void otherJwtRejectionStillFails() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(401,
                    "{\"error\":\"unauthorized\",\"error_description\":\"JWT expired\"}", 300), ORDER_SIGN_URL)));
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }

    @Nested
    class CoverageLocation {
        private final CoverageLocationCheck check = new CoverageLocationCheck();

        @Test
        void coverageInSystemActionsPasses() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void coverageInSuggestionsIsInfo() {
            var run = healthy().hookBody(resource("order-sign-coverage-in-suggestions.json"));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.INFO);
            assertTrue(f.evidence().contains("cards[0].suggestions[0].actions[0]"), f::evidence);
            assertTrue(f.explanation().contains("systemActions"));
        }

        @Test
        void coverageOnAnElementInsideTheOrderFails() {
            String ci = "{\"url\":\"" + CoverageLocationCheck.COVERAGE_INFORMATION_URL + "\",\"extension\":[]}";
            var run = healthy().hookBody("{\"cards\":[],\"systemActions\":[{\"type\":\"update\",\"resource\":"
                    + "{\"resourceType\":\"DeviceRequest\",\"codeCodeableConcept\":{\"coding\":[{\"extension\":[" + ci
                    + "]}]}}},{\"type\":\"update\",\"resource\":{\"resourceType\":\"Coverage\",\"extension\":[" + ci
                    + "]}},{\"type\":\"update\",\"resource\":{\"resourceType\":\"ServiceRequest\",\"extension\":[" + ci
                    + ",{\"url\":\"http://example.org/wrapper\",\"extension\":[" + ci + "]}]}}]}");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("systemActions[0].resource.codeCodeableConcept.coding[0].extension[0]"),
                    f::evidence);
            assertTrue(f.evidence().contains("systemActions[1].resource.extension[0] (on a Coverage)"), f::evidence);
            assertTrue(f.evidence().contains("systemActions[2].resource.extension[1].extension[0]"), f::evidence);
            assertTrue(f.evidence().contains("found in systemActions: crd-order-sign: systemActions[2]"), f::evidence);
        }

        @Test
        void noCoverageInformationDoesNotApply() {
            var run = healthy().hookBody("{\"cards\":[]}");
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }
}
