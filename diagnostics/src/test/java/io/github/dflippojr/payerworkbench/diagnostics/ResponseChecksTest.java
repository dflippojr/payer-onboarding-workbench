package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.ORDER_SIGN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertOnly;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.resource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

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
        void missingCardsArrayFails() {
            var run = healthy().hookBody("{\"systemActions\":[]}");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.FAIL).evidence().contains("\"cards\" array"));
        }

        @Test
        void longSummaryWarns() {
            var run = healthy().hookBody("{\"cards\":[{\"summary\":\"" + "x".repeat(141)
                    + "\",\"indicator\":\"info\",\"source\":{\"label\":\"Synthetic Health Plan\"}}]}");
            assertOnly(check.evaluate(run.build()), Severity.WARN);
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
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.FAIL).title().contains("HTTP 401"));
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
        void noCoverageInformationDoesNotApply() {
            var run = healthy().hookBody("{\"cards\":[]}");
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }
}
