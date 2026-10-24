package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertOnly;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DiscoveryChecksTest {

    @Nested
    class Reachable {
        private final DiscoveryReachableCheck check = new DiscoveryReachableCheck();

        @Test
        void healthyDiscoveryPasses() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void unreachableFails() {
            var run = healthy();
            run.discovery = Fixtures.unreachable("GET", Fixtures.DISCOVERY_URL,
                    "java.net.ConnectException: Connection refused");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Discovery endpoint unreachable", f.title());
            assertTrue(f.evidence().contains("Connection refused"));
        }

        @Test
        void non200FailsWithStatusSpecificFix() {
            var run = healthy();
            run.discovery = discovery(404, "{\"error\":\"not found\"}");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.title().contains("404"));
            assertTrue(f.suggestedFix().contains("/cds-services"));
        }

        @Test
        void htmlBodyFailsAsNotJson() {
            var run = healthy();
            run.discovery = discovery(200, "<html><body>Sign in</body></html>");
            assertEquals("Discovery response is not JSON", assertOnly(check.evaluate(run.build()), Severity.FAIL).title());
        }

        @Test
        void jsonWithoutServicesFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"resourceType\":\"CapabilityStatement\"}");
            assertOnly(check.evaluate(run.build()), Severity.FAIL);
        }

        @Test
        void doesNotApplyWithoutDiscovery() {
            var run = healthy();
            run.discovery = null;
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }

    @Nested
    class Services {
        @Test
        void advertisedRequiredHookPasses() {
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(healthy().build()), Severity.PASS);
            assertTrue(f.title().contains("order-sign"));
            assertEquals("Discovery lists CRD services, including every required hook.", f.explanation());
        }

        @Test
        void noCrdHooksFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"patient-view\",\"id\":\"pv\"}]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of()).evaluate(run.build()), Severity.FAIL);
            assertEquals("No CRD hooks advertised", f.title());
        }

        @Test
        void emptyServicesFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[]}");
            assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.FAIL);
        }

        @Test
        void missingRequiredHookFails() {
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of("order-sign", "order-dispatch"))
                    .evaluate(healthy().build()), Severity.FAIL);
            assertTrue(f.title().contains("order-dispatch"));
            assertTrue(f.suggestedFix().contains("order-dispatch"));
        }

        @org.junit.jupiter.params.ParameterizedTest
        @org.junit.jupiter.params.provider.ValueSource(strings = {"order sign", "a/b", "..", "a?b", "a#b", "a%20b", ""})
        void serviceIdThatCannotBeAUrlSegmentFails(String id) {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"" + id + "\",\"prefetch\":{}}]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.FAIL);
            assertTrue(f.title().contains("not URL-safe"), f.title());
            assertTrue(f.evidence().contains("unusable id: '" + id + "'"), f.evidence());
        }

        @Test
        void manyServicesListTheFirstAndCountTheRest() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\"},"
                    + "{},".repeat(99_999) + "{}]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.PASS);
            assertTrue(f.evidence().startsWith("advertised services: crd-order-sign -> order-sign, (no id) -> (no hook)"),
                    f::evidence);
            assertTrue(f.evidence().endsWith(", and " + (100_001 - CappedLines.MAX) + " more"), f::evidence);
        }

        /** #214: CDS Hooks 2.0 Discovery says services is an array of service objects. */
        @Test
        void aNullEntryFailsAndIsNamedEvenBesideAUsableService() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[null,{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\","
                    + "\"prefetch\":{}}]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.FAIL);
            assertEquals("services[0] is not a JSON object", f.title());
            assertTrue(f.evidence().contains("services[0]: null"), f::evidence);
            assertTrue(f.evidence().startsWith("advertised services: crd-order-sign -> order-sign"), f::evidence);
        }

        @Test
        void everyEntryThatIsNotAnObjectIsNamedWithItsType() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[1,\"x\",{},[],true]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of()).evaluate(run.build()), Severity.FAIL);
            assertEquals("services[0], services[1], services[3], services[4] are not JSON objects", f.title());
            assertTrue(f.evidence().contains("services[0]: number, services[1]: string, services[3]: array, "
                    + "services[4]: boolean"), f::evidence);
            assertFalse(f.evidence().contains("services[2]"), f::evidence);
            assertTrue(f.suggestedFix().contains("JSON object"), f::suggestedFix);
        }

        @org.junit.jupiter.params.ParameterizedTest
        @org.junit.jupiter.params.provider.CsvSource(delimiter = '|', value = {
                "5 | services[0], services[1], services[2], services[3], services[4] are not JSON objects",
                "6 | 6 entries in services are not JSON objects"})
        void aTitleNamesUpToFiveEntriesThatAreNotObjects(int count, String title) {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[" + String.join(",", java.util.Collections.nCopies(count, "0"))
                    + "]}");
            assertEquals(title, assertOnly(new DiscoveryServicesCheck(Set.of()).evaluate(run.build()), Severity.FAIL).title());
        }

        @Test
        void manyEntriesThatAreNotObjectsNameTheFirstAndCountTheRest() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[" + "null,".repeat(99) + "null]}");
            Finding f = assertOnly(new DiscoveryServicesCheck(Set.of()).evaluate(run.build()), Severity.FAIL);
            assertEquals("100 entries in services are not JSON objects", f.title());
            assertTrue(f.evidence().endsWith(", and " + (100 - CappedLines.MAX) + " more"), f::evidence);
        }

        @Test
        void onlyTheServiceTheClientWouldCallNeedsAUsableId() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"ok-1\"},"
                    + "{\"hook\":\"order-sign\",\"id\":\"bad id\"},{\"hook\":\"patient-view\",\"id\":\"x y\"}]}");
            assertOnly(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.PASS);
        }
    }

    @Nested
    class PrefetchKeys {
        private final DiscoveryPrefetchKeysCheck check = new DiscoveryPrefetchKeysCheck();

        @Test
        void standardKeysPass() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void nonStandardKeysAreMappedAsInfo() {
            var run = healthy();
            run.discovery = discovery(200, """
                    {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{
                      "patientToGet":"Patient/{{context.patientId}}",
                      "insurance":"Coverage?patient={{context.patientId}}",
                      "practitioner":"PractitionerRole/{{context.userId}}"}}]}""");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.INFO);
            assertTrue(f.evidence().contains("\"patientToGet\" = Patient/{{context.patientId}}  =>  patient"));
            assertTrue(f.evidence().contains("\"insurance\" = Coverage?patient={{context.patientId}}  =>  coverage"));
            assertTrue(f.evidence().contains("no standard equivalent"));
            assertTrue(f.evidence().contains("practitioner"));
        }

        @Test
        void mapsTemplatesByResourceType() {
            assertEquals("encounter", DiscoveryPrefetchKeysCheck.standardKeyFor("Encounter/{{context.encounterId}}"));
            assertEquals(null, DiscoveryPrefetchKeysCheck.standardKeyFor("Practitioner/{{context.userId}}"));
        }
    }
}
