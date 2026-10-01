package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.only;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
            only(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void unreachableFails() {
            var run = healthy();
            run.discovery = Fixtures.unreachable("GET", Fixtures.DISCOVERY_URL,
                    "java.net.ConnectException: Connection refused");
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Discovery endpoint unreachable", f.title());
            assertTrue(f.evidence().contains("Connection refused"));
        }

        @Test
        void non200FailsWithStatusSpecificFix() {
            var run = healthy();
            run.discovery = discovery(404, "{\"error\":\"not found\"}");
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.title().contains("404"));
            assertTrue(f.suggestedFix().contains("/cds-services"));
        }

        @Test
        void htmlBodyFailsAsNotJson() {
            var run = healthy();
            run.discovery = discovery(200, "<html><body>Sign in</body></html>");
            assertEquals("Discovery response is not JSON", only(check.evaluate(run.build()), Severity.FAIL).title());
        }

        @Test
        void jsonWithoutServicesFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"resourceType\":\"CapabilityStatement\"}");
            only(check.evaluate(run.build()), Severity.FAIL);
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
            Finding f = only(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(healthy().build()), Severity.PASS);
            assertTrue(f.title().contains("order-sign"));
        }

        @Test
        void noCrdHooksFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[{\"hook\":\"patient-view\",\"id\":\"pv\"}]}");
            Finding f = only(new DiscoveryServicesCheck(Set.of()).evaluate(run.build()), Severity.FAIL);
            assertEquals("No CRD hooks advertised", f.title());
        }

        @Test
        void emptyServicesFails() {
            var run = healthy();
            run.discovery = discovery(200, "{\"services\":[]}");
            only(new DiscoveryServicesCheck(Set.of("order-sign")).evaluate(run.build()), Severity.FAIL);
        }

        @Test
        void missingRequiredHookFails() {
            Finding f = only(new DiscoveryServicesCheck(Set.of("order-sign", "order-dispatch"))
                    .evaluate(healthy().build()), Severity.FAIL);
            assertTrue(f.title().contains("order-dispatch"));
            assertTrue(f.suggestedFix().contains("order-dispatch"));
        }
    }

    @Nested
    class PrefetchKeys {
        private final DiscoveryPrefetchKeysCheck check = new DiscoveryPrefetchKeysCheck();

        @Test
        void standardKeysPass() {
            only(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void nonStandardKeysAreMappedAsInfo() {
            var run = healthy();
            run.discovery = discovery(200, """
                    {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{
                      "patientToGet":"Patient/{{context.patientId}}",
                      "insurance":"Coverage?patient={{context.patientId}}",
                      "practitioner":"PractitionerRole/{{context.userId}}"}}]}""");
            Finding f = only(check.evaluate(run.build()), Severity.INFO);
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
