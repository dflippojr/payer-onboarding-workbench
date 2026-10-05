package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.NOW;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.TOKEN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertionBody;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.jwt;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.resource;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.token;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class DiagnosticEngineTest {

    private static final Set<String> CATALOG = Set.of(
            "discovery.reachable", "discovery.services", "discovery.prefetch-keys",
            "auth.hook-rejected", "perf.rate-limit", "auth.token", "auth.client-assertion", "auth.jwt-audience", "auth.clock-skew",
            "ig.version", "response.schema", "response.coverage-location", "response.coverage-information",
            "perf.latency", "tls.handshake");

    private final DiagnosticEngine engine = new DiagnosticEngine();

    @Test
    void defaultCatalogHasStableIds() {
        assertEquals(CATALOG, engine.checks().stream().map(DiagnosticCheck::id).collect(Collectors.toSet()));
        assertEquals(CATALOG.size(), engine.checks().size());
    }

    @Test
    void healthyRunYieldsOnePassPerCheck() {
        List<Finding> findings = engine.run(healthy().build());

        assertEquals(CATALOG.stream().filter(id -> !Set.of("auth.client-assertion", "auth.hook-rejected", "perf.rate-limit").contains(id)).collect(Collectors.toSet()),
                findings.stream().map(Finding::checkId).collect(Collectors.toSet()));
        assertEquals(CATALOG.size() - 3, findings.size(), findings::toString);
        findings.forEach(f -> assertEquals(Severity.PASS, f.severity(), f::toString));
        findings.forEach(f -> assertFalse(f.explanation().isBlank(), f::toString));
    }

    @Test
    void multiFaultRunReportsEachFaultMostSevereFirst() {
        var run = healthy();
        // IG major version mismatch, non-standard prefetch key.
        run.connection = Fixtures.connection("1.0.0", false);
        run.discovery = discovery(200, resource("discovery-healthy.json")
                .replace("\"patient\": \"Patient/{{context.patientId}}\",", "\"pt\": \"Patient/{{context.patientId}}\","));
        // Token issued without expires_in, and the client_assertion aud has a trailing slash (payer lenient).
        run.token = token(200, assertionBody(jwt(TOKEN_URL + "/", NOW, NOW.plusSeconds(300))), Fixtures.TOKEN_OK_BODY, NOW);
        run.tokenResponse = new TokenResponseMetadata(true, "Bearer", null, List.of("system/*.read"), null, null);
        // order-sign is slow, has an invalid indicator and puts coverage in a suggestion;
        // appointment-book fails mutual TLS.
        String body = resource("order-sign-coverage-in-suggestions.json").replace("\"info\"", "\"urgent\"");
        run.hooks = new ArrayList<>(List.of(
                orderSign(hook(200, body, 7_000)),
                new HookResponse("crd-appointment-book", "appointment-book", null,
                        Fixtures.unreachable("POST", Fixtures.DISCOVERY_URL + "/crd-appointment-book",
                                "javax.net.ssl.SSLHandshakeException: Received fatal alert: bad_certificate"))));

        List<Finding> findings = engine.run(run.build());

        for (int i = 1; i < findings.size(); i++) {
            assertTrue(findings.get(i - 1).severity().compareTo(findings.get(i).severity()) >= 0,
                    () -> "not sorted by severity: " + findings);
        }
        Map<String, Severity> worst = findings.stream().collect(Collectors.toMap(
                Finding::checkId, Finding::severity, (a, b) -> a.compareTo(b) >= 0 ? a : b));
        assertEquals(Severity.FAIL, worst.get("ig.version"));
        assertEquals(Severity.FAIL, worst.get("response.schema"));
        assertEquals(Severity.FAIL, worst.get("tls.handshake"));
        assertEquals(Severity.WARN, worst.get("auth.token"));
        assertEquals(Severity.WARN, worst.get("perf.latency"));
        assertEquals(Severity.INFO, worst.get("discovery.prefetch-keys"));
        assertEquals(Severity.INFO, worst.get("response.coverage-location"));
        assertEquals(Severity.INFO, worst.get("auth.jwt-audience"));
        assertEquals(Severity.PASS, worst.get("discovery.reachable"));
        assertEquals(Severity.FAIL, findings.get(0).severity());
        findings.stream().filter(f -> f.severity() != Severity.PASS)
                .forEach(f -> assertTrue(f.suggestedFix() != null && !f.suggestedFix().isBlank(), f::toString));
    }

    @Test
    void failingCheckBecomesWarnAndOthersStillRun() {
        DiagnosticCheck broken = new DiagnosticCheck() {
            @Override
            public String id() {
                return "test.broken";
            }

            @Override
            public List<Finding> evaluate(RunObservations obs) {
                throw new IllegalStateException("boom");
            }
        };
        List<Finding> findings = new DiagnosticEngine(List.of(broken, new DiscoveryReachableCheck()))
                .run(healthy().build());

        assertEquals(2, findings.size());
        assertEquals("test.broken", findings.get(0).checkId());
        assertEquals(Severity.WARN, findings.get(0).severity());
        assertEquals(Severity.PASS, findings.get(1).severity());
    }

    @Test
    void configTunesRequiredHooksAndLatency() {
        var config = DiagnosticsConfig.defaults().withRequiredHooks(Set.of("order-dispatch"));
        List<Finding> findings = new DiagnosticEngine(config).run(healthy().build());
        assertTrue(findings.stream().anyMatch(f -> f.checkId().equals("discovery.services")
                && f.severity() == Severity.FAIL));

        var slow = healthy();
        slow.hooks = new ArrayList<>(List.of(orderSign(hook(200, resource("order-sign-healthy.json"), 3_000))));
        var strict = new DiagnosticsConfig(Set.of(), Duration.ofSeconds(2), Duration.ofSeconds(10),
                Duration.ofSeconds(60));
        assertTrue(new DiagnosticEngine(strict).run(slow.build()).stream()
                .anyMatch(f -> f.checkId().equals("perf.latency") && f.severity() == Severity.WARN));
    }
}
