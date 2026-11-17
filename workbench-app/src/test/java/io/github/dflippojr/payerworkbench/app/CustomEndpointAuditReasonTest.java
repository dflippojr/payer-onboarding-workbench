package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The audited reason of a custom-endpoint run says what happened (#378): {@code invalid_custom_endpoint} only when
 * the endpoint was refused, and {@code request_failed} for a server error, the same as a synthetic run.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.custom-endpoints.enabled=true")
class CustomEndpointAuditReasonTest {

    private static final String SAMPLE = "order-sign-hospital-bed";
    /** Port 9 (discard) refuses the connection at once, so the run ends quickly with a FAIL verdict. */
    private static final String UNREACHABLE = "http://127.0.0.1:9/r4";
    static final List<AuditEvent> EVENTS = new CopyOnWriteArrayList<>();
    static final AtomicBoolean FAIL_SAVE = new AtomicBoolean();

    @TestConfiguration
    static class Doubles {
        @Bean
        @Primary
        AuditLog capturingAuditLog(MeterRegistry registry) {
            return new AuditLog(EVENTS::add, Clock.systemUTC(), registry);
        }

        /** A failure outside the run's steps: the run completes, then saving it throws, so the request is a 500. */
        @Bean
        @Primary
        RunStore failingRunStore(WorkbenchProperties properties) {
            return new RunStore(properties) {
                @Override
                public void save(OnboardingRun run) {
                    if (FAIL_SAVE.get()) { throw new IllegalStateException("synthetic run store failure"); }
                    super.save(run);
                }
            };
        }
    }

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void reset() {
        FAIL_SAVE.set(false);
    }

    @Test
    void customRunServerErrorIsAuditedAsRequestFailedLikeASyntheticRun() throws Exception {
        FAIL_SAVE.set(true);
        assertEquals(500, post(custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE"))).statusCode());
        AuditEvent customEnd = lastTerminal();
        assertEquals(500, post(Map.of("payerId", "northwind-synthetic", "sampleId", SAMPLE)).statusCode());
        AuditEvent syntheticEnd = lastTerminal();

        assertEquals(RunRequest.CUSTOM_PAYER_ID, customEnd.metadata().payerId());
        assertEquals("rejected", customEnd.outcome());
        assertEquals(500, customEnd.metadata().httpStatus());
        assertEquals("request_failed", customEnd.metadata().reasonCode(),
                "a server error on a custom run is not the caller's bad endpoint");
        assertEquals(syntheticEnd.metadata().reasonCode(), customEnd.metadata().reasonCode());
    }

    @Test
    void refusedCustomEndpointsAreAuditedAsInvalidCustomEndpoint() throws Exception {
        Map<String, Map<String, Object>> refused = new LinkedHashMap<>();
        refused.put("missing clientId", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                "credential", "synthetic-credential", "keyId", "synthetic-kid")));
        refused.put("missing credential", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                "clientId", "synthetic-client", "keyId", "synthetic-kid")));
        refused.put("missing keyId", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                "clientId", "synthetic-client", "credential", "synthetic-credential")));
        refused.put("credential with NONE", custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE",
                "credential", "synthetic-credential")));
        refused.put("unsupported authType", custom(Map.of("baseUrl", UNREACHABLE, "authType", "API_KEY",
                "clientId", "synthetic-client", "credential", "synthetic-credential")));
        Map<String, Object> faulted = new LinkedHashMap<>(custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE")));
        faulted.put("faults", List.of("discovery-500"));
        refused.put("faults on a custom run", faulted);

        for (Map.Entry<String, Map<String, Object>> entry : refused.entrySet()) {
            assertEquals(400, post(entry.getValue()).statusCode(), entry.getKey());
            AuditEvent end = lastTerminal();
            assertEquals("rejected", end.outcome(), entry.getKey());
            assertEquals("invalid_custom_endpoint", end.metadata().reasonCode(), entry.getKey());
        }
    }

    @Test
    void successfulCustomRunCarriesNoReason() throws Exception {
        assertEquals(200, post(custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE"))).statusCode());
        AuditEvent end = lastTerminal();
        assertEquals("success", end.outcome());
        assertEquals(null, end.metadata().reasonCode());
    }

    private static Map<String, Object> custom(Map<String, Object> endpoint) {
        return Map.of("sampleId", SAMPLE, "customEndpoint", endpoint);
    }

    private HttpResponse<String> post(Map<String, Object> body) throws Exception {
        int before = terminals().size();
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/runs"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))).build(),
                HttpResponse.BodyHandlers.ofString());
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (terminals().size() <= before) {
            if (System.nanoTime() > deadline) { fail("No run.completed event for " + body); }
            Thread.sleep(10);
        }
        return response;
    }

    /** This test's own run requests: the warm-up's self-request is the system actor. */
    private static List<AuditEvent> terminals() {
        return EVENTS.stream().filter(e -> e.action().equals("run.completed") && e.actorType().equals("anonymous")).toList();
    }

    private static AuditEvent lastTerminal() {
        return terminals().getLast();
    }
}
