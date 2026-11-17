package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The rows of {@link RunRejectionPinTest} (#379, Stage 1) that need custom endpoints switched off, the default.
 * Where a custom request also names an unknown sample, today's audited reason is {@code unknown_sample} while the
 * detail is the custom-endpoints-disabled message.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RunRejectionCustomDisabledPinTest {

    private static final String SAMPLE = RunRejectionPinTest.SAMPLE;
    private static final String CUSTOM = RunRequest.CUSTOM_PAYER_ID;
    private static final String DISABLED = "Custom endpoints are disabled. Set "
            + "workbench.custom-endpoints.enabled=true to run against your own payer endpoint.";
    private static final Map<String, Object> ENDPOINT = Map.of("baseUrl", RunRejectionPinTest.UNREACHABLE,
            "authType", "NONE");
    static final List<AuditEvent> EVENTS = new CopyOnWriteArrayList<>();

    @TestConfiguration
    static class Doubles {
        @Bean
        @Primary
        AuditLog capturingAuditLog(MeterRegistry registry) {
            return new AuditLog(EVENTS::add, Clock.systemUTC(), registry);
        }
    }

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void customRunsWhileDisabledKeepTheirStatusDetailAndAuditedReason() throws Exception {
        assertAll(
                () -> assertRejected("disabled", Map.of("sampleId", SAMPLE, "customEndpoint", ENDPOINT),
                        DISABLED, "custom_disabled", SAMPLE),
                () -> assertRejected("disabled, with faults and a refused endpoint", Map.of("sampleId", SAMPLE,
                        "faults", List.of("discovery-500"), "customEndpoint", Map.of(
                                "baseUrl", "http://169.254.169.254/", "authType", "API_KEY")),
                        DISABLED, "custom_disabled", SAMPLE),
                () -> assertRejected("disabled and an unknown sample: the reason and the detail name different rules",
                        Map.of("sampleId", "nothing", "customEndpoint", ENDPOINT), DISABLED, "unknown_sample", null),
                () -> assertRejected("disabled and no sample", Map.of("customEndpoint", ENDPOINT),
                        "payerId and sampleId are required", "missing_input", null));
    }

    private void assertRejected(String name, Map<String, Object> body, String detail, String reason, String sampleId)
            throws Exception {
        int before = terminals().size();
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/runs"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))).build(),
                HttpResponse.BodyHandlers.ofString());
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (terminals().size() <= before) {
            if (System.nanoTime() > deadline) { fail("No run.completed event for " + name); }
            Thread.sleep(10);
        }
        AuditEvent end = terminals().get(before);
        assertAll(name,
                () -> assertEquals(400, response.statusCode(), response.body()),
                () -> assertEquals(Map.of("detail", detail, "instance", "/api/runs", "status", 400,
                        "title", "Bad Request"),
                        new TreeMap<>(mapper.convertValue(mapper.readTree(response.body()), Map.class))),
                () -> assertEquals("rejected", end.outcome()),
                () -> assertEquals(400, end.metadata().httpStatus()),
                () -> assertEquals(reason, end.metadata().reasonCode()),
                () -> assertEquals(CUSTOM, end.metadata().payerId()),
                () -> assertEquals(sampleId, end.metadata().sampleId()),
                () -> assertEquals(Environment.SANDBOX, end.metadata().environment()),
                () -> assertEquals(null, end.runId()));
    }

    /** This test's own run requests: the warm-up's self-request is the system actor. */
    private static List<AuditEvent> terminals() {
        return EVENTS.stream().filter(e -> e.action().equals("run.completed") && e.actorType().equals("anonymous"))
                .toList();
    }
}
