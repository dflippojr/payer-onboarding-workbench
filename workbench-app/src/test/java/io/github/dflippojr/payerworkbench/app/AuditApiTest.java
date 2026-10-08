package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.custom-endpoints.enabled=true")
class AuditApiTest {
    @Value("${local.server.port}") int port;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private static final String SAMPLE = "order-sign-hospital-bed";
    private static final String SECRET = "SYNTHETIC_PATIENT_FINANCIAL_SECRET";

    @Test
    void healthyFaultedAndReportAccessHaveSafeCorrelatedEvents(CapturedOutput output) throws Exception {
        String healthy = run("[]");
        String faulted = run("[\"discovery-500\"]");
        assertEquals(200, get("/api/runs").statusCode());
        assertEquals(200, get("/api/runs/" + healthy).statusCode());
        for (String format : List.of("md", "html", "json", "%20HTML%20")) {
            assertEquals(200, get("/api/runs/" + healthy + "/report?format=" + format).statusCode());
        }
        assertEquals(400, get("/api/runs/" + healthy + "/report?format=" + SECRET).statusCode());
        assertEquals(404, get("/api/runs/" + SECRET).statusCode());
        assertEquals(404, get("/api/runs/" + SECRET + "/report?format=md").statusCode());
        get("/api/payers"); get("/api/samples"); get("/api/features"); get("/actuator/health"); get("/");
        List<JsonNode> events = events(output, 11);
        assertEquals(11, terminals(events).size());
        assertEquals(2, action(events, "run.requested").size());
        for (JsonNode terminal : action(events, "run.completed")) {
            JsonNode start = action(events, "run.requested").stream()
                    .filter(e -> e.path("requestId").equals(terminal.path("requestId"))).findFirst().orElseThrow();
            assertTrue(start.path("runId").isNull());
            UUID.fromString(terminal.path("requestId").asText());
            assertEquals(200, terminal.path("metadata").path("httpStatus").asInt());
            assertEquals("success", terminal.path("outcome").asText());
            assertEquals(terminal.path("runId").asText().equals(faulted) ? "FAIL" : "PASS",
                    terminal.path("metadata").path("verdict").asText());
        }
        assertTrue(action(events, "credential.resolved").stream().anyMatch(e ->
                e.path("runId").asText().equals(healthy) && e.path("metadata").path("available").asBoolean()));
        assertTrue(events.stream().filter(e -> e.path("metadata").path("httpStatus").asInt() == 404)
                .allMatch(e -> e.path("targetId").isNull()));
        assertSafe(events);
    }

    @Test
    void invalidInputsHaveOneStartAndTerminalWithFixedReasons(CapturedOutput output) throws Exception {
        List<String> bodies = List.of("{", "{}", "{\"payerId\":\"" + SECRET + "\",\"sampleId\":\"" + SAMPLE + "\"}",
                "{\"payerId\":\"northwind-synthetic\",\"sampleId\":\"" + SECRET + "\"}",
                "{\"payerId\":\"northwind-synthetic\",\"sampleId\":\"" + SAMPLE + "\",\"faults\":[\"" + SECRET + "\"]}",
                "{\"sampleId\":\"" + SAMPLE + "\",\"customEndpoint\":{\"baseUrl\":\"http://169.254.169.254/\"}}",
                "{\"payerId\":\"northwind-synthetic\",\"sampleId\":\"" + SAMPLE + "\",\"environment\":\"" + SECRET + "\"}");
        for (String body : bodies) { assertEquals(400, post(body).statusCode()); }
        List<JsonNode> events = events(output, bodies.size());
        List<JsonNode> starts = action(events, "run.requested");
        List<JsonNode> ends = action(events, "run.completed");
        assertEquals(bodies.size(), starts.size()); assertEquals(bodies.size(), ends.size());
        assertEquals(List.of("invalid_body", "missing_input", "unknown_payer", "unknown_sample", "unknown_fault",
                "destination_rejected", "invalid_body"), ends.stream().map(e -> e.path("metadata").path("reasonCode").asText()).toList());
        for (JsonNode end : ends) {
            assertEquals(1, starts.stream().filter(e -> e.path("requestId").equals(end.path("requestId"))).count());
            assertTrue(end.path("runId").isNull()); assertEquals("rejected", end.path("outcome").asText());
        }
        assertSafe(events);
    }

    @Test
    void customLoopbackAndOverridesDoNotLeakValues(CapturedOutput output) throws Exception {
        try (NorthwindPayer payer = NorthwindPayer.builder().client(SECRET, SECRET).build()) {
            payer.start(0);
            String body = mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", Map.of(
                    "baseUrl", payer.baseUrl(), "authType", "OAUTH2_CLIENT_CREDENTIALS", "clientId", SECRET,
                    "tokenEndpoint", payer.tokenEndpoint(), "credential", SECRET)));
            HttpResponse<String> response = post(body);
            assertEquals(200, response.statusCode());
            String run = mapper.readTree(response.body()).path("runId").asText();
            post(mapper.writeValueAsString(Map.of("payerId", "northwind-synthetic", "sampleId", SAMPLE,
                    "connection", Map.of("clientId", SECRET, "igVersion", "Patient/" + SECRET,
                            "baseUrlSuffix", "/?patient=" + SECRET + "\naudit forged"))));
            List<JsonNode> events = events(output, 2);
            List<JsonNode> credentials = action(events, "credential.resolved").stream()
                    .filter(e -> e.path("runId").asText().equals(run)).toList();
            assertFalse(credentials.isEmpty());
            assertTrue(credentials.stream().allMatch(e -> e.path("targetId").asText().equals("custom-" + run)));
            assertEquals(List.of("baseUrl", "igVersion", "clientId"), mapper.convertValue(
                    action(events, "run.completed").getLast().path("metadata").path("overrides"), List.class));
            assertSafe(events);
            assertFalse(events.toString().contains(payer.baseUrl()));
        }
    }

    @Test
    void plantedPayloadsAndLineForgingNeverBecomeAuditMetadata(CapturedOutput output) throws Exception {
        String planted = SECRET + "\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PEM\n-----END PRIVATE KEY-----"
                + " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.synthetic_signature"
                + " https://synthetic-user:synthetic-password@example.invalid/path?token=synthetic-token"
                + " {\"resourceType\":\"Patient\",\"id\":\"synthetic-patient-id\",\"name\":\"Synthetic Person\"}"
                + " synthetic-account-number=123456789\naudit {\"actorId\":\"forged\"}";
        assertEquals(400, post(mapper.writeValueAsString(Map.of("payerId", planted, "sampleId", planted))).statusCode());
        assertEquals(400, post(mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", Map.of(
                "baseUrl", planted, "authType", "OAUTH2_CLIENT_CREDENTIALS", "clientId", planted,
                "tokenEndpoint", planted, "keyId", planted, "credential", planted)))).statusCode());
        List<JsonNode> events = events(output, 2);
        assertEquals(4, events.size());
        assertSafe(events);
        for (String forbidden : List.of("PRIVATE KEY", "SYNTHETIC_PEM", "eyJ", "example.invalid",
                "synthetic-patient-id", "Synthetic Person", "synthetic-account-number", "forged")) {
            assertFalse(events.toString().contains(forbidden), forbidden);
        }
    }

    @Test
    void concurrentRunsKeepRequestAndRunIdsSeparate(CapturedOutput output) throws Exception {
        var first = CompletableFuture.supplyAsync(() -> uncheckedRun("[]"));
        var second = CompletableFuture.supplyAsync(() -> uncheckedRun("[\"discovery-500\"]"));
        String a = first.get(); String b = second.get(); assertNotEquals(a, b);
        List<JsonNode> events = events(output, 2);
        List<JsonNode> ends = action(events, "run.completed");
        assertNotEquals(ends.getFirst().path("requestId"), ends.getLast().path("requestId"));
        for (JsonNode credential : action(events, "credential.resolved")) {
            assertTrue(ends.stream().anyMatch(e -> e.path("runId").equals(credential.path("runId"))
                    && e.path("requestId").equals(credential.path("requestId"))));
        }
    }

    private String uncheckedRun(String faults) {
        try { return run(faults); } catch (Exception e) { throw new IllegalStateException(e); }
    }
    private String run(String faults) throws Exception {
        var response = post("{\"payerId\":\"northwind-synthetic\",\"sampleId\":\"" + SAMPLE + "\",\"faults\":" + faults + "}");
        assertEquals(200, response.statusCode());
        return mapper.readTree(response.body()).path("runId").asText();
    }
    private HttpResponse<String> post(String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/runs"))
                .header("Content-Type", "application/json").header("X-Actor-Id", SECRET)
                .header("X-Request-Id", SECRET).header("X-Source", SECRET)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
    private List<JsonNode> events(CapturedOutput output, int terminalCount) throws Exception {
        long deadline = System.nanoTime() + java.time.Duration.ofSeconds(3).toNanos();
        List<JsonNode> result;
        do {
            result = output.getAll().lines().filter(l -> l.contains(" : audit "))
                    .map(l -> { try { return mapper.readTree(l.substring(l.indexOf(" : audit ") + 9)); }
                                catch (Exception e) { throw new AssertionError("Invalid audit JSON", e); } }).toList();
            if (terminals(result).size() >= terminalCount) { return result; }
            Thread.sleep(10);
        } while (System.nanoTime() < deadline);
        fail("Missing terminal audit events"); return List.of();
    }
    private static List<JsonNode> terminals(List<JsonNode> events) {
        return events.stream().filter(e -> !List.of("run.requested", "credential.resolved").contains(e.path("action").asText())).toList();
    }
    private static List<JsonNode> action(List<JsonNode> events, String action) {
        return events.stream().filter(e -> e.path("action").asText().equals(action)).toList();
    }
    private static void assertSafe(List<JsonNode> events) {
        assertFalse(events.toString().contains(SECRET));
        assertFalse(events.toString().contains("audit forged"));
        for (JsonNode e : events) {
            assertEquals("anonymous", e.path("actorType").asText());
            assertTrue(e.path("actorId").isNull()); assertEquals("http", e.path("source").asText());
            UUID.fromString(e.path("eventId").asText());
            assertEquals(1, e.path("schemaVersion").asInt());
        }
    }
}
