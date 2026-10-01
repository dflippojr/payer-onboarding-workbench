package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The REST API and static UI over real HTTP on an ephemeral port. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WorkbenchApiTest {

    private static final Pattern ACCESS_TOKEN_VALUE = Pattern.compile("\"access_token\"\\s*:\\s*\"[A-Za-z0-9_-]{20,}\"");

    @Value("${local.server.port}")
    int port;

    @Autowired
    SyntheticPayers payers;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void listsBothPayersWithRedactedConnections() throws Exception {
        HttpResponse<String> response = get("/api/payers");
        assertEquals(200, response.statusCode());
        JsonNode payerList = mapper.readTree(response.body());
        assertEquals(List.of(SyntheticPayers.NORTHWIND_ID, SyntheticPayers.FABRIKAM_ID),
                payerList.findValuesAsText("payerId").stream().distinct().toList());
        JsonNode connection = payerList.get(0).path("connections").get(0);
        assertEquals("SANDBOX", connection.path("environment").asText());
        assertTrue(connection.path("credentialConfigured").asBoolean());
        assertFalse(response.body().contains("credentialRef"));
        assertTrue(payerList.get(1).path("editableSettings").toString().contains("audOverride"));
        assertFalse(payerList.get(0).path("editableSettings").toString().contains("audOverride"));
        assertEquals(7, payerList.get(0).path("faults").size());
    }

    @Test
    void listsSamples() throws Exception {
        JsonNode samples = mapper.readTree(get("/api/samples").body());
        assertTrue(samples.size() >= 6);
        assertTrue(samples.findValuesAsText("id").contains("order-sign-hospital-bed"));
    }

    @Test
    void runIsReturnedAndCanBeFetchedAgain() throws Exception {
        HttpResponse<String> posted = post("/api/runs", """
                {"payerId":"fabrikam-synthetic","environment":"SANDBOX","sampleId":"order-sign-hospital-bed",
                 "faults":["malformed-card"]}""");
        assertEquals(200, posted.statusCode(), posted.body());
        JsonNode run = mapper.readTree(posted.body());
        assertEquals(6, run.path("steps").size());
        JsonNode hook = run.path("steps").get(3);
        assertEquals("hook-request", hook.path("stepId").asText());
        JsonNode exchange = hook.path("details").path("exchanges").get(0);
        assertEquals("POST", exchange.path("method").asText());
        assertTrue(exchange.path("latencyMs").isNumber());
        assertTrue(run.path("findings").findValuesAsText("severity").contains("FAIL"));

        HttpResponse<String> fetched = get("/api/runs/" + run.path("runId").asText());
        assertEquals(200, fetched.statusCode());
        assertEquals(run, mapper.readTree(fetched.body()));
    }

    @Test
    void responsesNeverCarrySecrets() throws Exception {
        List<String> bodies = new ArrayList<>();
        bodies.add(get("/api/payers").body());
        for (String payer : payers.payerIds()) {
            bodies.add(post("/api/runs", "{\"payerId\":\"" + payer + "\",\"sampleId\":\"order-sign-hospital-bed\"}").body());
        }
        String secret = payers.credentials().resolve("northwind-client-secret").orElseThrow();
        String pem = payers.credentials().resolve("fabrikam-signing-key").orElseThrow();
        String keyChunk = pem.lines().skip(5).findFirst().orElseThrow();
        for (String body : bodies) {
            assertFalse(body.contains(secret), "client secret leaked");
            assertFalse(body.contains(keyChunk), "private key leaked");
            assertFalse(body.contains("PRIVATE KEY"), "private key leaked");
            assertFalse(ACCESS_TOKEN_VALUE.matcher(body).find(), "access token leaked");
        }
        // The Basic credential and the bearer JWT are masked in the recorded request headers.
        assertFalse(bodies.get(1).contains("Basic " + java.util.Base64.getEncoder().encodeToString(
                (SyntheticPayers.CLIENT_ID + ":" + secret).getBytes())));
    }

    @Test
    void reportsAreServedInEveryFormat() throws Exception {
        HttpResponse<String> posted = post("/api/runs", """
                {"payerId":"fabrikam-synthetic","sampleId":"order-sign-hospital-bed","faults":["wrong-audience-reject"]}""");
        String runId = mapper.readTree(posted.body()).path("runId").asText();
        String secret = payers.credentials().resolve("northwind-client-secret").orElseThrow();
        String keyChunk = payers.credentials().resolve("fabrikam-signing-key").orElseThrow()
                .lines().skip(5).findFirst().orElseThrow();
        for (String format : List.of("md", "html", "json")) {
            HttpResponse<String> report = get("/api/runs/" + runId + "/report?format=" + format);
            assertEquals(200, report.statusCode(), format);
            String type = report.headers().firstValue("Content-Type").orElse("");
            assertTrue(type.startsWith(switch (format) {
                case "md" -> "text/markdown";
                case "html" -> "text/html";
                default -> "application/json";
            }), type);
            assertTrue(report.headers().firstValue("Content-Disposition").orElse("")
                    .contains("onboarding-report-fabrikam-synthetic-" + runId + "." + format));
            String body = report.body();
            assertTrue(body.contains(RunReport.DISCLAIMER), format);
            assertTrue(body.contains("Fabrikam"), format);
            assertTrue(body.contains("response.schema"), format);
            assertTrue(body.contains("FAIL"), format);
            assertFalse(body.contains(secret), format);
            assertFalse(body.contains(keyChunk), format);
            assertFalse(body.contains("PRIVATE KEY"), format);
        }
        JsonNode json = mapper.readTree(get("/api/runs/" + runId + "/report?format=json").body());
        assertEquals(runId, json.path("runId").asText());
        assertEquals("SANDBOX", json.path("environment").asText());
        assertFalse(json.path("igVersion").asText().isBlank());
        assertFalse(json.path("workbenchVersion").asText().isBlank());
        assertFalse(json.path("generatedAt").asText().isBlank());

        assertEquals(400, get("/api/runs/" + runId + "/report?format=pdf").statusCode());
        assertEquals(404, get("/api/runs/no-such-run/report?format=md").statusCode());
    }

    @Test
    void badRequestsAreRejected() throws Exception {
        assertEquals(400, post("/api/runs", "{\"payerId\":\"nobody\",\"sampleId\":\"order-sign-hospital-bed\"}").statusCode());
        assertEquals(400, post("/api/runs", "{\"payerId\":\"northwind-synthetic\"}").statusCode());
        assertEquals(404, get("/api/runs/no-such-run").statusCode());
    }

    @Test
    void servesTheUiWithTheSyntheticBanner() throws Exception {
        HttpResponse<String> index = get("/");
        assertEquals(200, index.statusCode());
        assertTrue(index.body().contains("Synthetic payers only; passing here does not prove real-payer interoperability."));
        assertEquals(200, get("/app.js").statusCode());
        assertEquals(200, get("/styles.css").statusCode());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }
}
