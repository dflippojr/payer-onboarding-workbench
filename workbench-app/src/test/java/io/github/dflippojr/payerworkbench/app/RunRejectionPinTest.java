package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.core.Environment;
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
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Pins every way {@code POST /api/runs} and {@code GET /api/runs/{id}/report} refuse a request today (#379, Stage 1):
 * the status, the whole problem detail, and the terminal audit event's action, outcome, reason code and the
 * {@code payerId}, {@code sampleId} and {@code environment} it carries. The audit trail is a documented contract read
 * by {@code scripts/audit-reader.mjs}, so a refactor of run validation must leave every row here as it is.
 *
 * <p>Where a request breaks two rules, the row pins what wins today, even where the reason and the detail come from
 * different rules (an unknown payer and an unknown sample is audited {@code unknown_sample} with the unknown payer's
 * detail). {@link RunRejectionCustomDisabledPinTest} pins the rows that need custom endpoints switched off, and
 * {@link PayerLockTest} pins {@code payer_busy}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "workbench.custom-endpoints.enabled=true",
        "workbench.max-concurrent-runs=1",
        "workbench.request-timeout=2s"})
class RunRejectionPinTest {

    static final String SAMPLE = "order-sign-hospital-bed";
    static final String NORTHWIND = "northwind-synthetic";
    static final String CUSTOM = RunRequest.CUSTOM_PAYER_ID;
    /** Port 9 (discard) refuses the connection at once, so a run that gets that far ends quickly. */
    static final String UNREACHABLE = "http://127.0.0.1:9/r4";
    /** {@code workbench.request-timeout} plus 1 s. */
    static final long MAX_DELAY_MS = 3000;
    static final String SUFFIX_RULE = "baseUrlSuffix may only add path segments to the base URL: "
            + "it must start with / and can't contain . or .. segments (raw or as %2e), "
            + "@, ?, #, \\, whitespace or control characters";

    static final List<AuditEvent> EVENTS = new CopyOnWriteArrayList<>();
    /** What the run store throws on save, or null to save normally. */
    static final AtomicReference<RuntimeException> SAVE_FAILURE = new AtomicReference<>();

    @TestConfiguration
    static class Doubles {
        @Bean
        @Primary
        AuditLog capturingAuditLog(MeterRegistry registry) {
            return new AuditLog(EVENTS::add, Clock.systemUTC(), registry);
        }

        /** A failure after the run: the run completes, then saving it throws whatever the test set. */
        @Bean
        @Primary
        RunStore failingRunStore(WorkbenchProperties properties) {
            return new RunStore(properties) {
                @Override
                public void save(OnboardingRun run) {
                    RuntimeException failure = SAVE_FAILURE.get();
                    if (failure != null) { throw failure; }
                    super.save(run);
                }
            };
        }
    }

    /**
     * One refused request and everything the caller and the audit trail see of it.
     *
     * @param detail the problem detail's {@code detail}, or null when the response is not a problem detail
     */
    record Row(String name, String body, int status, String detail, String reason, String payerId, String sampleId,
               Environment environment) {
    }

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void reset() {
        SAVE_FAILURE.set(null);
    }

    @Test
    void everyRunRejectionKeepsItsStatusDetailAndAuditedReason() throws Exception {
        List<Row> rows = List.of(
                // missing_input: the controller's own check comes first
                new Row("no ids", "{}", 400, "payerId and sampleId are required", "missing_input",
                        null, null, Environment.SANDBOX),
                new Row("no sample", body(Map.of("payerId", NORTHWIND)), 400,
                        "payerId and sampleId are required", "missing_input", NORTHWIND, null, Environment.SANDBOX),
                new Row("no payer", body(Map.of("sampleId", SAMPLE)), 400,
                        "payerId and sampleId are required", "missing_input", null, SAMPLE, Environment.SANDBOX),
                new Row("custom, no sample", body(Map.of("customEndpoint", none(UNREACHABLE))), 400,
                        "payerId and sampleId are required", "missing_input", CUSTOM, null, Environment.SANDBOX),
                new Row("unknown payer and missing sample", body(Map.of("payerId", "nobody")), 400,
                        "payerId and sampleId are required", "missing_input", null, null, Environment.SANDBOX),

                // synthetic payer
                new Row("unknown sample", body(Map.of("payerId", NORTHWIND, "sampleId", "nothing",
                        "environment", "PRODUCTION")), 400, "Unknown sampleId: nothing", "unknown_sample",
                        NORTHWIND, null, Environment.PRODUCTION),
                new Row("unknown payer", body(Map.of("payerId", "nobody", "sampleId", SAMPLE)), 400,
                        "Unknown payerId: nobody", "unknown_payer", null, SAMPLE, Environment.SANDBOX),
                new Row("unknown payer and unknown sample: the reason and the detail name different rules",
                        body(Map.of("payerId", "nobody", "sampleId", "nothing")), 400,
                        "Unknown payerId: nobody", "unknown_sample", null, null, Environment.SANDBOX),
                new Row("unknown sample and unknown fault", body(Map.of("payerId", NORTHWIND, "sampleId", "nothing",
                        "faults", List.of("no-such-fault"))), 400, "Unknown sampleId: nothing", "unknown_sample",
                        NORTHWIND, null, Environment.SANDBOX),
                new Row("unknown fault", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "faults", List.of("no-such-fault"))), 400, "Unknown fault: no-such-fault", "unknown_fault",
                        NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("unknown payer and unknown fault", body(Map.of("payerId", "nobody", "sampleId", SAMPLE,
                        "faults", List.of("no-such-fault"))), 400, "Unknown payerId: nobody", "unknown_payer",
                        null, SAMPLE, Environment.SANDBOX),
                new Row("unknown fault and a delay out of range", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "faults", List.of("no-such-fault"), "slowResponseDelayMs", -1)), 400,
                        "Unknown fault: no-such-fault", "unknown_fault", NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("negative delay", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "faults", List.of("slow-response"), "slowResponseDelayMs", -1)), 400,
                        "slowResponseDelayMs must be between 0 and " + MAX_DELAY_MS
                                + " (workbench.request-timeout plus 1 s)",
                        "invalid_slow_response_delay", NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("delay past the maximum", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "slowResponseDelayMs", MAX_DELAY_MS + 1)), 400,
                        "slowResponseDelayMs must be at most " + MAX_DELAY_MS + " (workbench.request-timeout plus 1 s)",
                        "invalid_slow_response_delay", NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("delay past the maximum and a bad suffix", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "slowResponseDelayMs", MAX_DELAY_MS + 1, "connection", Map.of("baseUrlSuffix", "/.."))), 400,
                        "slowResponseDelayMs must be at most " + MAX_DELAY_MS + " (workbench.request-timeout plus 1 s)",
                        "invalid_slow_response_delay", NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("bad suffix", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "connection", Map.of("baseUrlSuffix", "@evil.example"))), 400, SUFFIX_RULE,
                        "invalid_connection_edit", NORTHWIND, SAMPLE, Environment.SANDBOX),
                new Row("bad suffix with no stored record for the environment", body(Map.of("payerId", NORTHWIND,
                        "sampleId", SAMPLE, "environment", "STAGING", "connection", Map.of("baseUrlSuffix", "x"))),
                        400, SUFFIX_RULE, "invalid_connection_edit", NORTHWIND, SAMPLE, Environment.STAGING),

                // custom endpoint
                new Row("custom, unknown sample", body(Map.of("sampleId", "nothing",
                        "customEndpoint", none(UNREACHABLE))), 400, "Unknown sampleId: nothing", "unknown_sample",
                        CUSTOM, null, Environment.SANDBOX),
                new Row("custom, unknown sample and faults", body(Map.of("sampleId", "nothing",
                        "faults", List.of("discovery-500"), "customEndpoint", none(UNREACHABLE))), 400,
                        "Unknown sampleId: nothing", "unknown_sample", CUSTOM, null, Environment.SANDBOX),
                new Row("custom, a payerId is replaced", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "faults", List.of("discovery-500"), "customEndpoint", none(UNREACHABLE))), 400,
                        "Faults only apply to the synthetic payers", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, faults", body(Map.of("sampleId", SAMPLE, "faults", List.of("no-such-fault"),
                        "customEndpoint", none(UNREACHABLE))), 400, "Faults only apply to the synthetic payers",
                        "invalid_custom_endpoint", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, faults and a refused base URL", body(Map.of("sampleId", SAMPLE,
                        "faults", List.of("discovery-500"), "customEndpoint", none("http://169.254.169.254/"))), 400,
                        "Faults only apply to the synthetic payers", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, unsupported authType", custom(Map.of("baseUrl", UNREACHABLE, "authType", "API_KEY")),
                        400, "authType must be NONE, OAUTH2_CLIENT_CREDENTIALS, CDS_HOOKS_JWT or OAUTH2_PRIVATE_KEY_JWT",
                        "invalid_custom_endpoint", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, unsupported authType and a refused base URL", custom(Map.of(
                        "baseUrl", "http://169.254.169.254/", "authType", "API_KEY")), 400,
                        "authType must be NONE, OAUTH2_CLIENT_CREDENTIALS, CDS_HOOKS_JWT or OAUTH2_PRIVATE_KEY_JWT",
                        "invalid_custom_endpoint", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no base URL", custom(Map.of("authType", "NONE")), 400, "Base URL is required",
                        "destination_rejected", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, plain http to a non-loopback base URL and a credential with NONE", custom(Map.of(
                        "baseUrl", "http://169.254.169.254/", "authType", "NONE", "credential", "synthetic")), 400,
                        "Base URL uses plain http to 169.254.169.254. Plain http is only allowed to loopback hosts "
                                + "(localhost, 127.0.0.1, [::1]); use https for any other host.",
                        "destination_rejected", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, credential with NONE", custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE",
                        "credential", "synthetic")), 400, "authType NONE takes no credential",
                        "invalid_custom_endpoint", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no clientId", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                        "credential", "synthetic", "keyId", "synthetic-kid")), 400,
                        "clientId is required for CDS_HOOKS_JWT", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no clientId and no credential", custom(Map.of("baseUrl", UNREACHABLE,
                        "authType", "OAUTH2_CLIENT_CREDENTIALS")), 400,
                        "clientId is required for OAUTH2_CLIENT_CREDENTIALS", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no credential", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                        "clientId", "synthetic-client", "keyId", "synthetic-kid")), 400,
                        "credential is required for CDS_HOOKS_JWT", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no token endpoint", custom(Map.of("baseUrl", UNREACHABLE,
                        "authType", "OAUTH2_CLIENT_CREDENTIALS", "clientId", "synthetic-client",
                        "credential", "synthetic")), 400, "Token endpoint is required", "destination_rejected",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no token endpoint and no keyId", custom(Map.of("baseUrl", UNREACHABLE,
                        "authType", "OAUTH2_PRIVATE_KEY_JWT", "clientId", "synthetic-client",
                        "credential", "synthetic")), 400, "Token endpoint is required", "destination_rejected",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, no keyId", custom(Map.of("baseUrl", UNREACHABLE, "authType", "CDS_HOOKS_JWT",
                        "clientId", "synthetic-client", "credential", "synthetic")), 400,
                        "keyId is required for CDS_HOOKS_JWT", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, bad suffix", body(Map.of("sampleId", SAMPLE, "connection", Map.of("baseUrlSuffix",
                        "/%2E%2E/x"), "customEndpoint", none(UNREACHABLE))), 400, SUFFIX_RULE,
                        "invalid_connection_edit", CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, bad suffix and a credential with NONE", body(Map.of("sampleId", SAMPLE,
                        "connection", Map.of("baseUrlSuffix", "/.."), "customEndpoint", Map.of("baseUrl", UNREACHABLE,
                                "authType", "NONE", "credential", "synthetic"))), 400,
                        "authType NONE takes no credential", "invalid_custom_endpoint",
                        CUSTOM, SAMPLE, Environment.SANDBOX),
                new Row("custom, a delay out of range is ignored, the suffix is not", body(Map.of("sampleId", SAMPLE,
                        "slowResponseDelayMs", -1, "connection", Map.of("baseUrlSuffix", "/.."),
                        "customEndpoint", none(UNREACHABLE))), 400, SUFFIX_RULE,
                        "invalid_connection_edit", CUSTOM, SAMPLE, Environment.SANDBOX),

                // a body MVC cannot bind is audited by the filter's fallback
                new Row("not JSON", "{", 400, RunBodyProblem.NOT_JSON, "invalid_body", null, null, null),
                new Row("not an object", "[]", 400, RunBodyProblem.NOT_AN_OBJECT, "invalid_body", null, null, null),
                new Row("null fault", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "faults", Arrays.asList((Object) null))), 400, "faults must not contain null",
                        "invalid_body", null, null, null),
                new Row("unknown environment", body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE,
                        "environment", "MOON")), 400, "environment must be one of SANDBOX, STAGING, PRODUCTION",
                        "invalid_body", null, null, null));

        List<Runnable> checks = new ArrayList<>();
        for (Row row : rows) {
            Answer answer = post(row.body());
            checks.add(() -> {
                assertRejected(row, answer, "/api/runs", "run.completed");
                assertEquals(null, answer.end().runId(), row.name() + ": no run started");
            });
        }
        assertAll(checks.stream().map(c -> c::run));
    }

    /**
     * An {@link IllegalArgumentException} nobody planned for, thrown after the run, still reaches the caller as a 400
     * with its message through the controller's generic handler, and the filter audits it {@code invalid_body}.
     * Without that handler it would be a 500 audited {@code request_failed}.
     */
    @Test
    void anUnplannedIllegalArgumentIsA400AuditedAsInvalidBody() throws Exception {
        SAVE_FAILURE.set(new IllegalArgumentException("synthetic run store refusal"));
        Answer answer = post(body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE)));
        assertRejected(new Row("unplanned IllegalArgumentException", null, 400, "synthetic run store refusal",
                "invalid_body", NORTHWIND, SAMPLE, Environment.SANDBOX), answer, "/api/runs", "run.completed");
        assertTrue(answer.end().runId() != null, "the run had started");
    }

    /** A failure the caller did not cause is a 500 audited {@code request_failed}, on a custom run too (#378). */
    @Test
    void aServerErrorAfterTheRunIsAuditedAsRequestFailed() throws Exception {
        SAVE_FAILURE.set(new IllegalStateException("synthetic run store failure"));
        Answer synthetic = post(body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE)));
        Answer custom = post(custom(Map.of("baseUrl", UNREACHABLE, "authType", "NONE")));
        assertRejected(new Row("server error, synthetic", null, 500, null, "request_failed",
                NORTHWIND, SAMPLE, Environment.SANDBOX), synthetic, "/api/runs", "run.completed");
        assertRejected(new Row("server error, custom", null, 500, null, "request_failed",
                CUSTOM, SAMPLE, Environment.SANDBOX), custom, "/api/runs", "run.completed");
    }

    /** One custom run more than {@code workbench.max-concurrent-runs} is refused with 503 and a retry hint. */
    @Test
    void aCustomRunPastTheConcurrencyLimitIsAuditedAsRunsBusy() throws Exception {
        CountDownLatch inHook = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService payerThreads = Executors.newCachedThreadPool();
        server.setExecutor(payerThreads);
        server.createContext("/held/cds-services", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) {
                respond(exchange, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\",\"prefetch\":{}}]}");
                return;
            }
            exchange.getRequestBody().readAllBytes();
            inHook.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, "{\"cards\":[]}");
        });
        server.start();
        try {
            String held = custom(Map.of("baseUrl", "http://127.0.0.1:" + server.getAddress().getPort() + "/held",
                    "authType", "NONE"));
            CompletableFuture<Answer> holder = CompletableFuture.supplyAsync(() -> {
                try { return post(held); } catch (Exception e) { throw new IllegalStateException(e); }
            });
            assertTrue(inHook.await(30, TimeUnit.SECONDS), "the permitted run reached its hook call");

            Answer refused = post(held);

            assertEquals(null, refused.end().runId(), "no run started");
            assertRejected(new Row("runs busy", null, 503, "1 custom-endpoint runs are already in progress "
                    + "(workbench.max-concurrent-runs); try again when one finishes", "runs_busy",
                    CUSTOM, SAMPLE, Environment.SANDBOX), refused, "/api/runs", "run.completed");
            assertEquals("5", refused.response().headers().firstValue("Retry-After").orElse(null));
            release.countDown();
            assertEquals(200, holder.get(30, TimeUnit.SECONDS).response().statusCode());
        } finally {
            release.countDown();
            server.stop(0);
            payerThreads.shutdownNow();
        }
    }

    @Test
    void everyReportRejectionKeepsItsStatusDetailAndAuditedReason() throws Exception {
        Answer ran = post(body(Map.of("payerId", NORTHWIND, "sampleId", SAMPLE)));
        assertEquals(200, ran.response().statusCode(), ran.response().body());
        String runId = mapper.readTree(ran.response().body()).path("runId").asText();

        Answer badFormat = get("/api/runs/" + runId + "/report?format=pdf");
        Answer unknownAndBadFormat = get("/api/runs/no-such-run/report?format=pdf");
        Answer unknown = get("/api/runs/no-such-run/report?format=md");
        Answer unknownRun = get("/api/runs/no-such-run");

        assertAll(
                () -> {
                    assertRejected(new Row("report, bad format", null, 400, "format must be md, html or json",
                            "invalid_format", null, null, null), badFormat, "/api/runs/" + runId + "/report",
                            "report.rendered");
                    assertEquals(runId, badFormat.end().runId());
                    assertEquals(runId, badFormat.end().targetId());
                    assertEquals(null, badFormat.end().metadata().reportFormat());
                },
                () -> {
                    // The format is checked before the run is looked up.
                    assertRejected(new Row("report, unknown run and bad format", null, 400,
                            "format must be md, html or json", "invalid_format", null, null, null),
                            unknownAndBadFormat, "/api/runs/no-such-run/report", "report.rendered");
                    assertEquals(null, unknownAndBadFormat.end().runId());
                },
                () -> {
                    assertRejected(new Row("report, unknown run", null, 404, null, "not_found",
                            null, null, null), unknown, "/api/runs/no-such-run/report", "report.rendered");
                    assertEquals(null, unknown.end().runId());
                    assertEquals("md", unknown.end().metadata().reportFormat());
                },
                () -> assertRejected(new Row("unknown run", null, 404, null, "not_found",
                        null, null, null), unknownRun, "/api/runs/no-such-run", "run.read"));
    }

    // ---- helpers ----

    /** A response and the terminal audit event this test's request produced. */
    record Answer(HttpResponse<String> response, AuditEvent end) {
    }

    private void assertRejected(Row row, Answer answer, String path, String action) {
        String name = row.name();
        HttpResponse<String> response = answer.response();
        AuditEvent end = answer.end();
        assertAll(name,
                () -> assertEquals(row.status(), response.statusCode(), name + ": " + response.body()),
                () -> {
                    if (row.status() == 404) {
                        // Spring Boot's error body for a ResponseStatusException, not a problem detail.
                        Map<String, Object> body = new TreeMap<>(
                                mapper.convertValue(mapper.readTree(response.body()), Map.class));
                        assertTrue(body.remove("timestamp") instanceof String, name);
                        assertEquals(Map.of("error", "Not Found", "path", path, "status", 404), body, name);
                        assertEquals("application/json",
                                response.headers().firstValue("Content-Type").orElse(null), name);
                        return;
                    }
                    if (row.detail() == null) { return; }
                    JsonNode problem = mapper.readTree(response.body());
                    Map<String, Object> expected = new LinkedHashMap<>();
                    expected.put("detail", row.detail());
                    expected.put("instance", path);
                    expected.put("status", row.status());
                    expected.put("title", HttpStatus.valueOf(row.status()).getReasonPhrase());
                    assertEquals(expected, new TreeMap<>(mapper.convertValue(problem, Map.class)), name);
                    assertEquals("application/problem+json",
                            response.headers().firstValue("Content-Type").orElse(null), name);
                },
                () -> assertEquals(action, end.action(), name),
                () -> assertEquals("rejected", end.outcome(), name),
                () -> assertEquals(row.status(), end.metadata().httpStatus(), name),
                () -> assertEquals(row.reason(), end.metadata().reasonCode(), name),
                () -> assertEquals(row.payerId(), end.metadata().payerId(), name + ": payerId"),
                () -> assertEquals(row.sampleId(), end.metadata().sampleId(), name + ": sampleId"),
                () -> assertEquals(row.environment(), end.metadata().environment(), name + ": environment"));
    }

    private Answer post(String body) throws Exception {
        return send(HttpRequest.newBuilder(uri("/api/runs")).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build());
    }

    private Answer get(String path) throws Exception {
        return send(HttpRequest.newBuilder(uri(path)).GET().build());
    }

    /** Sends one request and waits for the terminal audit event it produced. */
    private Answer send(HttpRequest request) throws Exception {
        int before = terminals().size();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (true) {
            List<AuditEvent> all = terminals();
            for (AuditEvent event : all.subList(before, all.size())) {
                if (event.metadata().httpStatus() != null && event.metadata().httpStatus() == response.statusCode()
                        && matches(request, event)) {
                    return new Answer(response, event);
                }
            }
            if (System.nanoTime() > deadline) { fail("No terminal audit event for " + request.uri()); }
            Thread.sleep(10);
        }
    }

    private static boolean matches(HttpRequest request, AuditEvent event) {
        String path = request.uri().getPath();
        return switch (event.action()) {
            case "run.completed" -> request.method().equals("POST");
            case "report.rendered" -> path.endsWith("/report");
            case "run.read" -> !path.endsWith("/report");
            default -> false;
        };
    }

    /** This test's own terminal events: the warm-up is the system actor. */
    private static List<AuditEvent> terminals() {
        return EVENTS.stream().filter(e -> e.actorType().equals("anonymous") && e.metadata() != null
                && e.metadata().httpStatus() != null).toList();
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private String body(Map<String, Object> body) throws IOException {
        return mapper.writeValueAsString(body);
    }

    private String custom(Map<String, Object> endpoint) throws IOException {
        return body(Map.of("sampleId", SAMPLE, "customEndpoint", endpoint));
    }

    private static Map<String, Object> none(String baseUrl) {
        return Map.of("baseUrl", baseUrl, "authType", "NONE");
    }

    private static void respond(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
