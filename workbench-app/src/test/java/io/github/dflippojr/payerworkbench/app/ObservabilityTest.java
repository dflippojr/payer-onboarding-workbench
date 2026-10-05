package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.ToDoubleFunction;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Actuator exposure and the run metrics, over real HTTP. Test contexts are shared
 * between test classes, so meter checks compare counts before and after.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        // Spring Boot turns metrics export off in tests; this test is about the export.
        properties = "management.prometheus.metrics.export.enabled=true")
class ObservabilityTest {

    private static final String SAMPLE = "order-sign-hospital-bed";

    @Value("${local.server.port}")
    int port;

    @Autowired
    MeterRegistry registry;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void exposesOnlyHealthInfoAndPrometheus() throws Exception {
        HttpResponse<String> health = get("/actuator/health");
        assertEquals(200, health.statusCode());
        assertEquals("UP", mapper.readTree(health.body()).path("status").asText());
        assertEquals(200, get("/actuator/info").statusCode());
        HttpResponse<String> prometheus = get("/actuator/prometheus");
        assertEquals(200, prometheus.statusCode());
        assertTrue(prometheus.headers().firstValue("Content-Type").orElse("").startsWith("text/plain"),
                prometheus.headers().toString());

        List<String> links = new ArrayList<>();
        mapper.readTree(get("/actuator").body()).path("_links").fieldNames().forEachRemaining(links::add);
        links.remove("self");
        assertEquals(List.of("health", "health-path", "info", "prometheus"), links.stream().sorted().toList());
        for (String hidden : List.of("env", "beans", "metrics", "loggers", "configprops", "heapdump", "threaddump",
                "mappings", "shutdown")) {
            assertEquals(404, get("/actuator/" + hidden).statusCode(), hidden + " must not be exposed");
        }
    }

    @Test
    void healthyAndFaultedRunsShowUpInTheMetrics() throws Exception {
        Map<String, Double> before = snapshot();

        JsonNode healthy = run(NORTHWIND_ID, List.of());
        JsonNode faulted = run(NORTHWIND_ID, List.of("discovery-500"));
        assertEquals(36, healthy.path("runId").asText().length());
        assertEquals(36, faulted.path("runId").asText().length());

        Map<String, Double> after = snapshot();
        Map<String, Double> delta = new TreeMap<>();
        after.forEach((k, v) -> {
            double d = v - before.getOrDefault(k, 0.0);
            if (d != 0) {
                delta.put(k, d);
            }
        });
        assertEquals(Map.of(
                "runs PASS none", 1.0,
                "runs FAIL discovery", 1.0,
                "step discovery passed", 1.0,
                "step discovery failed", 1.0,
                "step authenticate skipped", 1.0,
                "step diagnostics failed", 1.0,
                "request discovery 2xx", 1.0,
                "request discovery 5xx", 1.0,
                "request token 2xx", 1.0,
                "request hook 2xx", 1.0), filter(delta, "runs ", "step discovery", "step authenticate skipped",
                "step diagnostics failed", "request "));
        assertEquals(1.0, delta.get("finding discovery.reachable FAIL"));
        assertEquals(1.0, delta.get("finding discovery.reachable PASS"));

        String scrape = get("/actuator/prometheus").body();
        assertTrue(scrape.contains("workbench_runs_total{broke_at=\"discovery\",environment=\"SANDBOX\",payer=\""
                + NORTHWIND_ID + "\",verdict=\"FAIL\"}"), scrape);
        assertTrue(scrape.contains("workbench_step_duration_seconds_count{environment=\"SANDBOX\",payer=\""
                + NORTHWIND_ID + "\",status=\"failed\",step=\"discovery\"}"), scrape);
        assertTrue(scrape.contains("workbench_payer_request_duration_seconds_count{environment=\"SANDBOX\","
                + "payer=\"" + NORTHWIND_ID + "\",phase=\"discovery\",status_class=\"5xx\"}"), scrape);
        assertTrue(scrape.contains("workbench_findings_total{check=\"discovery.reachable\",environment=\"SANDBOX\","
                + "payer=\"" + NORTHWIND_ID + "\",severity=\"FAIL\"}"), scrape);
        assertFalse(scrape.contains(healthy.path("runId").asText()), "no run id in any tag");
        assertFalse(scrape.contains("127.0.0.1"), "no URL in any tag");
    }

    @ParameterizedTest
    @ValueSource(strings = {"md", "html", "json"})
    void everyReportFormatShowsTheCorrelationId(String format) throws Exception {
        String runId = run(NORTHWIND_ID, List.of()).path("runId").asText();
        String report = get("/api/runs/" + runId + "/report?format=" + format).body();
        if (format.equals("json")) {
            assertEquals(runId, mapper.readTree(report).path("correlationId").asText());
        } else {
            assertTrue(report.contains("Correlation id (X-Request-Id)"), report);
            assertTrue(report.contains(format.equals("md") ? "`" + runId + "`" : "<code>" + runId + "</code>"));
        }
    }

    /** The workbench meters for Northwind in SANDBOX, keyed by a short description of their tags. */
    private Map<String, Double> snapshot() {
        Map<String, Double> values = new TreeMap<>();
        collect(values, registry.find(RunMetrics.RUNS).tag("payer", NORTHWIND_ID).counters(), Counter::count,
                c -> "runs " + c.getId().getTag("verdict") + " " + c.getId().getTag("broke_at"));
        collect(values, registry.find(RunMetrics.STEP_DURATION).tag("payer", NORTHWIND_ID).timers(), Timer::count,
                t -> "step " + t.getId().getTag("step") + " " + t.getId().getTag("status"));
        collect(values, registry.find(RunMetrics.PAYER_REQUEST_DURATION).tag("payer", NORTHWIND_ID).timers(),
                Timer::count, t -> "request " + t.getId().getTag("phase") + " " + t.getId().getTag("status_class"));
        collect(values, registry.find(RunMetrics.FINDINGS).tag("payer", NORTHWIND_ID).counters(), Counter::count,
                c -> "finding " + c.getId().getTag("check") + " " + c.getId().getTag("severity"));
        return values;
    }

    private static <M extends Meter> void collect(
            Map<String, Double> into, Collection<M> meters, ToDoubleFunction<M> value,
            Function<M, String> key) {
        for (M meter : meters) {
            assertEquals("SANDBOX", meter.getId().getTag("environment"));
            into.merge(key.apply(meter), value.applyAsDouble(meter), Double::sum);
        }
    }

    private static Map<String, Double> filter(Map<String, Double> delta, String... prefixes) {
        Map<String, Double> out = new TreeMap<>();
        delta.forEach((k, v) -> {
            for (String prefix : prefixes) {
                if (k.startsWith(prefix)) {
                    out.put(k, v);
                }
            }
        });
        return out;
    }

    private JsonNode run(String payerId, List<String> faults) throws Exception {
        String body = mapper.writeValueAsString(Map.of("payerId", payerId, "environment", "SANDBOX",
                "sampleId", SAMPLE, "faults", faults));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/runs"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return mapper.readTree(response.body());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
