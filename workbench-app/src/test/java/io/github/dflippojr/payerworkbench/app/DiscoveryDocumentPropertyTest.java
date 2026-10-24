package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

/**
 * Class-level check (#214): no discovery document the payer serves with HTTP 200 makes a run
 * report a raw Java exception, or claim the payer never answered. Generated {@code services}
 * lists mix service objects (with string, number, object, array and null hooks, ids and prefetch
 * maps) with entries that are not objects at all. Every entry that is not an object must be named
 * by a {@code discovery.services} FAIL.
 */
class DiscoveryDocumentPropertyTest {

    private static final String SAMPLE = "order-sign-hospital-bed";
    private static final AtomicReference<String> DOCUMENT = new AtomicReference<>("{\"services\":[]}");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static HttpServer server;
    private static SyntheticPayers payers;
    private static OnboardingRunner runner;

    @BeforeContainer
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p/cds-services", exchange -> {
            exchange.getRequestBody().readAllBytes();
            String body = exchange.getRequestMethod().equals("GET") ? DOCUMENT.get()
                    : "{\"cards\":[{\"summary\":\"s\",\"indicator\":\"info\",\"source\":{\"label\":\"l\"}}]}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        payers = new SyntheticPayers(new AuditLog(registry));
        runner = new OnboardingRunner(payers, new SampleCatalog(), new WorkbenchProperties(null, null, null, null, null,
                new WorkbenchProperties.CustomEndpoints(true)), new RunMetrics(registry));
    }

    @AfterContainer
    static void stop() throws Exception {
        server.stop(0);
        payers.destroy();
    }

    @Provide
    Arbitrary<List<String>> services() {
        Arbitrary<String> notObject = Arbitraries.of("null", "0", "-1.5", "1e3", "true", "false", "\"\"", "\"x\"",
                "\"order-sign\"", "[]", "[null]", "[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\"}]");
        Arbitrary<String> hook = Arbitraries.of("\"order-sign\"", "\"patient-view\"", "\"\"", "5", "null", "{}", "[]", "true");
        Arbitrary<String> id = Arbitraries.of("\"crd-order-sign\"", "\"bad id\"", "\"..\"", "\"\"", "7", "null", "{}", "[]");
        Arbitrary<String> prefetch = Arbitraries.of("{}", "{\"coverage\":\"Coverage?patient={{context.patientId}}\"}",
                "{\"a\":1}", "{\"a\":null}", "{\"a\":{}}", "{\"a\":[]}", "\"x\"", "[]", "null", "3");
        Arbitrary<String> object = Combinators.combine(
                        field("hook", hook), field("id", id), field("prefetch", prefetch), field("extra", notObject))
                .as((h, i, p, e) -> "{" + String.join(",", List.of(h, i, p, e).stream().filter(f -> !f.isEmpty())
                        .toList()) + "}");
        return Arbitraries.oneOf(notObject, object).list().ofMaxSize(6);
    }

    /** The field as {@code "name":value}, or left out a third of the time. */
    private static Arbitrary<String> field(String name, Arbitrary<String> value) {
        return Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(2, value.map(v -> "\"" + name + "\":" + v)),
                net.jqwik.api.Tuple.of(1, Arbitraries.just("")));
    }

    @Property(tries = 300)
    void anyDiscoveryDocumentIsReportedWithoutAJavaExceptionAndNamesEntriesThatAreNotObjects(
            @ForAll("services") List<String> services) throws Exception {
        String document = "{\"services\":[" + String.join(",", services) + "]}";
        DOCUMENT.set(document);
        OnboardingRun run = runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                new RunRequest.CustomEndpoint("http://127.0.0.1:" + server.getAddress().getPort() + "/p",
                        AuthType.NONE, null, null, null, NorthwindPayer.builder().build().igVersion(), null)));

        for (StepResult step : run.steps()) {
            assertFalse(step.summary().contains("Exception") || step.summary().contains("Unexpected error"),
                    document + " -> " + step.stepId() + ": " + step.summary());
        }
        for (Finding f : run.findings()) {
            String text = f.title() + "\n" + f.explanation() + "\n" + f.evidence() + "\n" + f.suggestedFix();
            assertFalse(text.contains("Exception"), document + " -> " + text);
            // Discovery always answered here, so no finding may say the payer did not.
            assertFalse(text.contains("no payer response") || text.contains("before the payer answered"),
                    document + " -> " + text);
        }
        JsonNode entries = MAPPER.readTree(document).path("services");
        for (int i = 0; i < entries.size(); i++) {
            if (!entries.get(i).isObject()) {
                Finding named = run.findings().stream().filter(f -> f.checkId().equals("discovery.services"))
                        .findFirst().orElseThrow(() -> new AssertionError(document + " -> no discovery.services"));
                assertEquals(Severity.FAIL, named.severity(), document + " -> " + named.title());
                assertTrue(named.evidence().contains("services[" + i + "]: "), document + " -> " + named.evidence());
                assertFalse(run.steps().get(1).ok(), document + " -> discovery must fail");
                break;
            }
        }
    }
}
