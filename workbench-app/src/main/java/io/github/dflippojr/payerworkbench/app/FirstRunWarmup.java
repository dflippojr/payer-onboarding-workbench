package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Runs the onboarding flow once against each synthetic payer in the background as the app starts, so
 * the first run a user starts does not pay for class loading, TLS and SDK setup (issue #53).
 *
 * <p>The warm-up is invisible: it never reaches {@link RunStore}, the run metrics or a replay export.
 * It does not delay startup, and a user run that arrives while it is going just proceeds (runs for
 * one payer take turns). A failure is logged as a warning and nothing more.
 */
@Component
class FirstRunWarmup implements SmartInitializingSingleton {

    static final String SAMPLE_ID = "order-sign-hospital-bed";
    static final List<String> PAYERS = List.of("northwind-synthetic");

    private static final Logger LOG = LoggerFactory.getLogger(FirstRunWarmup.class);

    private final OnboardingRunner runner;
    private final JsonMapper json;
    private final ApplicationContext context;
    private final CompletableFuture<Integer> port = new CompletableFuture<>();

    FirstRunWarmup(OnboardingRunner runner, JsonMapper json, ApplicationContext context) {
        this.runner = runner;
        this.json = json;
        this.context = context;
    }

    /** Starts as soon as every bean exists, so the warm-up overlaps the web server starting. */
    @Override
    public void afterSingletonsInstantiated() {
        Thread.ofPlatform().name("first-run-warmup").daemon().start(this::warmUp);
    }

    @EventListener
    void onWebServerInitialized(WebServerInitializedEvent event) {
        if ("management".equals(event.getApplicationContext().getServerNamespace())) {
            return;
        }
        port.complete(event.getWebServer().getPort());
    }

    /** Runs the warm-up on the calling thread. */
    void warmUp() {
        long start = System.nanoTime();
        // The request path needs the web server, not a run, so it warms alongside the first run.
        Thread path = Thread.ofPlatform().name("first-run-warmup-path").daemon().start(this::warmRequestPath);
        for (String payerId : PAYERS) {
            try {
                // Serialising the result with the app's mapper also warms the response the API sends.
                json.writeValueAsString(
                        runner.warmUp(new RunRequest(payerId, Environment.SANDBOX, SAMPLE_ID, List.of(), null, null)));
            } catch (RuntimeException e) {
                LOG.warn("First-run warm-up against {} failed; the first run will be slower: {}", payerId,
                        e.toString());
            }
        }
        try {
            path.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        LOG.info("First-run warm-up finished in {} ms", (System.nanoTime() - start) / 1_000_000);
    }

    /**
     * Sends {@code POST /api/runs} with an empty body to this app, which answers 400 before any run
     * starts. That loads the web stack's request path (parsing, the controller, the error response)
     * without creating a run, so nothing is stored or counted.
     */
    private void warmRequestPath() {
        if (!(context instanceof WebServerApplicationContext)) {
            return; // no web server to wait for, as in a test with a mock web environment
        }
        try (HttpClient http = HttpClient.newHttpClient()) {
            URI uri = URI.create("http://127.0.0.1:" + port.get(10, TimeUnit.SECONDS) + "/api/runs");
            http.send(HttpRequest.newBuilder(uri)
                            .timeout(Duration.ofSeconds(10))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("First-run warm-up of the request path was interrupted");
        } catch (Exception e) {
            LOG.warn("First-run warm-up of the request path failed; the first request will be slower: {}",
                    e.toString());
        }
    }
}
