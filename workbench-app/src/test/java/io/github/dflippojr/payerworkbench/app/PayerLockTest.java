package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.mock.Fault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.FABRIKAM_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Runs against one synthetic payer take turns, because its faults are shared. A slow run must not stall the
 * runs queued behind it: each waits for the payer at most {@code workbench.request-timeout} and is then refused
 * with 409, and a {@code slowResponseDelayMs} past {@code request-timeout + 1 s} is refused before it can hold
 * the payer at all. The timeout is scaled down to 2 s so the queue builds in a few seconds.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "workbench.request-timeout=2s",
        "workbench.latency-warn=300ms",
        "workbench.latency-fail=600ms",
        "workbench.slow-response-delay=900ms"})
class PayerLockTest {

    private static final String SAMPLE = "order-sign-hospital-bed";
    private static final Duration WAIT = Duration.ofSeconds(2);
    /** {@code request-timeout + 1 s}. */
    private static final long CAP_MS = 3000;

    @Value("${local.server.port}")
    int port;

    @Autowired
    SyntheticPayers payers;

    @Autowired
    OnboardingRunner runner;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    /** A response and how long it took, from send to the whole body. */
    private record Answer(HttpResponse<String> response, Duration elapsed) {
        int status() { return response.statusCode(); }

        /** The status and the start of the body, enough to see why a run was refused. */
        @Override
        public String toString() {
            String body = response.body();
            return status() + " after " + elapsed + ": " + body.substring(0, Math.min(body.length(), 300));
        }
    }

    @Test
    void aQueueOfSlowRunsDoesNotStallTheNextRunForThePayer(CapturedOutput output) throws Exception {
        int remembered = mapper.readTree(get("/api/runs").body()).size();
        CompletableFuture<Answer> holder = post(slow(FABRIKAM_ID, CAP_MS));
        awaitSlowResponseOn(FABRIKAM_ID);
        List<CompletableFuture<Answer>> queued = List.of(post(slow(FABRIKAM_ID, CAP_MS)), post(slow(FABRIKAM_ID, CAP_MS)));
        Thread.sleep(100);
        CompletableFuture<Answer> healthy = post(healthy(FABRIKAM_ID));
        Answer northwind = post(healthy(NORTHWIND_ID)).get(30, TimeUnit.SECONDS);

        Answer next = healthy.get(30, TimeUnit.SECONDS);
        assertTrue(next.status() == 200 || next.status() == 409, next::toString);
        assertTrue(next.elapsed().compareTo(WAIT.plusSeconds(1)) <= 0,
                "the healthy run answered " + next.status() + " after " + next.elapsed());
        assertEquals(200, northwind.status(), northwind.toString());
        assertTrue(northwind.elapsed().compareTo(WAIT) < 0, "another payer's run took " + northwind.elapsed());

        List<Answer> all = new ArrayList<>(List.of(holder.get(30, TimeUnit.SECONDS), next));
        for (CompletableFuture<Answer> run : queued) { all.add(run.get(30, TimeUnit.SECONDS)); }
        assertEquals(200, all.getFirst().status(), "the slow run holding the payer finishes");
        List<Answer> refused = all.stream().filter(a -> a.status() == 409).toList();
        assertFalse(refused.isEmpty(), "two slow runs queued behind a third cannot all get the payer in time");
        for (Answer answer : refused) {
            assertEquals("another run against fabrikam-synthetic is in progress; try again when it finishes",
                    mapper.readTree(answer.response().body()).path("detail").asText());
            assertTrue(answer.elapsed().compareTo(WAIT.plusSeconds(1)) <= 0, "refused after " + answer.elapsed());
        }
        assertTrue(all.stream().allMatch(a -> a.status() == 200 || a.status() == 409), all::toString);

        // A refused run never started: nothing is remembered for it and its audit trail has no run id.
        long started = all.stream().filter(a -> a.status() == 200).count() + 1; // and the Northwind run
        assertEquals(remembered + started, mapper.readTree(get("/api/runs").body()).size());
        List<JsonNode> busy = runCompleted(output).stream()
                .filter(e -> e.path("metadata").path("reasonCode").asText().equals("payer_busy")).toList();
        assertEquals(refused.size(), busy.size(), output::getAll);
        for (JsonNode event : busy) {
            assertEquals("rejected", event.path("outcome").asText());
            assertEquals(409, event.path("metadata").path("httpStatus").asInt());
            assertTrue(event.path("runId").isNull(), event::toString);
        }
        assertEquals(List.of(), List.copyOf(payers.payer(FABRIKAM_ID).orElseThrow().faults().enabled()),
                "a refused run left the payer's faults alone, and the last run cleared them");
    }

    @Test
    void aSlowResponseDelayPastTheRequestTimeoutIsRefused(CapturedOutput output) throws Exception {
        Answer over = post(slow(NORTHWIND_ID, CAP_MS + 1)).get(30, TimeUnit.SECONDS);

        assertEquals(400, over.status(), over.toString());
        assertEquals("slowResponseDelayMs must be at most 3000 (workbench.request-timeout plus 1 s)",
                mapper.readTree(over.response().body()).path("detail").asText());
        assertTrue(over.elapsed().compareTo(WAIT) < 0, "refused before the payer was held: " + over.elapsed());
        JsonNode refused = runCompleted(output).stream()
                .filter(e -> e.path("metadata").path("httpStatus").asInt() == 400).findFirst().orElseThrow();
        assertEquals("invalid_slow_response_delay", refused.path("metadata").path("reasonCode").asText());
        assertTrue(refused.path("runId").isNull(), refused::toString);

        Answer atCap = post(slow(NORTHWIND_ID, CAP_MS)).get(30, TimeUnit.SECONDS);
        assertEquals(200, atCap.status(), atCap.toString());
        Answer byDefault = post("{\"payerId\":\"" + NORTHWIND_ID + "\",\"sampleId\":\"" + SAMPLE + "\",\"faults\":[\""
                + Fault.SLOW_RESPONSE.id() + "\"]}").get(30, TimeUnit.SECONDS);
        assertEquals(200, byDefault.status(), byDefault.toString());
    }

    @Test
    void theDefaultDelayFitsUnderTheDefaultCap() {
        WorkbenchProperties defaults = new WorkbenchProperties(null, null, null, null, null);
        assertEquals(Duration.ofSeconds(16), defaults.maxSlowResponseDelay());
        assertTrue(defaults.slowResponseDelay().compareTo(defaults.maxSlowResponseDelay()) <= 0);
    }

    @Test
    void aRunWaitingForThePayerStopsWhenInterrupted() throws Exception {
        CompletableFuture<Answer> holder = post(slow(FABRIKAM_ID, CAP_MS));
        awaitSlowResponseOn(FABRIKAM_ID);
        CompletableFuture<RuntimeException> waiting = new CompletableFuture<>();
        Thread waiter = new Thread(() -> {
            try {
                runner.run(new RunRequest(FABRIKAM_ID, null, SAMPLE, List.of(), null, null));
                waiting.complete(null);
            } catch (RuntimeException e) {
                waiting.complete(e);
            }
        });
        waiter.start();
        Thread.sleep(200);
        long start = System.nanoTime();
        waiter.interrupt();

        RuntimeException refused = waiting.get(30, TimeUnit.SECONDS);
        assertTrue(refused instanceof PayerBusyException, String.valueOf(refused));
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(WAIT) < 0, "the wait ended with the interrupt");
        waiter.join(10_000);
        assertEquals(200, holder.get(30, TimeUnit.SECONDS).status());
    }

    private void awaitSlowResponseOn(String payerId) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!payers.payer(payerId).orElseThrow().faults().isEnabled(Fault.SLOW_RESPONSE)) {
            if (System.nanoTime() > deadline) { fail("the slow run never set up its fault"); }
            Thread.sleep(5);
        }
    }

    private static String slow(String payerId, long delayMs) {
        return "{\"payerId\":\"" + payerId + "\",\"sampleId\":\"" + SAMPLE + "\",\"faults\":[\""
                + Fault.SLOW_RESPONSE.id() + "\"],\"slowResponseDelayMs\":" + delayMs + "}";
    }

    private static String healthy(String payerId) {
        return "{\"payerId\":\"" + payerId + "\",\"sampleId\":\"" + SAMPLE + "\"}";
    }

    private CompletableFuture<Answer> post(String body) {
        long start = System.nanoTime();
        return http.sendAsync(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/runs"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
                .thenApply(r -> new Answer(r, Duration.ofNanos(System.nanoTime() - start)));
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private List<JsonNode> runCompleted(CapturedOutput output) {
        return output.getAll().lines().filter(l -> l.contains(" : audit "))
                .map(l -> {
                    try { return mapper.readTree(l.substring(l.indexOf(" : audit ") + 9)); }
                    catch (Exception e) { throw new AssertionError("Invalid audit JSON", e); }
                })
                .filter(e -> e.path("action").asText().equals("run.completed"))
                .toList();
    }
}
