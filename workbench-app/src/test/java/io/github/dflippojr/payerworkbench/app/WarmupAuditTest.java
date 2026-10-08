package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/** The first-run warm-up is the system actor; a caller cannot claim that, or suppress its own audit. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WarmupAuditTest {

    static final List<AuditEvent> EVENTS = new CopyOnWriteArrayList<>();

    @TestConfiguration
    static class Capture {
        @Bean
        @Primary
        AuditLog capturingAuditLog(MeterRegistry registry) {
            return new AuditLog(EVENTS::add, Clock.systemUTC(), registry);
        }
    }

    @Value("${local.server.port}")
    int port;

    @Autowired
    RunStore runs;

    @Autowired
    FirstRunWarmup warmup;

    private static List<AuditEvent> action(String action) {
        return EVENTS.stream().filter(e -> e.action().equals(action)).toList();
    }

    private static void awaitEvents(String description, java.util.function.BooleanSupplier ready) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (!ready.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                fail("Timed out waiting for " + description + ": " + EVENTS.stream().map(AuditEvent::action).toList());
            }
            Thread.sleep(25);
        }
    }

    @Test
    void warmUpAndItsSelfRequestAreTheSystemActorAndStayOutOfRunHistory() throws Exception {
        awaitEvents("startup warm-up", () -> !action("warmup.finished").isEmpty()
                && action("run.completed").stream().anyMatch(e -> e.actorType().equals("system")));
        AuditEvent started = action("warmup.started").getFirst();
        AuditEvent finished = action("warmup.finished").getFirst();
        assertEquals("system", started.actorType());
        assertEquals("first-run-warmup", started.actorId());
        assertEquals("job", started.source());
        assertEquals("success", finished.outcome());
        assertNotNull(finished.runId());
        assertTrue(runs.find(finished.runId()).isEmpty(), "warm-up must stay out of run history");
        List<AuditEvent> mine = EVENTS.stream().filter(e -> started.requestId().equals(e.requestId())).toList();
        assertTrue(mine.stream().allMatch(e -> e.actorId().equals("first-run-warmup") && e.source().equals("job")));
        assertEquals(List.of("fault.run_setup", "fault.run_reset"), mine.stream().map(AuditEvent::action)
                .filter(a -> a.startsWith("fault.")).toList());
        assertTrue(mine.stream().anyMatch(e -> e.action().equals("credential.resolved")));
        // the self-request is recognised by the single-use value, not by anything a caller can send
        AuditEvent selfRequest = action("run.completed").stream()
                .filter(e -> e.actorType().equals("system")).findFirst().orElseThrow();
        assertEquals("first-run-warmup", selfRequest.actorId());
        assertEquals("job", selfRequest.source());
        assertEquals(400, selfRequest.metadata().httpStatus());
        assertNull(selfRequest.runId());
        assertEquals(1, action("startup.configuration").size());
    }

    @Test
    void forgedActorSourceAndInternalHeadersStayAnonymousAndAudited() throws Exception {
        int before = action("run.completed").size();
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/runs"))
                        .header("Content-Type", "application/json")
                        .header("X-Actor-Id", "first-run-warmup").header("X-Actor-Type", "system")
                        .header("X-Source", "job").header(InternalRequestToken.HEADER, "guessed-value")
                        .POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode());
        awaitEvents("forged request audit", () -> action("run.completed").size() > before
                && action("run.completed").stream().anyMatch(e -> e.actorType().equals("anonymous")));
        AuditEvent forged = action("run.completed").stream()
                .filter(e -> e.actorType().equals("anonymous")).findFirst().orElseThrow();
        assertNull(forged.actorId());
        assertEquals("http", forged.source());
        assertEquals("missing_input", forged.metadata().reasonCode());
        assertFalse(EVENTS.toString().contains("guessed-value"));
    }

    @Test
    void theInternalValueIsRandomSingleUseAndNeverMatchesAGuess() {
        InternalRequestToken token = new InternalRequestToken();
        assertFalse(token.consume("anything"));
        String first = token.issue();
        assertFalse(token.consume(null));
        assertFalse(token.consume(first + "x"));
        assertTrue(token.consume(first));
        assertFalse(token.consume(first), "a used value no longer matches");
        String second = token.issue();
        assertFalse(second.equals(first));
        assertTrue(UUID.randomUUID().toString().length() < second.length());
    }
}
