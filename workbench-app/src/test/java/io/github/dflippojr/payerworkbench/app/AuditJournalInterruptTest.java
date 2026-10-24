package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Class-level check for #220: every journal operation (open, append, rotation, hourly and expiring
 * retention, close) must behave the same whether or not the calling thread's interrupt flag is set,
 * and must hand the flag back unchanged. Random operation sequences cover paths a single case misses.
 */
class AuditJournalInterruptTest {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    // Small segments force a rotation every few events; the long retention keeps every event until expiry.
    private static final AuditJournal.Policy POLICY = new AuditJournal.Policy(Duration.ofDays(30), 600, 10_000_000);

    @TempDir
    Path tmp;

    private AuditJournal journal;

    @AfterEach
    void release() throws IOException {
        Thread.interrupted();
        if (journal != null) {
            journal.close();
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 2, 3, 4, 5, 6, 7, 8})
    void journalOperationsIgnoreTheCallersInterruptFlagAndKeepIt(long seed) throws Exception {
        Random random = new Random(seed);
        Path dir = tmp.resolve("journal");
        MutableClock clock = new MutableClock(NOW);
        journal = maybeInterrupted(random, () -> AuditJournal.open(dir.toString(), POLICY, null, clock, MAPPER));
        List<UUID> written = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            int op = random.nextInt(10);
            if (op == 0) {
                clock.now = clock.now.plus(Duration.ofMinutes(61 + random.nextInt(60))); // hourly retention runs
            } else if (op == 1) {
                maybeInterrupted(random, () -> {
                    journal.close();
                    return null;
                });
                journal = maybeInterrupted(random,
                        () -> AuditJournal.open(dir.toString(), POLICY, null, clock, MAPPER));
            } else {
                AuditEvent event = event(clock.now, "op-" + i);
                maybeInterrupted(random, () -> {
                    journal.append(event);
                    return null;
                });
                written.add(event.eventId());
            }
        }

        String text = allSegments(dir);
        for (UUID id : written) {
            assertTrue(text.contains(id.toString()), "event " + id + " is in the journal (seed " + seed + ")");
        }
        assertNoEmptySegment(dir);
        assertVerifies(dir);

        // Expiring retention deletes closed segments and records it, from an interrupted thread too.
        clock.now = clock.now.plus(Duration.ofDays(31));
        AuditEvent late = event(clock.now, "after-expiry");
        Thread.currentThread().interrupt();
        try {
            journal.append(late);
        } finally {
            assertTrue(Thread.interrupted(), "the flag survives an append that expires segments");
        }
        String after = allSegments(dir);
        assertTrue(after.contains(late.eventId().toString()));
        assertTrue(after.contains("\"action\":\"audit.retention\""));
        assertFalse(Files.exists(dir.resolve("audit-000001.jsonl")));
        assertNoEmptySegment(dir);
        assertVerifies(dir);
    }

    @FunctionalInterface
    private interface Step<T> {
        T run() throws IOException;
    }

    /** Runs the step with the interrupt flag set half the time, and checks the flag comes back as it went in. */
    private static <T> T maybeInterrupted(Random random, Step<T> step) throws IOException {
        boolean interrupt = random.nextBoolean();
        if (interrupt) {
            Thread.currentThread().interrupt();
        }
        try {
            return step.run();
        } finally {
            assertEquals(interrupt, Thread.interrupted(), "the caller's interrupt flag is unchanged");
        }
    }

    private static AuditEvent event(Instant at, String marker) {
        return new AuditEvent(1, UUID.randomUUID(), at, "anonymous", null, "http", "run.requested", "started",
                UUID.randomUUID(), null, "run", marker, null);
    }

    private static List<Path> segments(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".jsonl")).sorted().toList();
        }
    }

    private static String allSegments(Path dir) throws IOException {
        StringBuilder all = new StringBuilder();
        for (Path p : segments(dir)) {
            all.append(Files.readString(p));
        }
        return all.toString();
    }

    private static void assertNoEmptySegment(Path dir) throws IOException {
        for (Path p : segments(dir)) {
            assertNotEquals(0, Files.size(p), p.getFileName() + " is empty");
        }
    }

    /** The offline reader must find every sealed segment intact; only the active one may be unsealed. */
    private void assertVerifies(Path dir) throws Exception {
        Path script = Path.of("..", "scripts", "audit-reader.mjs").toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(script), "real Node reader must be available");
        Path stdout = Files.createTempFile(tmp, "stdout-", ".txt");
        Path stderr = Files.createTempFile(tmp, "stderr-", ".txt");
        Process process = new ProcessBuilder("node", script.toString(), dir.toString(), "--verify")
                .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "reader must finish");
            assertEquals(0, process.exitValue(), Files.readString(stderr));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "reader must stop");
            }
        }
        int unsealed = 0;
        for (String line : Files.readAllLines(stdout)) {
            JsonNode result = MAPPER.readTree(line);
            String status = result.path("status").asText();
            if (status.equals("unsealed")) {
                unsealed++;
            } else {
                assertEquals("ok", status, line);
            }
        }
        assertTrue(unsealed <= 1, "only the active segment may be unsealed");
    }

    private static final class MutableClock extends Clock {
        Instant now;
        MutableClock(Instant now) { this.now = now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
