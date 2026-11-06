package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/**
 * A segment closed after a failed write is sealed at most twice; when both attempts fail the manifest lists it
 * with a JSON null digest, which survives a restart and which the reader reports like the legacy marker (#323).
 */
class AuditJournalSealRetryTest {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final String FIRST = "audit-000001";

    @TempDir
    Path tmp;

    private static AuditEvent event(String marker) {
        return new AuditEvent(1, UUID.randomUUID(), NOW, "anonymous", null, "http", "run.requested", "started",
                UUID.randomUUID(), null, "run", marker, null);
    }

    /** One event per segment, so the fourth append rotates and writes the manifest. */
    private static AuditJournal.Policy oneLinePerSegment() throws IOException {
        long lineBytes = (MAPPER.writeValueAsString(event("m0")) + "\n").getBytes(StandardCharsets.UTF_8).length;
        return new AuditJournal.Policy(Duration.ofDays(30), lineBytes, 1_000_000);
    }

    /**
     * Segment 1 is closed by a failed write and sealed through {@code source}; segment 2 then rotates, which writes
     * the manifest, and segment 3 stays active.
     */
    private AuditJournal abandonFirstSegment(Path dir, FaultySource source) throws IOException {
        AuditJournal journal = AuditJournal.open(dir.toString(), oneLinePerSegment(), "bench-1",
                Clock.fixed(NOW, ZoneOffset.UTC), new FailSecondWrite(), source);
        try {
            journal.append(event("m1"));
            assertThrows(RuntimeException.class, () -> journal.append(event("m2")));
            journal.append(event("m3"));
            journal.append(event("m4"));
            return journal;
        } catch (RuntimeException | Error e) {
            journal.close();
            throw e;
        }
    }

    private static JsonNode manifestEntry(Path dir, String id) throws IOException {
        for (JsonNode s : MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST))).path("segments")) {
            if (s.path("id").asText().equals(id)) {
                return s;
            }
        }
        return fail(id + " is not in the manifest");
    }

    @Test
    void aSealThatFailsOnceIsRetriedAndTheManifestHoldsTheRealDigest() throws Exception {
        Path dir = tmp.resolve("retry");
        FaultySource source = new FaultySource(FIRST, 1);
        try (AuditJournal journal = abandonFirstSegment(dir, source)) {
            JsonNode entry = manifestEntry(dir, FIRST);
            byte[] bytes = Files.readAllBytes(dir.resolve(FIRST + ".jsonl"));
            String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            assertEquals(expected, entry.path("sha256").asText());
            assertEquals(bytes.length, entry.path("bytes").asLong());
            assertEquals(1, entry.path("events").asLong());
            assertEquals(2, source.attempts.get(), "one failed attempt, then one that succeeds");
        }
    }

    @Test
    void aSealThatFailsTwiceIsListedWithANullDigestAfterExactlyTwoAttempts() throws Exception {
        Path dir = tmp.resolve("null");
        FaultySource source = new FaultySource(FIRST, Integer.MAX_VALUE);
        try (AuditJournal journal = abandonFirstSegment(dir, source)) {
            JsonNode sha = manifestEntry(dir, FIRST).get("sha256");
            assertNotNull(sha, "the entry keeps its sha256 member");
            assertTrue(sha.isNull(), "a JSON null, not the string \"unsealed\" or \"null\": " + sha);
            assertEquals(2, source.attempts.get(), "the seal is attempted at most twice");
            journal.append(event("m5"));
            assertEquals(2, source.attempts.get(), "later rotations do not retry the abandoned segment");
        }
    }

    @Test
    void aNullDigestSurvivesARestartAndTheReaderReportsTheSegmentAsSealFailed() throws Exception {
        Path dir = tmp.resolve("restart");
        abandonFirstSegment(dir, new FaultySource(FIRST, Integer.MAX_VALUE)).close();
        assertThrows(AssertionError.class, () -> manifestEntry(dir, "audit-000003"), "segment 3 is still active");

        // Reopening seals the leftover segment 3 and rewrites the manifest from what it read.
        AuditJournal.open(dir.toString(), oneLinePerSegment(), "bench-1", Clock.fixed(NOW, ZoneOffset.UTC), MAPPER)
                .close();
        assertTrue(manifestEntry(dir, "audit-000003").path("sha256").isTextual(), "the manifest was rewritten");
        JsonNode sha = manifestEntry(dir, FIRST).get("sha256");
        assertTrue(sha.isNull(), "still a JSON null after the restart: " + sha);

        Result verify = reader(dir, "--verify");
        assertEquals(1, verify.exit(), verify.stderr());
        assertEquals(List.of("{\"segment\":\"audit-000001\",\"status\":\"seal_failed\"}",
                "{\"segment\":\"audit-000002\",\"status\":\"ok\"}",
                "{\"segment\":\"audit-000003\",\"status\":\"ok\"}"), verify.stdout().lines().toList());
        assertEquals("Journal segments with problems: 1\n", verify.stderr());
        Result review = reader(dir);
        assertEquals(0, review.exit(), review.stderr());
        assertEquals(3, review.stdout().lines().count(), "review still prints the abandoned segment's event");
    }

    @Test
    void aLegacyUnsealedEntryStillLoadsKeepsItsValueAndIsReportedAsSealFailed() throws Exception {
        Path dir = tmp.resolve("legacy");
        AuditJournal.open(dir.toString(), oneLinePerSegment(), "bench-1", Clock.fixed(NOW, ZoneOffset.UTC), MAPPER)
                .close();
        String line = MAPPER.writeValueAsString(event("m1")) + "\n";
        Files.writeString(dir.resolve(FIRST + ".jsonl"), line);
        Files.writeString(dir.resolve("audit-000002.jsonl"), line);
        Files.writeString(dir.resolve(AuditJournal.MANIFEST), """
                {"version":1,"operatorLabel":"bench-1","segments":[{"id":"audit-000001","file":"audit-000001.jsonl",\
                "bytes":0,"events":0,"firstAt":null,"lastAt":null,"sha256":"unsealed"}]}""");

        AuditJournal.open(dir.toString(), oneLinePerSegment(), "bench-1", Clock.fixed(NOW, ZoneOffset.UTC), MAPPER)
                .close();
        assertTrue(manifestEntry(dir, "audit-000002").path("sha256").isTextual(), "the manifest was rewritten");
        assertEquals("unsealed", manifestEntry(dir, FIRST).path("sha256").textValue());

        Result verify = reader(dir, "--verify");
        assertEquals(1, verify.exit(), verify.stderr());
        assertEquals(List.of("{\"segment\":\"audit-000001\",\"status\":\"seal_failed\"}",
                "{\"segment\":\"audit-000002\",\"status\":\"ok\"}"), verify.stdout().lines().toList());
    }

    /** Fails the first {@code failures} attempts to open {@code target} and counts every attempt on it. */
    private static final class FaultySource implements AuditJournal.SegmentSource {
        private final String target;
        private final int failures;
        final AtomicInteger attempts = new AtomicInteger();

        FaultySource(String id, int failures) {
            this.target = id + ".jsonl";
            this.failures = failures;
        }

        @Override
        public InputStream open(Path segment) throws IOException {
            if (segment.getFileName().toString().equals(target) && attempts.incrementAndGet() <= failures) {
                throw new IOException("injected_seal_failure");
            }
            return Files.newInputStream(segment);
        }
    }

    /** The second event fails to serialize, which closes the active segment as abandoned. */
    private static final class FailSecondWrite extends ObjectMapper {
        private int calls;

        FailSecondWrite() {
            registerModule(new JavaTimeModule());
            disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        }

        @Override
        public String writeValueAsString(Object value) throws JsonProcessingException {
            if (value instanceof AuditEvent && ++calls == 2) {
                throw new JsonProcessingException("injected_write_failure") { };
            }
            return super.writeValueAsString(value);
        }
    }

    private record Result(int exit, String stdout, String stderr) { }

    private Result reader(Path dir, String... options) throws Exception {
        Path script = Path.of("..", "scripts", "audit-reader.mjs").toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(script), "real Node reader must be available");
        List<String> args = new ArrayList<>(List.of("node", script.toString(), dir.toString()));
        args.addAll(List.of(options));
        Path stdout = Files.createTempFile(tmp, "stdout-", ".txt");
        Path stderr = Files.createTempFile(tmp, "stderr-", ".txt");
        Process process = new ProcessBuilder(args).redirectOutput(stdout.toFile())
                .redirectError(stderr.toFile()).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "reader must finish");
            return new Result(process.exitValue(), Files.readString(stdout), Files.readString(stderr));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "reader must stop");
            }
        }
    }
}
