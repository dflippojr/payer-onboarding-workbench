package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class AuditJournalReaderTest {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00.123456789Z");
    private static final String LABEL = "bench-1";
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final AuditEvent EVENT = new AuditEvent(1,
            UUID.fromString("00000000-0000-4000-8000-000000000094"), NOW, "anonymous", null,
            "http", "run.requested", "started",
            UUID.fromString("00000000-0000-4000-8000-000000000095"),
            "00000000-0000-4000-8000-000000000096", "run", "synthetic-run", null);

    @TempDir
    Path tmp;

    @Test
    void stoppedFreshEmptyJournalCanBeReviewedAndVerified() throws Exception {
        Path dir = writeFreshJournal(false);
        assertEquals("", reader(dir).stdout());
        assertEquals("", reader(dir, "--verify").stdout());
        try (var files = Files.list(dir)) {
            assertEquals(List.of(AuditJournal.MANIFEST),
                    files.map(p -> p.getFileName().toString()).toList());
        }
    }

    @Test
    void stoppedFreshJournalPreservesTheEventAndLeavesItsSegmentUnsealed() throws Exception {
        Path dir = writeFreshJournal(true);
        String output = reader(dir).stdout();
        assertEquals(MAPPER.valueToTree(EVENT), MAPPER.readTree(output));
        assertFalse(output.contains("operatorLabel"));
        assertFalse(output.contains(LABEL));
        assertEquals(MAPPER.readTree(output), MAPPER.readTree(reader(dir, "--run", EVENT.runId(),
                "--since", NOW.toString(), "--until", NOW.toString()).stdout()));
        assertEquals("", reader(dir, "--run", UUID.randomUUID().toString()).stdout());
        JsonNode verification = MAPPER.readTree(reader(dir, "--verify").stdout());
        assertEquals("audit-000001", verification.path("segment").asText());
        assertEquals("unsealed", verification.path("status").asText());
        try (var files = Files.list(dir)) {
            assertEquals(List.of("audit-000001.jsonl", AuditJournal.MANIFEST),
                    files.map(p -> p.getFileName().toString()).sorted().toList());
        }
        assertEquals(0, manifest(dir).path("segments").size());
    }

    private Path writeFreshJournal(boolean append) throws Exception {
        Path dir = tmp.resolve("journal");
        String java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString();
        // A separate writer exits before review, releasing the active channel without reopening or sealing it.
        command(List.of(java, "-cp", System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path")), Writer.class.getName(), dir.toString(),
                Boolean.toString(append)));
        JsonNode manifest = manifest(dir);
        assertEquals(1, manifest.path("version").asInt());
        assertEquals(LABEL, manifest.path("operatorLabel").asText());
        assertTrue(manifest.path("segments").isArray());
        assertEquals(0, manifest.path("segments").size());
        return dir;
    }

    private JsonNode manifest(Path dir) throws Exception {
        return MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)));
    }

    private Result reader(Path dir, String... options) throws Exception {
        Path script = Path.of("..", "scripts", "audit-reader.mjs").toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(script), "real Node reader must be available");
        List<String> args = new ArrayList<>(List.of("node", script.toString(), dir.toString()));
        args.addAll(List.of(options));
        return command(args);
    }

    private record Result(String stdout, String stderr) { }

    private Result command(List<String> args) throws Exception {
        Path stdout = Files.createTempFile(tmp, "stdout-", ".txt");
        Path stderr = Files.createTempFile(tmp, "stderr-", ".txt");
        Process process = new ProcessBuilder(args).redirectOutput(stdout.toFile())
                .redirectError(stderr.toFile()).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "subprocess must finish");
            Result result = new Result(Files.readString(stdout), Files.readString(stderr));
            assertEquals(0, process.exitValue(), result.stderr());
            assertEquals("", result.stderr());
            return result;
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "subprocess must stop");
            }
        }
    }

    /** Real Java writer, with default retention and size policy and no application server. */
    public static final class Writer {
        private Writer() { }

        public static void main(String[] args) throws Exception {
            AuditJournal journal = AuditJournal.open(args[0],
                    new AuditJournal.Policy(Duration.ofDays(30), 10L * 1024 * 1024, 100L * 1024 * 1024),
                    LABEL, Clock.fixed(NOW, ZoneOffset.UTC), MAPPER);
            if (Boolean.parseBoolean(args[1])) {
                journal.append(EVENT);
            }
        }
    }
}
