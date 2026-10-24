package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(OutputCaptureExtension.class)
class AuditJournalTest {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final AuditJournal.Policy DEFAULT =
            new AuditJournal.Policy(Duration.ofDays(30), 10L * 1024 * 1024, 100L * 1024 * 1024);

    @TempDir
    Path tmp;

    private final List<AutoCloseable> resources = new java.util.ArrayList<>();

    @AfterEach
    void releaseWriters() throws Exception {
        for (AutoCloseable resource : resources.reversed()) {
            resource.close();
        }
    }

    private AuditJournal openTracked(String dir, AuditJournal.Policy policy, String label,
                                     Clock clock, ObjectMapper mapper) throws IOException {
        AuditJournal journal = AuditJournal.open(dir, policy, label, clock, mapper);
        resources.add(journal);
        return journal;
    }

    private AuditLog track(AuditLog log) {
        resources.add(log::destroy);
        return log;
    }

    private static AuditEvent event(Instant at, String marker) {
        return new AuditEvent(1, UUID.randomUUID(), at, "anonymous", null, "http", "run.requested", "started",
                UUID.randomUUID(), null, "run", marker, null);
    }

    private AuditJournal open(Path dir, AuditJournal.Policy policy, Instant now) throws IOException {
        return openTracked(dir.toString(), policy, "bench-1", Clock.fixed(now, ZoneOffset.UTC), MAPPER);
    }

    private static List<Path> segments(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".jsonl")).sorted().toList();
        }
    }

    private static String allText(Path dir) throws IOException {
        StringBuilder all = new StringBuilder();
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.filter(p -> !p.getFileName().toString().equals(AuditJournal.WRITER_LOCK)).toList()) {
                all.append(Files.readString(p));
            }
        }
        return all.toString();
    }

    @Test
    void openingAnExistingEmptyJournalPreservesItsManifest() throws Exception {
        Path dir = tmp.resolve("journal");
        open(dir, DEFAULT, NOW).close();
        byte[] manifest = Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST));

        openTracked(dir.toString(), DEFAULT, null, Clock.fixed(NOW, ZoneOffset.UTC), MAPPER);

        assertArrayEquals(manifest, Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)));
        assertTrue(segments(dir).isEmpty());
    }

    @Test
    void eventsSurviveAReopenAndKeepIdsAndTimestamps() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditEvent first = event(NOW, "run-1");
        AuditJournal initial = open(dir, DEFAULT, NOW);
        initial.append(first);
        initial.close();
        AuditEvent second = event(NOW.plusSeconds(5), "run-2");
        open(dir, DEFAULT, NOW.plusSeconds(10)).append(second);

        List<Path> files = segments(dir);
        assertEquals(2, files.size(), "a restart seals the old segment and starts a new one");
        JsonNode manifest = MAPPER.readTree(Files.readAllBytes(dir.resolve("manifest.json")));
        assertEquals(1, manifest.path("version").asInt());
        assertEquals("bench-1", manifest.path("operatorLabel").asText());
        assertEquals(64, manifest.path("segments").get(0).path("sha256").asText().length());
        String text = allText(dir);
        assertTrue(text.contains(first.eventId().toString()));
        assertTrue(text.contains(second.eventId().toString()));
        assertTrue(text.contains("\"occurredAt\":\"2026-10-08T12:00:05Z\""));
    }

    @Test
    void rotatesAtTheSegmentSizeAndRecordsEachClosedSegment() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 600, 1_000_000), NOW);
        for (int i = 0; i < 6; i++) {
            journal.append(event(NOW.plusSeconds(i), "run-" + i));
        }
        assertTrue(segments(dir).size() >= 3);
        JsonNode manifest = MAPPER.readTree(Files.readAllBytes(dir.resolve("manifest.json")));
        assertEquals(segments(dir).size() - 1, manifest.path("segments").size(), "the active segment is not sealed");
        for (Path p : segments(dir)) {
            assertTrue(Files.size(p) <= 600 + 10, "segments stay near the cap");
        }
    }

    @Test
    void ageExpiryRemovesOnlyOldClosedSegmentsAndRecordsIt() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal.Policy tiny = new AuditJournal.Policy(Duration.ofDays(30), 600, 1_000_000);
        AuditJournal old = open(dir, tiny, NOW);
        for (int i = 0; i < 4; i++) {
            old.append(event(NOW.plusSeconds(i), "SYNTHETIC_MARKER"));
        }
        List<Path> before = segments(dir);
        old.close();
        AuditJournal later = open(dir, tiny, NOW.plus(Duration.ofDays(31)));
        later.append(event(NOW.plus(Duration.ofDays(31)), "new"));

        assertTrue(segments(dir).stream().noneMatch(before::contains), "every old segment expired");
        String text = allText(dir);
        assertTrue(text.contains("\"action\":\"audit.retention\""));
        assertTrue(text.contains("\"reasonCode\":\"age\""));
        assertTrue(text.contains("\"segmentIds\":[\"audit-000001\""));
        assertFalse(text.contains("SYNTHETIC_MARKER"), "expired record contents are gone and never re-logged");
        JsonNode manifest = MAPPER.readTree(Files.readAllBytes(dir.resolve("manifest.json")));
        for (JsonNode s : manifest.path("segments")) {
            assertFalse(s.path("id").asText().equals("audit-000001"));
        }
    }

    @Test
    void rotationAtTheTotalSizeBoundaryKeepsEverySegment() throws Exception {
        Path dir = tmp.resolve("boundary");
        AuditEvent fixed = event(NOW, "fixed");
        long lineBytes = (MAPPER.writeValueAsString(fixed) + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 2 * lineBytes, 7 * lineBytes), NOW);
        for (int i = 0; i < 7; i++) {
            journal.append(fixed);
        }

        assertEquals(List.of("audit-000001.jsonl", "audit-000002.jsonl", "audit-000003.jsonl", "audit-000004.jsonl"),
                segments(dir).stream().map(p -> p.getFileName().toString()).toList());
        long total = 0;
        for (Path p : segments(dir)) {
            total += Files.size(p);
        }
        assertEquals(7 * lineBytes, total);
        assertFalse(allText(dir).contains("audit.retention"));
    }

    @Test
    void rotationOverTheSizeCapExpiresOnlyTheNecessaryOldestSegment() throws Exception {
        Path dir = tmp.resolve("over-cap");
        AuditEvent fixed = event(NOW, "fixed");
        long lineBytes = (MAPPER.writeValueAsString(fixed) + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 2 * lineBytes, 7 * lineBytes), NOW);
        for (int i = 0; i < 9; i++) {
            journal.append(fixed);
        }

        assertEquals(List.of("audit-000002.jsonl", "audit-000003.jsonl", "audit-000004.jsonl", "audit-000005.jsonl"),
                segments(dir).stream().map(p -> p.getFileName().toString()).toList());
        JsonNode manifest = MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST))).path("segments");
        assertEquals(3, manifest.size());
        for (int i = 0; i < manifest.size(); i++) {
            assertEquals(String.format("audit-%06d", i + 2), manifest.get(i).path("id").asText());
            assertEquals(2 * lineBytes, manifest.get(i).path("bytes").asLong());
            assertEquals(2, manifest.get(i).path("events").asInt());
        }
        List<AuditEvent> retained = new java.util.ArrayList<>();
        for (Path p : segments(dir)) {
            for (String line : Files.readAllLines(p)) {
                retained.add(MAPPER.readValue(line, AuditEvent.class));
            }
        }
        List<AuditEvent> expirations = retained.stream().filter(e -> e.action().equals("audit.retention")).toList();
        assertEquals(1, expirations.size());
        AuditEvent.Metadata metadata = expirations.getFirst().metadata();
        assertEquals("size_cap", metadata.reasonCode());
        assertEquals(AuditEvent.Lifecycle.retention(List.of("audit-000001")), metadata.lifecycle());
        assertEquals(7, retained.stream().filter(fixed::equals).count());
    }

    @Test
    void hourlyRetentionCountsAnAbandonedSegmentOnlyOnce() throws Exception {
        Path dir = tmp.resolve("abandoned-boundary");
        AuditEvent fixed = event(NOW, "fixed");
        long lineBytes = (MAPPER.writeValueAsString(fixed) + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        MutableClock clock = new MutableClock(NOW);
        AuditJournal journal = openTracked(dir.toString(),
                new AuditJournal.Policy(Duration.ofDays(30), 2 * lineBytes, lineBytes), null, clock, new FlakyMapper());
        journal.append(fixed);
        assertThrows(RuntimeException.class, () -> journal.append(fixed));
        clock.now = NOW.plus(Duration.ofHours(2));
        journal.append(fixed);

        assertEquals(List.of("audit-000001.jsonl", "audit-000002.jsonl"),
                segments(dir).stream().map(p -> p.getFileName().toString()).toList());
        assertEquals(lineBytes, Files.size(dir.resolve("audit-000001.jsonl")));
        assertFalse(allText(dir).contains("audit.retention"));
    }

    @Test
    void unsafeSetupIsRejectedWithoutEchoingThePath() throws Exception {
        IOException relative = assertThrows(IOException.class, () -> AuditJournal.prepareDirectory("journal"));
        assertEquals("path_not_absolute", relative.getMessage());

        Path checkout = tmp.resolve("checkout");
        Files.createDirectories(checkout.resolve(".git"));
        IOException inside = assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory(checkout.resolve("audit").toString()));
        assertEquals("inside_checkout", inside.getMessage());

        Path file = tmp.resolve("a-file");
        Files.writeString(file, "x");
        assertEquals("not_a_directory", assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory(file.toString())).getMessage());

        assertThrows(IOException.class, () -> openTracked(tmp.resolve("j").toString(), DEFAULT,
                "bad label!", Clock.systemUTC(), MAPPER));
    }

    /** Two closed segments in the manifest, as a restarted journal leaves them. */
    static void seedTwoClosedSegments(Path dir) throws IOException {
        for (int i = 0; i < 3; i++) {
            try (AuditJournal journal = AuditJournal.open(dir.toString(), DEFAULT, null,
                    Clock.fixed(NOW.plusSeconds(i), ZoneOffset.UTC), MAPPER)) {
                if (i < 2) {
                    journal.append(event(NOW.plusSeconds(i), "seed-" + i));
                }
            }
        }
    }

    /** Every file name in the directory with the SHA-256 of its bytes. */
    static java.util.Map<String, String> fingerprint(Path dir) throws Exception {
        java.util.Map<String, String> files = new java.util.TreeMap<>();
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.toList()) {
                files.put(p.getFileName().toString(), java.util.HexFormat.of().formatHex(
                        java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p))));
            }
        }
        return files;
    }

    @Test
    void nonPositivePolicyIsRefusedBeforeAnyFileIsTouched() throws Exception {
        Path dir = tmp.resolve("journal");
        seedTwoClosedSegments(dir);
        assertEquals(2, MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)))
                .path("segments").size());
        java.util.Map<String, String> before = fingerprint(dir);

        List<AuditJournal.Policy> invalid = List.of(
                new AuditJournal.Policy(Duration.ofDays(-1), DEFAULT.segmentBytes(), DEFAULT.totalBytes()),
                new AuditJournal.Policy(Duration.ZERO, DEFAULT.segmentBytes(), DEFAULT.totalBytes()),
                new AuditJournal.Policy(DEFAULT.retention(), DEFAULT.segmentBytes(), 0),
                new AuditJournal.Policy(DEFAULT.retention(), 0, DEFAULT.totalBytes()),
                new AuditJournal.Policy(DEFAULT.retention(), -1, DEFAULT.totalBytes()),
                new AuditJournal.Policy(DEFAULT.retention(), DEFAULT.segmentBytes(), -1),
                new AuditJournal.Policy(null, DEFAULT.segmentBytes(), DEFAULT.totalBytes()));
        for (AuditJournal.Policy policy : invalid) {
            IOException refused = assertThrows(AuditJournal.UnsafeJournalException.class,
                    () -> open(dir, policy, NOW.plus(Duration.ofDays(1))), policy::toString);
            assertEquals("invalid_policy", refused.getMessage());
            assertEquals(before, fingerprint(dir), "segments and manifest unchanged after " + policy);
        }

        Path fresh = tmp.resolve("never-created");
        assertEquals("invalid_policy", assertThrows(IOException.class, () -> open(fresh,
                new AuditJournal.Policy(Duration.ZERO, 1, 1), NOW)).getMessage());
        assertFalse(Files.exists(fresh), "a refused policy creates no directory");
    }

    @Test
    void worldAccessibleExistingDirectoryIsNotAProtectedJournal() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                Files.getFileStore(tmp).supportsFileAttributeView("posix"));
        Path open = Files.createDirectory(tmp.resolve("open"),
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x")));
        Files.setPosixFilePermissions(open, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        assertEquals("directory_not_owner_only", assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory(open.toString())).getMessage());
    }

    @Test
    void newDirectoryIsCreatedOwnerOnly() throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("fresh").toString());
        assertTrue(Files.isDirectory(dir));
        // a second open validates the same restriction
        assertEquals(dir, AuditJournal.prepareDirectory(dir.toString()));
    }

    @Test
    void unreadableManifestStopsSetupInsteadOfOverwritingHistory() throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("journal").toString());
        Files.writeString(dir.resolve("manifest.json"), "{not json");
        IOException e = assertThrows(IOException.class, () -> open(dir, DEFAULT, NOW));
        assertEquals("manifest_unreadable", e.getMessage());
        assertEquals("{not json", Files.readString(dir.resolve("manifest.json")));
    }

    @Test
    void writeFailureThrowsConstantMessageAndTheNextEventStartsAFreshSegment() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 300, 1_000_000), NOW);
        // A directory where the temporary manifest goes makes the first rotation fail.
        Files.createDirectory(dir.resolve("manifest.json.tmp"));
        journal.append(event(NOW, "SYNTHETIC_SECRET"));
        RuntimeException failure = assertThrows(RuntimeException.class,
                () -> journal.append(event(NOW.plusSeconds(1), "SYNTHETIC_SECRET")));
        assertFalse(String.valueOf(failure).contains("SYNTHETIC_SECRET"));
        assertFalse(String.valueOf(failure.getCause()).contains(tmp.toString()));
        Files.delete(dir.resolve("manifest.json.tmp"));
        journal.append(event(NOW.plusSeconds(2), "after"));
        assertTrue(allText(dir).contains("\"targetId\":\"after\""));
    }

    @Test
    void anEventFromAnInterruptedThreadLandsInTheActiveSegmentAndKeepsTheFlag() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, DEFAULT, NOW);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = track(new AuditLog(journal, Clock.fixed(NOW, ZoneOffset.UTC), registry));
        AuditEvent before = event(NOW, "before-interrupt");
        AuditEvent during = event(NOW, "while-interrupted");
        log.append(before);
        Thread.currentThread().interrupt();
        try {
            log.append(during);
        } finally {
            assertTrue(Thread.interrupted(), "the caller's interrupt flag must survive the append");
        }

        assertEquals(List.of(dir.resolve("audit-000001.jsonl")), segments(dir), "no extra or empty segment");
        String active = Files.readString(dir.resolve("audit-000001.jsonl"));
        assertTrue(active.contains(before.eventId().toString()));
        assertTrue(active.contains(during.eventId().toString()));
        assertEquals(0, MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)))
                .path("segments").size(), "the active segment is not sealed");
        assertEquals(0, registry.get("workbench.audit.write.failures").counter().count());
    }

    @Test
    void auditLogFailsOpenWithWarningAndCounterWhenTheJournalCannotWrite(CapturedOutput output) throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 300, 1_000_000), NOW);
        Files.createDirectory(dir.resolve("manifest.json.tmp"));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = track(new AuditLog(journal, Clock.fixed(NOW, ZoneOffset.UTC), registry));
        log.append(event(NOW, "one"));
        log.append(event(NOW, "two"));
        log.append(event(NOW, "three"));
        assertTrue(registry.get("workbench.audit.write.failures").counter().count() >= 1);
        assertTrue(output.getAll().contains(AuditLog.WARNING));
    }

    @Test
    void springWiringCreatesTheJournalAndStaysOffWhenUnconfigured() throws Exception {
        Path dir = tmp.resolve("wired");
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = track(new AuditLog(registry, new WorkbenchProperties(null, null, null, null, null, null,
                new WorkbenchProperties.Audit(dir.toString(), null, null, null, "bench-1"))));
        log.lifecycle("startup.configuration", "success", "configuration", null, null);
        assertEquals(1, segments(dir).size());
        assertEquals(1.0, registry.get("workbench.audit.journal.protected").gauge().value());

        SimpleMeterRegistry off = new SimpleMeterRegistry();
        track(new AuditLog(off, new WorkbenchProperties(null, null, null, null, null))).lifecycle("a", "success", "c", null, null);
        assertThrows(io.micrometer.core.instrument.search.MeterNotFoundException.class,
                () -> off.get("workbench.audit.journal.protected").gauge());
    }

    @Test
    void unsafeConfiguredJournalIsNotProtectedAndTheApplicationKeepsLogging(CapturedOutput output) {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = track(new AuditLog(registry, new WorkbenchProperties(null, null, null, null, null, null,
                new WorkbenchProperties.Audit("relative/path", null, null, null, null))));
        log.lifecycle("startup.configuration", "success", "configuration", null, null);
        assertEquals(0.0, registry.get("workbench.audit.journal.protected").gauge().value());
        assertEquals(1.0, registry.get("workbench.audit.write.failures").counter().count());
        assertTrue(output.getAll().contains(AuditLog.JOURNAL_WARNING));
        assertFalse(output.getAll().contains("relative/path"));
        assertTrue(output.getAll().contains("audit {"));
    }

    @Test
    void initialManifestFailureKeepsLoggingWithSafeWarningAndCounter(CapturedOutput output) throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("SYNTHETIC_PRIVATE_PATH").toString());
        Files.createDirectory(dir.resolve("manifest.json.tmp"));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = track(new AuditLog(registry, new WorkbenchProperties(null, null, null, null, null, null,
                new WorkbenchProperties.Audit(dir.toString(), null, null, null, "bench-1"))));
        log.lifecycle("startup.configuration", "success", "configuration", null, null);

        assertEquals(0.0, registry.get("workbench.audit.journal.protected").gauge().value());
        assertEquals(1.0, registry.get("workbench.audit.write.failures").counter().count());
        assertTrue(output.getAll().contains(AuditLog.JOURNAL_WARNING));
        assertTrue(output.getAll().contains("audit {"));
        assertFalse(output.getAll().contains(dir.toString()));
        assertFalse(output.getAll().contains("SYNTHETIC_PRIVATE_PATH"));
        assertFalse(output.getAll().contains("manifest.json.tmp"));
        assertTrue(segments(dir).isEmpty());
        assertFalse(Files.exists(dir.resolve(AuditJournal.MANIFEST)));
    }

    private static final class MutableClock extends Clock {
        Instant now;
        MutableClock(Instant now) { this.now = now; }
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    /** Serializes normally except for its second event. */
    private static final class FlakyMapper extends ObjectMapper {
        private int calls;

        FlakyMapper() {
            registerModule(new JavaTimeModule());
            disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        }

        @Override
        public String writeValueAsString(Object value) throws com.fasterxml.jackson.core.JsonProcessingException {
            if (++calls == 2) {
                throw new com.fasterxml.jackson.core.JsonProcessingException("SYNTHETIC_SECRET") { };
            }
            return super.writeValueAsString(value);
        }
    }

    @Test
    void invalidAndLinkedPathsAreRejected() throws Exception {
        assertEquals("invalid_path", assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory("bad\u0000path")).getMessage());
        Path real = AuditJournal.prepareDirectory(tmp.resolve("real").toString());
        Path link = tmp.resolve("link");
        try {
            Files.createSymbolicLink(link, real);
        } catch (IOException | UnsupportedOperationException e) {
            org.junit.jupiter.api.Assumptions.abort("symbolic links unavailable");
        }
        assertEquals("path_is_link", assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory(link.toString())).getMessage());
    }

    @Test
    void unsupportedOrForgedManifestsAreRejected() throws Exception {
        for (String body : List.of("{\"version\":2,\"segments\":[]}",
                "{\"version\":1,\"segments\":[{\"id\":\"../evil\",\"sha256\":\"x\"}]}")) {
            Path dir = AuditJournal.prepareDirectory(tmp.resolve("j" + body.length()).toString());
            Files.writeString(dir.resolve("manifest.json"), body);
            assertEquals("manifest_unreadable", assertThrows(IOException.class,
                    () -> open(dir, DEFAULT, NOW)).getMessage());
        }
    }

    @Test
    void leftoverSegmentsAreSealedWithCountsAndDamagedLinesAreNotCounted() throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("crash").toString());
        String good = MAPPER.writeValueAsString(event(NOW, "a"));
        String nl = String.valueOf((char) 10);
        Files.writeString(dir.resolve("audit-000004.jsonl"), good + nl + "{not json" + nl + "{\"noTime\":1}" + nl
                + MAPPER.writeValueAsString(event(NOW.plusSeconds(9), "b")) + nl + "{\"truncated\":\"");
        AuditJournal journal = open(dir, DEFAULT, NOW.plusSeconds(60));
        JsonNode segment = MAPPER.readTree(Files.readAllBytes(dir.resolve("manifest.json"))).path("segments").get(0);
        assertEquals("audit-000004", segment.path("id").asText());
        assertEquals(2, segment.path("events").asInt());
        assertEquals("2026-10-08T12:00:00Z", segment.path("firstAt").asText());
        assertEquals("2026-10-08T12:00:09Z", segment.path("lastAt").asText());
        journal.append(event(NOW.plusSeconds(61), "next"));
        assertTrue(Files.exists(dir.resolve("audit-000005.jsonl")), "numbering continues after what was found");
    }

    @Test
    void manifestBoundsOrderAWholeSecondBeforeItsFractionOfThatSecond() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, DEFAULT, NOW);
        journal.append(event(NOW, "whole"));
        journal.append(event(NOW.plusMillis(500), "fraction"));
        journal.close();
        open(dir, DEFAULT, NOW.plusSeconds(10)).close();

        JsonNode segment = MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)))
                .path("segments").get(0);
        assertEquals("2026-10-08T12:00:00Z", segment.path("firstAt").asText());
        assertEquals("2026-10-08T12:00:00.500Z", segment.path("lastAt").asText());
    }

    @Test
    void retentionAlsoRunsHourlyInsideALongRunningProcess() throws Exception {
        Path dir = tmp.resolve("long");
        MutableClock clock = new MutableClock(NOW);
        AuditJournal journal = openTracked(dir.toString(),
                new AuditJournal.Policy(Duration.ofDays(30), 300, 1_000_000), null, clock, MAPPER);
        for (int i = 0; i < 4; i++) {
            journal.append(event(NOW.plusSeconds(i), "old"));
        }
        assertTrue(Files.exists(dir.resolve("audit-000001.jsonl")));
        clock.now = NOW.plus(Duration.ofDays(31));
        journal.append(event(clock.now, "new"));
        assertFalse(Files.exists(dir.resolve("audit-000001.jsonl")));
        assertTrue(allText(dir).contains("\"reasonCode\":\"age\""));
    }

    @Test
    void ageAndSizeCapCanBothApplyInOnePass() throws Exception {
        Path dir = tmp.resolve("both");
        MutableClock clock = new MutableClock(NOW);
        AuditJournal.Policy policy = new AuditJournal.Policy(Duration.ofDays(30), 300, 1_000_000);
        AuditJournal first = openTracked(dir.toString(), policy, null, clock, MAPPER);
        for (int i = 0; i < 8; i++) {
            first.append(event(NOW.plusSeconds(i), "x"));
        }
        first.close();
        clock.now = NOW.plus(Duration.ofDays(30)).plusSeconds(3);
        AuditJournal second = openTracked(dir.toString(),
                new AuditJournal.Policy(Duration.ofDays(30), 300, 1000), null, clock, MAPPER);
        second.append(event(clock.now, "y"));

        // Segments 1-3 end before the age cutoff; 4-5 are then the oldest over the total size cap.
        List<AuditEvent> expirations = new java.util.ArrayList<>();
        for (Path p : segments(dir)) {
            for (String line : Files.readAllLines(p)) {
                AuditEvent logged = MAPPER.readValue(line, AuditEvent.class);
                if (logged.action().equals("audit.retention")) {
                    expirations.add(logged);
                }
            }
        }
        // Writing that event rotates the segment, so a later pass may expire more by size; the first pass is the one under test.
        List<AuditEvent> combined = expirations.stream()
                .filter(e -> e.metadata().reasonCode().equals("age_and_size_cap")).toList();
        assertEquals(1, combined.size(), expirations.toString());
        assertEquals(AuditEvent.Lifecycle.retention(List.of("audit-000001", "audit-000002", "audit-000003",
                "audit-000004", "audit-000005")), combined.getFirst().metadata().lifecycle());
        assertFalse(Files.exists(dir.resolve("audit-000005.jsonl")));
    }

    @Test
    void aSerializationFailureMidSegmentClosesItAndLaterEventsStillLand() throws Exception {
        Path dir = tmp.resolve("abandon");
        ObjectMapper flaky = new FlakyMapper();
        AuditJournal journal = openTracked(dir.toString(), DEFAULT, null, Clock.fixed(NOW, ZoneOffset.UTC), flaky);
        journal.append(event(NOW, "one"));
        RuntimeException e = assertThrows(RuntimeException.class, () -> journal.append(event(NOW, "two")));
        assertFalse(String.valueOf(e).contains("SYNTHETIC_SECRET"));
        journal.append(event(NOW, "three"));
        assertEquals(2, segments(dir).size());
        assertTrue(allText(dir).contains("\"targetId\":\"three\""));
    }
}
