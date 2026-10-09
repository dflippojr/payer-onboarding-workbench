package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
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

    private static AuditEvent event(Instant at, String marker) {
        return new AuditEvent(1, UUID.randomUUID(), at, "anonymous", null, "http", "run.requested", "started",
                UUID.randomUUID(), null, "run", marker, null);
    }

    private AuditJournal open(Path dir, AuditJournal.Policy policy, Instant now) throws IOException {
        return AuditJournal.open(dir.toString(), policy, "bench-1", Clock.fixed(now, ZoneOffset.UTC), MAPPER);
    }

    private static List<Path> segments(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".jsonl")).sorted().toList();
        }
    }

    private static String allText(Path dir) throws IOException {
        StringBuilder all = new StringBuilder();
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.toList()) {
                all.append(Files.readString(p));
            }
        }
        return all.toString();
    }

    @Test
    void eventsSurviveANewProcessAndKeepIdsAndTimestamps() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditEvent first = event(NOW, "run-1");
        open(dir, DEFAULT, NOW).append(first);
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
    void sizeCapExpiresOldestFirstAndMayShortenTheWindow() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 500, 1800), NOW);
        for (int i = 0; i < 12; i++) {
            journal.append(event(NOW.plusSeconds(i), "run-" + i));
        }
        long total = 0;
        for (Path p : segments(dir)) {
            total += Files.size(p);
        }
        assertTrue(total <= 1800 + 600, "total stays near the cap, was " + total);
        assertFalse(Files.exists(dir.resolve("audit-000001.jsonl")));
        assertTrue(allText(dir).contains("\"reasonCode\":\"size_cap\""));
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

        assertThrows(IOException.class, () -> AuditJournal.open(tmp.resolve("j").toString(), DEFAULT,
                "bad label!", Clock.systemUTC(), MAPPER));
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
    void auditLogFailsOpenWithWarningAndCounterWhenTheJournalCannotWrite(CapturedOutput output) throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, new AuditJournal.Policy(Duration.ofDays(30), 300, 1_000_000), NOW);
        Files.createDirectory(dir.resolve("manifest.json.tmp"));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = new AuditLog(journal, Clock.fixed(NOW, ZoneOffset.UTC), registry);
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
        AuditLog log = new AuditLog(registry, new WorkbenchProperties(null, null, null, null, null, null,
                new WorkbenchProperties.Audit(dir.toString(), null, null, null, "bench-1")));
        log.lifecycle("startup.configuration", "success", "configuration", null, null);
        assertEquals(1, segments(dir).size());
        assertEquals(1.0, registry.get("workbench.audit.journal.protected").gauge().value());

        SimpleMeterRegistry off = new SimpleMeterRegistry();
        new AuditLog(off, new WorkbenchProperties(null, null, null, null, null)).lifecycle("a", "success", "c", null, null);
        assertThrows(io.micrometer.core.instrument.search.MeterNotFoundException.class,
                () -> off.get("workbench.audit.journal.protected").gauge());
    }

    @Test
    void unsafeConfiguredJournalIsNotProtectedAndTheApplicationKeepsLogging(CapturedOutput output) {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = new AuditLog(registry, new WorkbenchProperties(null, null, null, null, null, null,
                new WorkbenchProperties.Audit("relative/path", null, null, null, null)));
        log.lifecycle("startup.configuration", "success", "configuration", null, null);
        assertEquals(0.0, registry.get("workbench.audit.journal.protected").gauge().value());
        assertEquals(1.0, registry.get("workbench.audit.write.failures").counter().count());
        assertTrue(output.getAll().contains(AuditLog.JOURNAL_WARNING));
        assertFalse(output.getAll().contains("relative/path"));
        assertTrue(output.getAll().contains("audit {"));
    }

    @Test
    void markerValuesNeverAppearBecauseTheSchemaHasNoPayloadFields() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditJournal journal = open(dir, DEFAULT, NOW);
        journal.append(event(NOW, "northwind-synthetic"));
        String text = allText(dir);
        for (String marker : List.of("SYNTHETIC_CLIENT_SECRET", "Bearer ", "MedicationRequest", "Patient/", "SSN")) {
            assertFalse(text.contains(marker));
        }
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
    void retentionAlsoRunsHourlyInsideALongRunningProcess() throws Exception {
        Path dir = tmp.resolve("long");
        MutableClock clock = new MutableClock(NOW);
        AuditJournal journal = AuditJournal.open(dir.toString(),
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
        AuditJournal first = AuditJournal.open(dir.toString(), policy, null, clock, MAPPER);
        for (int i = 0; i < 8; i++) {
            first.append(event(NOW.plusSeconds(i), "x"));
        }
        clock.now = NOW.plus(Duration.ofDays(29));
        AuditJournal second = AuditJournal.open(dir.toString(),
                new AuditJournal.Policy(Duration.ofDays(30), 300, 700), null, clock, MAPPER);
        clock.now = NOW.plus(Duration.ofDays(30)).plusSeconds(3);
        second.append(event(clock.now, "y"));
        assertTrue(allText(dir).contains("age_and_size_cap") || allText(dir).contains("size_cap"));
    }

    @Test
    void aSerializationFailureMidSegmentClosesItAndLaterEventsStillLand() throws Exception {
        Path dir = tmp.resolve("abandon");
        ObjectMapper flaky = new FlakyMapper();
        AuditJournal journal = AuditJournal.open(dir.toString(), DEFAULT, null, Clock.fixed(NOW, ZoneOffset.UTC), flaky);
        journal.append(event(NOW, "one"));
        RuntimeException e = assertThrows(RuntimeException.class, () -> journal.append(event(NOW, "two")));
        assertFalse(String.valueOf(e).contains("SYNTHETIC_SECRET"));
        journal.append(event(NOW, "three"));
        assertEquals(2, segments(dir).size());
        assertTrue(allText(dir).contains("\"targetId\":\"three\""));
    }
}
