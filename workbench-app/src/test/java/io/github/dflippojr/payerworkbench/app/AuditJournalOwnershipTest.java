package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@ExtendWith(OutputCaptureExtension.class)
class AuditJournalOwnershipTest {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final AuditJournal.Policy POLICY =
            new AuditJournal.Policy(Duration.ofDays(30), 10L * 1024 * 1024, 100L * 1024 * 1024);

    @TempDir
    Path tmp;

    private static AuditJournal open(Path dir) throws IOException {
        return AuditJournal.open(dir.toString(), POLICY, "bench-1", Clock.systemUTC(), MAPPER);
    }

    private static AuditEvent event(String marker) {
        return new AuditEvent(1, UUID.randomUUID(), Instant.now(), "anonymous", null, "http",
                "run.requested", "started", UUID.randomUUID(), null, "run", marker, null);
    }

    private static void assertSealedIntact(Path dir, int events) throws Exception {
        var segment = MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)))
                .path("segments").get(0);
        assertEquals(events, segment.path("events").asInt());
        byte[] bytes = Files.readAllBytes(dir.resolve(segment.path("file").asText()));
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                segment.path("sha256").asText());
    }

    @Test
    void sameJvmContenderCannotSealOrExpireTheLiveWritersFiles() throws Exception {
        Path dir = tmp.resolve("journal");
        AuditEvent first = event("first");
        AuditEvent next = event("next");
        AuditJournal writer = open(dir);
        try (writer) {
            writer.append(first);
            byte[] manifest = Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST));
            byte[] segment = Files.readAllBytes(dir.resolve("audit-000001.jsonl"));
            // The most destructive policy open accepts: it would expire every closed segment at once.
            var destructivePolicy = new AuditJournal.Policy(Duration.ofNanos(1), 1, 1);
            IOException busy = assertThrows(IOException.class, () -> AuditJournal.open(dir.toString(),
                    destructivePolicy, null, Clock.systemUTC(), MAPPER));
            assertEquals("journal_busy", busy.getMessage());
            assertNull(busy.getCause());
            assertArrayEquals(manifest, Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)));
            assertArrayEquals(segment, Files.readAllBytes(dir.resolve("audit-000001.jsonl")));
            writer.append(next);
        }
        byte[] afterClose = Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST));
        assertEquals(0, MAPPER.readTree(afterClose).path("segments").size());
        writer.close();
        assertThrows(RuntimeException.class, () -> writer.append(event("closed")));
        assertArrayEquals(afterClose, Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)));
        try (AuditJournal reopened = open(dir)) {
            assertSealedIntact(dir, 2);
            reopened.append(event("reopened"));
            assertEquals(List.of(first, next), Files.readAllLines(dir.resolve("audit-000001.jsonl")).stream()
                    .map(line -> {
                        try {
                            return MAPPER.readValue(line, AuditEvent.class);
                        } catch (IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    }).toList());
            // Closing the old instance again cannot release the new writer's lock.
            writer.close();
            assertThrows(IOException.class, () -> open(dir));
        }
    }

    @Test
    void separateProcessIsRejectedThenCanAdoptAfterTheOwnerCloses() throws Exception {
        Path dir = tmp.resolve("process");
        try (AuditJournal writer = open(dir)) {
            writer.append(event("before"));
            byte[] manifest = Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST));
            // A rejected same-JVM opener must not inadvertently release the owner's OS lock.
            assertThrows(IOException.class, () -> open(dir));
            assertEquals("journal_busy", child(dir, "busy"));
            assertArrayEquals(manifest, Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)));
            writer.append(event("after"));
        }
        assertEquals("opened", child(dir, "open"));
        try (AuditJournal reopened = open(dir)) {
            assertSealedIntact(dir, 2);
            var segments = MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST))).path("segments");
            assertEquals(2, segments.size());
            assertEquals(1, segments.get(1).path("events").asInt());
            reopened.append(event("parent-reopened"));
        }
    }

    private Path link(Path link, Path target) throws IOException {
        try {
            return Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symbolic links unavailable");
            return link;
        }
    }

    private static String verdict(Path dir) {
        try {
            AuditJournal.prepareDirectory(dir.toString());
            return "accepted";
        } catch (IOException e) {
            return e.getMessage();
        }
    }

    @Test
    void symlinkedParentIntoACheckoutIsRefusedAndLeavesNoFiles() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("checkout"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path audit = Files.createDirectories(checkout.resolve(".tmp/audit"));
        Path alias = link(Files.createDirectory(tmp.resolve("scratch")).resolve("alias"), audit);

        IOException refused = assertThrows(IOException.class, () -> open(alias.resolve("j1")));
        assertEquals("inside_checkout", refused.getMessage());
        try (var left = Files.list(audit)) {
            assertEquals(List.of(), left.toList());
        }
    }

    @Test
    void symlinkedParentOutsideAnyCheckoutIsAccepted() throws Exception {
        Path real = Files.createDirectory(tmp.resolve("outside"));
        Path alias = link(tmp.resolve("outside-alias"), real);
        try (AuditJournal journal = open(alias.resolve("j1"))) {
            journal.append(event("through-alias"));
        }
        assertTrue(Files.exists(real.resolve("j1").resolve(AuditJournal.MANIFEST)));
        assertEquals(real.toRealPath().resolve("j1"), AuditJournal.prepareDirectory(alias.resolve("j1").toString()));
    }

    @Test
    void relinkingTheAliasAfterOpenCannotMoveWritesOrDeletesIntoACheckout() throws Exception {
        Path outside = Files.createDirectory(tmp.resolve("release-1"));
        Path checkout = Files.createDirectories(tmp.resolve("relinked"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path decoys = Files.createDirectory(checkout.resolve("j1"));
        Files.writeString(decoys.resolve("audit-000001.jsonl"), "decoy\n");
        Path current = link(tmp.resolve("current"), outside);
        // Every append rotates, and the size cap expires closed segments by name at each rotation.
        var policy = new AuditJournal.Policy(Duration.ofDays(30), 1, 1);
        try (AuditJournal journal = AuditJournal.open(current.resolve("j1").toString(), policy, null,
                Clock.systemUTC(), MAPPER)) {
            journal.append(event("before-relink"));
            Files.delete(current);
            link(current, checkout);
            journal.append(event("after-relink"));
            journal.append(event("after-rotation"));
        }
        try (var left = Files.list(decoys)) {
            assertEquals(List.of(decoys.resolve("audit-000001.jsonl")), left.toList());
        }
        assertEquals("decoy\n", Files.readString(decoys.resolve("audit-000001.jsonl")));
        assertTrue(Files.exists(outside.resolve("j1").resolve(AuditJournal.MANIFEST)));
    }

    @Test
    void realPathRecheckRemovesOnlyEmptyDirectoriesThisOpenerMade() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("swapped"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path made = Files.createDirectories(checkout.resolve("made/inner")).toRealPath();
        Path busy = Files.createDirectories(checkout.resolve("busy/inner")).toRealPath();
        Files.writeString(busy.resolveSibling("other"), "not ours");
        Path found = Files.createDirectory(checkout.resolve("found"));

        List<Path> madePaths = List.of(made.getParent(), made);
        List<Path> busyPaths = List.of(busy.getParent(), busy);

        assertEquals("inside_checkout", assertThrows(IOException.class,
                () -> AuditJournal.recheckRealPath(made, madePaths)).getMessage());
        assertFalse(Files.exists(checkout.resolve("made")));
        assertEquals("inside_checkout", assertThrows(IOException.class,
                () -> AuditJournal.recheckRealPath(busy, busyPaths)).getMessage());
        assertFalse(Files.exists(busy));
        assertTrue(Files.exists(busy.resolveSibling("other")));
        assertEquals("inside_checkout", assertThrows(IOException.class,
                () -> AuditJournal.recheckRealPath(found, List.of())).getMessage());
        assertTrue(Files.isDirectory(found));
        Path clean = Files.createDirectory(tmp.resolve("clean"));
        assertEquals(clean.toRealPath(), AuditJournal.recheckRealPath(clean, List.of(clean.toRealPath())));
        assertTrue(Files.isDirectory(clean));
    }

    @Test
    void ancestorSwappedIntoACheckoutDuringCreationIsRefusedAndCleanupNeverReachesIntoIt() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("raced"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path scratch = Files.createDirectory(tmp.resolve("scratch-race"));
        link(tmp.resolve("probe"), scratch);
        Path parent = scratch.resolve("parent");

        // Both directories are made outside any checkout; the race then moves them in behind a link.
        AuditJournal.Interleave race = (stage, dir) -> {
            if (stage == AuditJournal.Interleave.Stage.AFTER_CREATE) {
                Files.move(parent, checkout.resolve("parent"));
                Files.createSymbolicLink(parent, checkout.resolve("parent"));
            }
        };
        String journal = parent.resolve("j1").toString();
        IOException refused = assertThrows(IOException.class, () -> AuditJournal.prepareDirectory(journal, race));
        assertEquals("inside_checkout", refused.getMessage());
        // Cleanup removes only what is still where it was made, so every platform leaves the moved pair as is.
        try (var left = Files.list(checkout)) {
            assertEquals(List.of(checkout.resolve("parent"), checkout.resolve("pom.xml")), left.sorted().toList());
        }
        assertTrue(Files.isDirectory(checkout.resolve("parent/j1")));
    }

    @Test
    void levelSwappedForALinkRightAfterItIsMadeCannotGetACheckoutDirectoryRemoved() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("swap-checkout"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path theirs = Files.createDirectory(checkout.resolve("parent"));
        Path scratch = Files.createDirectory(tmp.resolve("scratch-swap"));
        link(tmp.resolve("probe-swap"), scratch);
        Path parent = scratch.resolve("parent");

        // Right after parent is made, it becomes a link to the checkout's own empty directory of that name.
        AuditJournal.Interleave race = (stage, dir) -> {
            if (stage == AuditJournal.Interleave.Stage.CREATED && dir.getFileName().toString().equals("parent")) {
                Files.delete(parent);
                Files.createSymbolicLink(parent, theirs);
            }
        };
        String journal = parent.resolve("j1").toString();
        IOException refused = assertThrows(IOException.class, () -> AuditJournal.prepareDirectory(journal, race));
        assertEquals("inside_checkout", refused.getMessage());
        assertTrue(Files.isDirectory(theirs));
    }

    @Test
    void aliasRepointedBeforeCreationCannotRedirectCreationOrCleanup() throws Exception {
        Path outside = Files.createDirectory(tmp.resolve("before-1"));
        Path checkout = Files.createDirectories(tmp.resolve("before-checkout"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path theirs = Files.createDirectory(checkout.resolve("parent"));
        Path current = link(tmp.resolve("before-current"), outside);

        // The guard judged outside; a re-point after that must not create in, or clean up, the checkout.
        Path dir = AuditJournal.prepareDirectory(current.resolve("parent/j1").toString(), (stage, d) -> {
            if (stage == AuditJournal.Interleave.Stage.BEFORE_CREATE) {
                Files.delete(current);
                Files.createSymbolicLink(current, checkout);
            }
        });
        assertEquals(outside.toRealPath().resolve("parent/j1"), dir);
        assertTrue(Files.isDirectory(theirs));
        try (var left = Files.list(theirs)) {
            assertEquals(List.of(), left.toList());
        }
    }

    @Test
    void cleanupAfterARefusalNeverRemovesDirectoriesItDidNotMake() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("theirs-checkout"));
        Files.writeString(checkout.resolve("pom.xml"), "<project/>");
        Path theirs = Files.createDirectories(checkout.resolve("parent/j1"));
        Path scratch = Files.createDirectory(tmp.resolve("scratch-theirs"));
        link(tmp.resolve("probe-theirs"), scratch);
        Path parent = scratch.resolve("parent");

        // The directories this opener made move away; empty look-alikes in a checkout take their place.
        AuditJournal.Interleave race = (stage, dir) -> {
            if (stage == AuditJournal.Interleave.Stage.AFTER_CREATE) {
                Files.move(parent, tmp.resolve("moved-away"));
                Files.createSymbolicLink(parent, checkout.resolve("parent"));
            }
        };
        String journal = parent.resolve("j1").toString();
        IOException refused = assertThrows(IOException.class, () -> AuditJournal.prepareDirectory(journal, race));
        assertEquals("inside_checkout", refused.getMessage());
        assertTrue(Files.isDirectory(theirs));
    }

    @Test
    void cleanupAfterARefusalNeverDeletesAFileLeftAtAPathItMade() throws Exception {
        Path scratch = Files.createDirectory(tmp.resolve("scratch-file"));
        Path parent = scratch.resolve("parent");

        // The made pair moves away; a checkout with a file of the leaf's name takes its place. No links needed.
        AuditJournal.Interleave race = (stage, dir) -> {
            if (stage == AuditJournal.Interleave.Stage.AFTER_CREATE) {
                Files.move(parent, tmp.resolve("moved-file"));
                Files.createDirectory(parent);
                Files.writeString(parent.resolve("pom.xml"), "<project/>");
                Files.writeString(parent.resolve("j1"), "theirs");
            }
        };
        String journal = parent.resolve("j1").toString();
        IOException refused = assertThrows(IOException.class, () -> AuditJournal.prepareDirectory(journal, race));
        assertEquals("inside_checkout", refused.getMessage());
        assertEquals("theirs", Files.readString(parent.resolve("j1")));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void missingRootIsRefusedWithAReason() throws Exception {
        Path absent = null;
        for (char drive = 'Z'; drive >= 'D' && absent == null; drive--) {
            Path root = Path.of(drive + ":\\");
            absent = Files.exists(root) ? null : root;
        }
        assumeTrue(absent != null, "every drive letter is in use");
        String journal = absent.resolve("nodrive").resolve("j1").toString();
        assertEquals("invalid_path", assertThrows(IOException.class,
                () -> AuditJournal.prepareDirectory(journal)).getMessage());
    }

    /** Class-level check: the checkout guard judges where a path lands, so no alias changes its verdict. */
    @Test
    void checkoutVerdictIsTheSameThroughEveryAlias() throws Exception {
        Path checkout = Files.createDirectories(tmp.resolve("repo"));
        Files.createDirectory(checkout.resolve(".git"));
        Path deep = Files.createDirectories(checkout.resolve("a/b"));
        Path outside = Files.createDirectory(tmp.resolve("elsewhere"));
        Path aliases = Files.createDirectory(tmp.resolve("aliases"));
        Path chained = link(aliases.resolve("chain"), link(aliases.resolve("to-deep"), deep));
        List<Path[]> shapes = List.of(
                new Path[] {checkout, link(aliases.resolve("to-root"), checkout)},
                new Path[] {deep, aliases.resolve("to-deep")},
                new Path[] {deep, chained},
                new Path[] {deep.resolve("c"), link(aliases.resolve("to-a"), checkout.resolve("a"))
                        .resolve("b/c")},
                new Path[] {outside, link(aliases.resolve("to-outside"), outside)});
        int n = 0;
        for (Path[] shape : shapes) {
            String direct = verdict(shape[0].resolve("direct-" + n));
            String aliased = verdict(shape[1].resolve("aliased-" + n));
            assertEquals(direct, aliased, "alias " + shape[1] + " of " + shape[0]);
            n++;
        }
        assertEquals("accepted", verdict(outside.resolve("again")));
        assertEquals("inside_checkout", verdict(deep.resolve("again")));
    }

    @Test
    void aliasedPathIsRejectedWithoutReleasingTheOwnersLock() throws Exception {
        Path real = Files.createDirectory(tmp.resolve("real"));
        Path alias = tmp.resolve("alias");
        try {
            Files.createSymbolicLink(alias, real);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symbolic links unavailable");
        }
        Path dir = real.resolve("journal");
        try (AuditJournal writer = open(dir)) {
            writer.append(event("owner"));
            Path aliased = alias.resolve("journal");
            assertEquals(AuditJournal.ownershipKey(dir), AuditJournal.ownershipKey(aliased));
            IOException busy = assertThrows(IOException.class, () -> open(aliased));
            assertEquals("journal_busy", busy.getMessage());
            assertEquals("journal_busy", child(dir, "busy"));
            writer.append(event("still-owner"));
        }
        assertEquals("opened", child(dir, "open"));
    }

    @Test
    void overlappingLockIsTreatedAsHeldAndItsChannelIsNeverClosed() throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("overlap").toString());
        // An owner this JVM's reservation cannot see, such as another classloader or an unmerged alias.
        try (FileChannel owner = FileChannel.open(dir.resolve(AuditJournal.WRITER_LOCK),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock lock = owner.lock()) {
            IOException busy = assertThrows(IOException.class, () -> open(dir));
            assertEquals("journal_busy", busy.getMessage());
            System.gc();
            assertTrue(lock.isValid());
            // Under POSIX fcntl semantics closing the contender's channel would have dropped this lock.
            assertEquals("journal_busy", child(dir, "busy"));
        }
    }

    private String child(Path dir, String mode) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString();
        Path output = tmp.resolve("child-" + mode + ".txt");
        Process child = new ProcessBuilder(java, "-cp", System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path")), Contender.class.getName(), dir.toString(), mode)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(child.waitFor(30, TimeUnit.SECONDS), "child must finish");
            assertEquals(0, child.exitValue(), Files.readString(output));
            return Files.readString(output).strip();
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                assertTrue(child.waitFor(10, TimeUnit.SECONDS), "child must stop");
            }
        }
    }

    public static final class Contender {
        private Contender() { }

        public static void main(String[] args) throws Exception {
            Path dir = Path.of(args[0]);
            if (args[1].equals("busy")) {
                try (AuditJournal unexpected = open(dir)) {
                    unexpected.append(event("unexpected"));
                    throw new IllegalStateException("competing writer accepted");
                } catch (AuditJournal.UnsafeJournalException e) {
                    if (!e.getMessage().equals("journal_busy")) {
                        throw e;
                    }
                    System.out.println(e.getMessage());
                }
            } else {
                try (AuditJournal journal = open(dir)) {
                    journal.append(event("child"));
                }
                System.out.println("opened");
            }
        }
    }

    @Test
    void failedInitializationReleasesOwnershipForTheNextOpen() throws Exception {
        Path dir = AuditJournal.prepareDirectory(tmp.resolve("failed").toString());
        Files.createDirectory(dir.resolve(AuditJournal.MANIFEST + ".tmp"));
        assertThrows(IOException.class, () -> open(dir));
        Files.delete(dir.resolve(AuditJournal.MANIFEST + ".tmp"));
        try (AuditJournal journal = open(dir)) {
            journal.append(event("recovered"));
        }
        // An unchecked failure after adoption must also release ownership.
        Clock failing = new Clock() {
            @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { throw new IllegalStateException("synthetic clock failure"); }
        };
        assertThrows(IllegalStateException.class, () -> AuditJournal.open(dir.toString(),
                new AuditJournal.Policy(Duration.ofDays(30), 1000, 10000), null, failing, MAPPER));
        try (AuditJournal journal = open(dir)) {
            assertSealedIntact(dir, 1);
            journal.append(event("recovered-again"));
        }
    }

    private AnnotationConfigApplicationContext context(Path dir) {
        var context = configuredContext(dir);
        context.registerBean(ShutdownAudit.class);
        context.refresh();
        return context;
    }

    private AnnotationConfigApplicationContext configuredContext(Path dir) {
        var context = new AnnotationConfigApplicationContext();
        context.registerBean(SimpleMeterRegistry.class);
        context.registerBean(WorkbenchProperties.class, () -> new WorkbenchProperties(null, null, null,
                null, null, null, new WorkbenchProperties.Audit(dir.toString(), null, null, null, "bench-1")));
        context.registerBean(AuditLog.class);
        return context;
    }

    static final class FailedStartup {
        FailedStartup(AuditLog log) {
            log.lifecycle("startup.failed", "failed", "application", null, null);
            throw new IllegalStateException("synthetic startup failure");
        }
    }

    @Test
    void failedContextRefreshClosesItsActiveJournal() throws Exception {
        Path dir = tmp.resolve("failed-context");
        try (var context = configuredContext(dir)) {
            context.registerBean(FailedStartup.class);
            assertThrows(org.springframework.beans.factory.BeanCreationException.class, context::refresh);
            try (AuditJournal journal = open(dir)) {
                assertSealedIntact(dir, 1);
                assertTrue(Files.readString(dir.resolve("audit-000001.jsonl")).contains("startup.failed"));
                journal.append(event("after-failed-context"));
            }
        }
    }

    static final class ShutdownAudit implements DisposableBean {
        private final AuditLog log;

        ShutdownAudit(AuditLog log) { this.log = log; }

        @Override
        public void destroy() {
            log.lifecycle("cleanup.finished", "success", "application", null, null);
        }
    }

    @Test
    void contextShutdownRecordsDependentEventsAndReleasesWriter(CapturedOutput output) throws Exception {
        Path dir = tmp.resolve("SYNTHETIC_PRIVATE_PATH");
        try (var owner = context(dir)) {
            owner.getBean(AuditLog.class).append(event("first"));
            try (var contender = context(dir)) {
                var registry = contender.getBean(SimpleMeterRegistry.class);
                assertEquals(0, registry.get("workbench.audit.journal.protected").gauge().value());
                assertEquals(1, registry.get("workbench.audit.write.failures").counter().count());
                assertTrue(output.getAll().contains(AuditLog.JOURNAL_WARNING));
                assertFalse(output.getAll().contains("SYNTHETIC_PRIVATE_PATH"));
                contender.getBean(AuditLog.class).append(event("log-only"));
            }
            owner.getBean(AuditLog.class).append(event("continued"));
            assertEquals(0, owner.getBean(SimpleMeterRegistry.class)
                    .get("workbench.audit.write.failures").counter().count());
        }
        try (var reopened = context(dir)) {
            assertEquals(1, reopened.getBean(SimpleMeterRegistry.class)
                    .get("workbench.audit.journal.protected").gauge().value());
            assertSealedIntact(dir, 3);
            String contents = Files.readString(dir.resolve("audit-000001.jsonl"));
            assertTrue(contents.contains("cleanup.finished"));
            assertFalse(contents.contains("log-only"));
        }
    }
}
