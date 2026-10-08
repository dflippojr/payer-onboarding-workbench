package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

/** Startup, cleanup and per-run fault events, using only in-process synthetic payers and system temp storage. */
class LifecycleAuditTest {

    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final String SAMPLE = "order-sign-hospital-bed";

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final AuditLog log = new AuditLog(events::add, Clock.fixed(NOW, ZoneOffset.UTC), registry);

    private List<AuditEvent> action(String action) {
        return events.stream().filter(e -> e.action().equals(action)).toList();
    }

    private OnboardingRunner runner(SyntheticPayers payers) {
        return new OnboardingRunner(payers, new SampleCatalog(), new WorkbenchProperties(null, null, null, null, null),
                new RunMetrics(registry));
    }

    private static RunRequest request(List<String> faults, Long delayMs) {
        return new RunRequest(NORTHWIND_ID, Environment.SANDBOX, SAMPLE, faults, delayMs, null);
    }

    private static void deleteTree(Path dir) throws IOException {
        if (Files.exists(dir)) {
            try (Stream<Path> walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void startupSeedAndConfigurationAreSystemEventsWithoutSecretsOrPaths() throws Exception {
        SyntheticPayers payers = new SyntheticPayers(log);
        try {
            new StartupAudit(log, new WorkbenchProperties(Duration.ofSeconds(11), Duration.ofSeconds(4),
                    Duration.ofSeconds(9), Duration.ofSeconds(14), 77,
                    new WorkbenchProperties.CustomEndpoints(true)));
            String secret = payers.credentials().peek("northwind-client-secret").orElseThrow();
            assertEquals(3, action("payer.started").size());
            assertEquals(List.of(NORTHWIND_ID, SyntheticPayers.FABRIKAM_ID, SyntheticPayers.TAILSPIN_ID),
                    action("connection.seeded").stream().map(AuditEvent::targetId).toList());
            assertEquals(List.of("northwind-client-secret", "fabrikam-signing-key", "tailspin-signing-key"),
                    action("credential.put").stream().map(AuditEvent::targetId).toList());
            AuditEvent config = action("startup.configuration").getFirst();
            AuditEvent.Lifecycle settings = config.metadata().lifecycle();
            assertTrue(settings.customEndpointsEnabled());
            assertEquals(77, settings.maxRuns());
            assertEquals(4000, settings.latencyWarnMs());
            assertEquals(9000, settings.latencyFailMs());
            assertEquals(14000, settings.requestTimeoutMs());
            for (AuditEvent e : events) {
                assertEquals("system", e.actorType());
                assertEquals("application", e.actorId());
                assertEquals("lifecycle", e.source());
                assertEquals(NOW, e.occurredAt());
            }
            String all = events.toString();
            assertFalse(all.contains(secret));
            assertFalse(all.contains("PRIVATE KEY"));
            assertFalse(all.contains("payer-workbench-"));
            assertFalse(all.contains(System.getProperty("java.io.tmpdir")));
            assertFalse(all.contains("127.0.0.1"));
        } finally {
            payers.destroy();
        }
    }

    @Test
    void cleanupSuccessCountsEveryDeleteAndRemovesCredentials() throws Exception {
        SyntheticPayers payers = new SyntheticPayers(log);
        payers.destroy();
        assertEquals(3, action("payer.stopped").size());
        assertEquals(3, action("credential.removed").size());
        assertEquals("started", action("cleanup.attempted").getFirst().outcome());
        AuditEvent done = action("cleanup.finished").getFirst();
        assertEquals("success", done.outcome());
        assertNull(done.metadata().reasonCode());
        AuditEvent.Lifecycle counts = done.metadata().lifecycle();
        assertTrue(counts.attempted() >= 2);
        assertEquals(counts.attempted(), counts.deleted());
        assertEquals(0, counts.failed());
    }

    @Test
    void cleanupPartialFailureIsNeverReportedAsDeleted() throws Exception {
        AtomicBoolean failYaml = new AtomicBoolean(true);
        Path[] work = new Path[1];
        SyntheticPayers payers = new SyntheticPayers(log, path -> {
            if (failYaml.get() && path.getFileName().toString().equals("connections.yaml")) {
                work[0] = path.getParent();
                throw new IOException("SYNTHETIC_LOCKED " + path);
            }
            Files.delete(path);
        });
        payers.destroy();
        try {
            AuditEvent done = action("cleanup.finished").getFirst();
            assertEquals("partial", done.outcome());
            assertEquals("delete_failed", done.metadata().reasonCode());
            AuditEvent.Lifecycle counts = done.metadata().lifecycle();
            assertEquals(2, counts.failed()); // the file, then the directory it keeps non-empty
            assertEquals(counts.attempted(), counts.deleted() + counts.failed());
            assertTrue(Files.exists(work[0]), "the directory really is still there");
            assertFalse(events.toString().contains("SYNTHETIC_LOCKED"));
            assertFalse(events.toString().contains(work[0].toString()));
        } finally {
            failYaml.set(false);
            deleteTree(work[0]);
        }
    }

    @Test
    void auditFailureNeverStopsStartupOrCleanupAndIsCounted() throws Exception {
        AuditLog failing = new AuditLog(e -> { throw new IllegalStateException("SYNTHETIC_SECRET"); },
                Clock.systemUTC(), registry);
        SyntheticPayers payers = new SyntheticPayers(failing);
        payers.destroy();
        assertTrue(registry.get("workbench.audit.write.failures").counter().count() > 10);
    }

    @Test
    void faultedRunRecordsOneSetupAndOneResetWithTheActualRestoredState() throws Exception {
        SyntheticPayers payers = new SyntheticPayers(log);
        try {
            runner(payers).run(request(List.of(Fault.SLOW_RESPONSE.id(), Fault.MALFORMED_CARD.id()), 25L));
            AuditEvent setup = action("fault.run_setup").getFirst();
            AuditEvent reset = action("fault.run_reset").getFirst();
            assertEquals(1, action("fault.run_setup").size());
            assertEquals(1, action("fault.run_reset").size());
            assertEquals("unknown", setup.actorType()); // called outside any request, job or trusted context
            assertEquals("programmatic", setup.source());
            assertEquals(setup.runId(), reset.runId());
            assertNotNull(setup.runId());
            assertEquals(setup.requestId(), reset.requestId());
            assertEquals(List.of("slow-response", "malformed-card"), setup.metadata().faults().after());
            assertEquals(25, setup.metadata().faults().delayAfterMs());
            assertEquals(List.of("slow-response", "malformed-card"), reset.metadata().faults().before());
            assertEquals(List.of(), reset.metadata().faults().after());
            assertEquals(25, reset.metadata().faults().delayBeforeMs());
            assertEquals(2000, reset.metadata().faults().delayAfterMs());
            assertEquals(NORTHWIND_ID, setup.targetId());
            // nothing was recorded again at the low-level setters
            assertTrue(action("fault.changed").isEmpty());
            assertTrue(payers.payer(NORTHWIND_ID).orElseThrow().faults().enabled().isEmpty());
        } finally {
            payers.destroy();
        }
    }

    @Test
    void exceptionalRunStillRecordsResetAndRejectedSetupChangesNothing() throws Exception {
        SyntheticPayers payers = new SyntheticPayers(log);
        try {
            OnboardingRunner runner = runner(payers);
            assertThrows(IllegalArgumentException.class,
                    () -> runner.run(request(List.of(Fault.SLOW_RESPONSE.id()), -1L)));
            AuditEvent setup = action("fault.run_setup").getFirst();
            assertEquals("rejected", setup.outcome());
            assertEquals("setup_failed", setup.metadata().reasonCode());
            assertFalse(setup.metadata().faults().changed());
            AuditEvent reset = action("fault.run_reset").getFirst();
            assertEquals(setup.runId(), reset.runId());
            assertEquals(List.of(), reset.metadata().faults().after());

            // A failure after the faults are applied: setup is recorded, then the reset shows them undone.
            events.clear();
            SyntheticPayers broken = spy(payers);
            doThrow(new IllegalStateException("SYNTHETIC_SECRET")).when(broken).tls();
            OnboardingRunner failing = runner(broken);
            assertThrows(IllegalStateException.class, () -> failing.run(request(List.of(Fault.DISCOVERY_500.id()), null)));
            assertEquals(List.of("discovery-500"), action("fault.run_setup").getFirst().metadata().faults().after());
            AuditEvent after = action("fault.run_reset").getFirst();
            assertEquals(List.of("discovery-500"), after.metadata().faults().before());
            assertEquals(List.of(), after.metadata().faults().after());
            assertEquals(action("fault.run_setup").getFirst().runId(), after.runId());
            assertFalse(events.toString().contains("SYNTHETIC_SECRET"));
            assertTrue(payers.payer(NORTHWIND_ID).orElseThrow().faults().enabled().isEmpty());
        } finally {
            payers.destroy();
        }
    }

    @Test
    void concurrentAdminToggleNeverMakesASetupSnapshotInconsistent() throws Exception {
        SyntheticPayers payers = new SyntheticPayers(log);
        try {
            var settings = payers.payer(NORTHWIND_ID).orElseThrow().faults();
            AtomicBoolean stop = new AtomicBoolean();
            Thread toggler = Thread.ofPlatform().start(() -> {
                while (!stop.get()) {
                    settings.change(() -> settings.enable(Fault.RATE_LIMITED_429).enable(Fault.EXPIRED_TOKEN_401));
                    settings.change(settings::clear);
                }
            });
            OnboardingRunner runner = runner(payers);
            for (int i = 0; i < 5; i++) {
                runner.run(request(List.of(Fault.DISCOVERY_500.id()), null));
            }
            stop.set(true);
            toggler.join();
            for (AuditEvent setup : action("fault.run_setup")) {
                assertEquals(List.of("discovery-500"), setup.metadata().faults().after());
                assertEquals(2000, setup.metadata().faults().delayAfterMs());
            }
            for (AuditEvent reset : action("fault.run_reset")) {
                assertEquals(List.of(), reset.metadata().faults().after());
            }
            assertEquals(5, action("fault.run_reset").size());
        } finally {
            payers.destroy();
        }
    }
}
