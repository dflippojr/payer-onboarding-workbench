package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminAuditTest {

    private static final String HOSTILE = "SYNTHETIC_SECRET%0Aforged%20audit%20%7B%22action%22%3A%22x%22%7D";

    private static PayerFixture fixture(List<AuditEvent> events) throws Exception {
        PayerFixture f = PayerFixture.northwind();
        f.payer.auditSink(events::add).auditPayerId("northwind-synthetic");
        return f;
    }

    @Test
    void everyMutationAttemptHasOneAccurateEventWithoutARequestId() throws Exception {
        List<AuditEvent> events = new ArrayList<>();
        try (PayerFixture f = fixture(events)) {
            f.raw("POST", "/admin/faults/discovery-500", null);
            f.raw("POST", "/admin/faults/discovery-500", null); // no-op
            f.raw("PUT", "/admin/faults/slow-response?delayMs=50", null);
            f.raw("POST", "/admin/faults/slow-response?delayMs=75", null);
            f.raw("DELETE", "/admin/faults/discovery-500", null);
            f.raw("DELETE", "/admin/faults/discovery-500", null); // no-op
            f.raw("DELETE", "/admin/faults", null);
            f.raw("DELETE", "/admin/faults", null); // no-op
            f.raw("GET", "/admin/faults", null); // read-only
            f.raw("GET", "/admin/faults/discovery-500", null); // read-only, rejected route
            f.raw("GET", "/admin/faults/nope", null);

            assertEquals(List.of("fault.enable", "fault.enable", "fault.delay_set", "fault.delay_set",
                    "fault.disable", "fault.disable", "fault.clear", "fault.clear"),
                    events.stream().map(AuditEvent::action).toList());
            AuditEvent enable = events.get(0);
            assertEquals("anonymous", enable.actorType());
            assertNull(enable.actorId());
            assertEquals("http", enable.source());
            assertEquals("success", enable.outcome());
            assertEquals("fault", enable.targetType());
            assertEquals("discovery-500", enable.targetId());
            assertEquals("northwind-synthetic", enable.metadata().payerId());
            assertEquals(200, enable.metadata().httpStatus());
            assertEquals(List.of(), enable.metadata().faults().before());
            assertEquals(List.of("discovery-500"), enable.metadata().faults().after());
            assertTrue(enable.metadata().faults().changed());
            assertFalse(events.get(1).metadata().faults().changed());
            assertEquals(List.of("discovery-500"), events.get(1).metadata().faults().before());
            AuditEvent delay = events.get(2);
            assertEquals(2000, delay.metadata().faults().delayBeforeMs());
            assertEquals(50, delay.metadata().faults().delayAfterMs());
            assertEquals(List.of("slow-response", "discovery-500"), delay.metadata().faults().after());
            assertEquals(50, events.get(3).metadata().faults().delayBeforeMs());
            assertEquals(75, events.get(3).metadata().faults().delayAfterMs());
            AuditEvent clear = events.get(6);
            assertEquals("payer", clear.targetType());
            assertEquals(List.of("slow-response"), clear.metadata().faults().before());
            assertEquals(List.of(), clear.metadata().faults().after());
            assertEquals(75, clear.metadata().faults().delayBeforeMs());
            assertEquals(2000, clear.metadata().faults().delayAfterMs());
            assertFalse(events.get(7).metadata().faults().changed());
            assertEquals(8, events.stream().map(AuditEvent::eventId).distinct().count());
            assertEquals(8, events.stream().map(AuditEvent::requestId).distinct().count());
        }
    }

    @Test
    void invalidInputsAreRejectedWithFixedReasonsAndNoStateChange() throws Exception {
        List<AuditEvent> events = new ArrayList<>();
        try (PayerFixture f = fixture(events)) {
            f.payer.faults().change(() -> f.payer.faults().enable(Fault.MALFORMED_CARD));
            f.raw("POST", "/admin/faults/unknown-fault", null);
            f.raw("POST", "/admin/faults/slow-response?delayMs=-5", null);
            f.raw("POST", "/admin/faults/slow-response?delayMs=abc", null);
            f.raw("POST", "/admin/faults", null);
            f.raw("PATCH", "/admin/faults/discovery-500", null);
            f.raw("POST", "/admin/faults/slow-response?delayMs=" + HOSTILE, null);

            assertEquals(List.of("unknown_fault", "invalid_delay", "invalid_delay", "method_not_allowed",
                    "method_not_allowed", "invalid_delay"),
                    events.stream().map(e -> e.metadata().reasonCode()).toList());
            assertTrue(events.stream().allMatch(e -> e.outcome().equals("rejected")));
            assertNull(events.get(0).targetId()); // unknown text is never echoed
            assertEquals(404, events.get(0).metadata().httpStatus());
            assertEquals("slow-response", events.get(1).targetId());
            assertEquals("fault.delay_set", events.get(1).action());
            for (AuditEvent e : events) {
                assertFalse(e.metadata().faults().changed());
                assertEquals(List.of("malformed-card"), e.metadata().faults().after());
                assertEquals(e.metadata().faults().before(), e.metadata().faults().after());
            }
            assertEquals(Duration.ofSeconds(2), f.payer.faults().slowResponseDelay());
            assertFalse(events.toString().contains("SYNTHETIC_SECRET"));
        }
    }

    @Test
    void sinkFailureDoesNotFailTheAdminRequestAndIsCounted() throws Exception {
        try (PayerFixture f = PayerFixture.northwind()) {
            f.payer.auditSink(event -> { throw new IllegalStateException("SYNTHETIC_SECRET"); });
            assertEquals(200, f.raw("POST", "/admin/faults/discovery-500", null).statusCode());
            assertTrue(f.payer.faults().isEnabled(Fault.DISCOVERY_500));
            assertEquals(404, f.raw("POST", "/admin/faults/missing", null).statusCode());
            assertEquals(2, f.payer.auditWriteFailures());
        }
    }

    @Test
    void directProgrammaticChangesAreUnknownActorAndScopedChangesAreNotDoubleRecorded() throws Exception {
        List<AuditEvent> events = new ArrayList<>();
        try (PayerFixture f = fixture(events)) {
            f.payer.faults().enable(Fault.RATE_LIMITED_429);
            assertEquals(1, events.size());
            AuditEvent e = events.getFirst();
            assertEquals("unknown", e.actorType());
            assertEquals("programmatic", e.source());
            assertEquals("fault.changed", e.action());
            assertEquals(List.of("rate-limited-429"), e.metadata().faults().after());
            f.payer.faults().change(() -> f.payer.faults().clear().enable(Fault.DISCOVERY_500));
            assertEquals(1, events.size());
            f.raw("DELETE", "/admin/faults", null);
            assertEquals(2, events.size()); // the route records once, not again at the setter
        }
    }

    @Test
    void concurrentChangesNeverProduceInconsistentSnapshots() throws Exception {
        List<AuditEvent> events = new CopyOnWriteArrayList<>();
        List<Throwable> failures = new CopyOnWriteArrayList<>();
        try (PayerFixture f = fixture(events)) {
            FaultSettings faults = f.payer.faults();
            Thread[] threads = new Thread[4];
            for (int i = 0; i < threads.length; i++) {
                int n = i;
                threads[i] = Thread.ofPlatform().start(() -> {
                    try {
                        for (int j = 0; j < 100; j++) {
                            FaultSettings.Change c = faults.change(() -> {
                                if (n % 2 == 0) {
                                    faults.enable(Fault.DISCOVERY_500).enable(Fault.MALFORMED_CARD);
                                } else {
                                    faults.clear();
                                }
                            });
                            // the pair is self-consistent: after is what this change left, never a mix
                            if (n % 2 == 0) {
                                assertTrue(c.after().enabled().containsAll(
                                        List.of(Fault.DISCOVERY_500, Fault.MALFORMED_CARD)));
                            } else {
                                assertTrue(c.after().enabled().isEmpty());
                            }
                        }
                    } catch (Throwable t) {
                        failures.add(t);
                    }
                });
            }
            for (Thread t : threads) {
                t.join();
            }
            assertTrue(failures.isEmpty(), failures.toString());
            assertTrue(events.isEmpty(), "scoped changes record through their caller, not the setters");
        }
    }

    @Test
    void defaultSinkWritesOneParseableJsonLineAfterTheAuditMarker() throws Exception {
        Logger logger = Logger.getLogger(FaultAudit.class.getName());
        List<String> lines = new CopyOnWriteArrayList<>();
        Handler handler = new Handler() {
            @Override public void publish(LogRecord r) {
                lines.add(new java.util.logging.SimpleFormatter().formatMessage(r));
            }
            @Override public void flush() { }
            @Override public void close() { }
        };
        logger.addHandler(handler);
        logger.setLevel(java.util.logging.Level.INFO);
        try (PayerFixture f = PayerFixture.northwind()) {
            f.raw("POST", "/admin/faults/slow-response?delayMs=10", null);
            assertEquals(1, lines.size());
            assertTrue(lines.getFirst().startsWith("audit {"), lines.getFirst());
            JsonNode event = new ObjectMapper().readTree(lines.getFirst().substring("audit ".length()));
            assertEquals(1, event.path("schemaVersion").asInt());
            assertEquals("fault.delay_set", event.path("action").asText());
            assertTrue(event.path("occurredAt").asText().endsWith("Z"));
            assertEquals(10, event.path("metadata").path("faults").path("delayAfterMs").asInt());
            assertFalse(lines.getFirst().contains("\n"));
        } finally {
            logger.removeHandler(handler);
        }
    }
}
