package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(OutputCaptureExtension.class)
class AuditInfrastructureTest {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");

    @Test
    void sinkFailuresPreserveHttpBehaviorAndOnlyWarnWithCounter(CapturedOutput output) throws Exception {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AuditLog log = new AuditLog(event -> { throw new IllegalStateException("SYNTHETIC_SECRET"); },
                Clock.fixed(NOW, ZoneOffset.UTC), registry);
        MockHttpServletResponse response = new MockHttpServletResponse();
        new AuditRequestFilter(log).doFilter(new MockHttpServletRequest("POST", "/api/runs"), response,
                (request, reply) -> { reply.getWriter().write("synthetic success"); });
        assertEquals(200, response.getStatus());
        assertEquals("synthetic success", response.getContentAsString());
        assertEquals(2, registry.get("workbench.audit.write.failures").counter().count());
        assertFalse(output.getAll().contains("SYNTHETIC_SECRET"));
        assertEquals(2, output.getAll().lines().filter(l -> l.endsWith(AuditLog.WARNING)).count());
        assertNull(AuditContext.current());
    }

    @Test
    void exceptionCleansScopeAndEmitsExactlyOneTerminalAtFixedTime() throws Exception {
        List<AuditEvent> events = new ArrayList<>();
        AuditRequestFilter filter = new AuditRequestFilter(new AuditLog(events::add,
                Clock.fixed(NOW, ZoneOffset.UTC), new SimpleMeterRegistry()));
        assertThrows(IllegalStateException.class, () -> filter.doFilter(
                new MockHttpServletRequest("POST", "/api/runs"), new MockHttpServletResponse(),
                (request, response) -> { throw new IllegalStateException("SYNTHETIC_SECRET"); }));
        assertNull(AuditContext.current());
        assertEquals(2, events.size());
        assertEquals(NOW, events.getFirst().occurredAt());
        assertEquals(events.getFirst().requestId(), events.getLast().requestId());
        assertEquals(500, events.getLast().metadata().httpStatus());
        assertEquals("request_failed", events.getLast().metadata().reasonCode());
        filter.doFilter(new MockHttpServletRequest("GET", "/api/runs"), new MockHttpServletResponse(),
                (request, response) -> assertNull(AuditContext.current().runId));
        assertNotEquals(events.getFirst().requestId(), events.getLast().requestId());
        assertNull(AuditContext.current());
    }

    @Test
    void credentialResolutionRecordsActualCallsAndOmitsUnknownReferences() {
        List<AuditEvent> events = new ArrayList<>();
        AuditContext context = new AuditContext(new AuditLog(events::add,
                Clock.fixed(NOW, ZoneOffset.UTC), new SimpleMeterRegistry()));
        InMemoryCredentials credentials = new InMemoryCredentials();
        credentials.put("northwind-client-secret", "SYNTHETIC_SECRET");
        credentials.resolve("northwind-client-secret"); // startup/warm-up are outside HTTP scope
        assertTrue(events.isEmpty());
        AuditContext.bind(context);
        try {
            context.runId = UUID.randomUUID().toString();
            credentials.peek("northwind-client-secret"); // availability check is not authentication
            assertTrue(events.isEmpty());
            assertTrue(credentials.resolve("northwind-client-secret").isPresent());
            assertTrue(credentials.resolve("fabrikam-signing-key").isEmpty());
            assertTrue(credentials.resolve("SYNTHETIC_PATIENT_ID").isEmpty());
            assertTrue(credentials.resolve(null).isEmpty());
        } finally { AuditContext.clear(); }
        assertEquals(4, events.size());
        assertEquals("available", events.getFirst().outcome());
        assertEquals("missing", events.get(1).outcome());
        assertNull(events.get(2).targetId());
        assertNull(events.getLast().metadata().credentialId());
        assertTrue(events.stream().allMatch(e -> e.runId().equals(context.runId)));
        assertFalse(events.toString().contains("SYNTHETIC_SECRET"));
        assertFalse(events.toString().contains("SYNTHETIC_PATIENT_ID"));
    }
}
