package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.core.AuditSink;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Writes the audit events for one {@link MockPayer}'s fault changes. Spring-free: the default sink logs
 * one JSON line after the {@code audit } marker the offline reader looks for, and an embedding
 * application can replace it. A failing sink never fails the admin request; it is counted and warned.
 */
final class FaultAudit {

    static final String WARNING = "Audit event write failed; audit trail has a gap";
    private static final System.Logger LOG = System.getLogger(FaultAudit.class.getName());

    private final AtomicLong failures = new AtomicLong();
    private volatile AuditSink sink = loggingSink();
    private volatile String payerId;

    FaultAudit(String defaultPayerId) {
        payerId = defaultPayerId;
    }

    void sink(AuditSink sink) {
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    void payerId(String payerId) {
        this.payerId = Objects.requireNonNull(payerId, "payerId");
    }

    String payerId() {
        return payerId;
    }

    long failures() {
        return failures.get();
    }

    AuditEvent.Faults faults(FaultSettings.Change change) {
        return new AuditEvent.Faults(ids(change.before()), ids(change.after()),
                change.before().slowResponseDelay().toMillis(), change.after().slowResponseDelay().toMillis(),
                change.changed());
    }

    /** An HTTP admin attempt: anonymous, because the standalone admin endpoint has no authentication. */
    void admin(Clock clock, String action, String outcome, String targetType, String targetId, int status,
               String reasonCode, AuditEvent.Faults faults) {
        append(new AuditEvent(1, UUID.randomUUID(), clock.instant(), "anonymous", null, "http", action, outcome,
                UUID.randomUUID(), null, targetType, targetId,
                AuditEvent.Metadata.ofFaults(status, reasonCode, payerId, faults)));
    }

    /** A change made by calling {@link FaultSettings} directly, outside any context that records itself. */
    void programmatic(Clock clock, FaultSettings.Change change) {
        append(new AuditEvent(1, UUID.randomUUID(), clock.instant(), "unknown", null, "programmatic",
                "fault.changed", "success", null, null, "payer", payerId,
                AuditEvent.Metadata.ofFaults(null, null, payerId, faults(change))));
    }

    private void append(AuditEvent event) {
        try {
            sink.append(event);
        } catch (RuntimeException e) {
            failures.incrementAndGet();
            LOG.log(System.Logger.Level.WARNING, WARNING);
        }
    }

    private static List<String> ids(FaultSettings.Snapshot snapshot) {
        return snapshot.enabled().stream().map(Fault::id).toList();
    }

    private static AuditSink loggingSink() {
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new SimpleModule().addSerializer(Instant.class, ToStringSerializer.instance))
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return event -> {
            try {
                LOG.log(System.Logger.Level.INFO, "audit {0}", mapper.writeValueAsString(event));
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Audit serialization failed");
            }
        };
    }
}
