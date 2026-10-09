package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.core.AuditSink;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.time.Clock;
import java.util.UUID;

/** Best effort logging with a constant warning and a count of missing events. */
@Component
public class AuditLog {
    static final String WARNING = "Audit event write failed; audit trail has a gap";
    private static final Logger LOG = LoggerFactory.getLogger(AuditLog.class);
    private final AuditSink sink;
    private final Clock clock;
    private final Counter failures;

    static final String JOURNAL_WARNING = "Audit journal unavailable; durable audit trail is not being written";

    public AuditLog(MeterRegistry registry) {
        this(loggingSink(), Clock.systemUTC(), registry);
    }

    /** Logging sink plus, when {@code workbench.audit.journal-dir} is set, the durable journal. */
    @org.springframework.beans.factory.annotation.Autowired
    public AuditLog(MeterRegistry registry, WorkbenchProperties properties) {
        this(withJournal(properties.audit(), registry), Clock.systemUTC(), registry);
    }

    private static AuditSink withJournal(WorkbenchProperties.Audit audit, MeterRegistry registry) {
        AuditSink logging = loggingSink();
        if (audit.journalDir() == null) {
            return logging;
        }
        AuditJournal journal = null;
        try {
            journal = AuditJournal.open(audit.journalDir(), new AuditJournal.Policy(audit.retention(),
                    audit.segmentBytes(), audit.totalBytes()), audit.operatorLabel(), Clock.systemUTC(), MAPPER);
        } catch (java.io.IOException | RuntimeException e) {
            registry.counter("workbench.audit.write.failures").increment();
            LOG.warn(JOURNAL_WARNING);
        }
        int protectedFlag = journal == null ? 0 : 1;
        io.micrometer.core.instrument.Gauge.builder("workbench.audit.journal.protected", () -> protectedFlag)
                .register(registry);
        if (journal == null) {
            return logging;
        }
        AuditJournal active = journal;
        return event -> {
            try {
                logging.append(event);
            } finally {
                active.append(event);
            }
        };
    }

    AuditLog(AuditSink sink, Clock clock, MeterRegistry registry) {
        this.sink = sink;
        this.clock = clock;
        failures = registry.counter("workbench.audit.write.failures");
    }

    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private static AuditSink loggingSink() {
        return event -> {
            try {
                LOG.info("audit {}", MAPPER.writeValueAsString(event));
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException("Audit serialization failed");
            }
        };
    }

    void emit(AuditContext context, String action, String outcome, String targetType,
              String targetId, AuditEvent.Metadata metadata) {
        append(new AuditEvent(1, UUID.randomUUID(), clock.instant(), context.actorType, context.actorId,
                context.source, action, outcome, context.requestId, context.runId, targetType, targetId, metadata));
    }

    /** Lifecycle work done by the application itself, outside any request. */
    void lifecycle(String action, String outcome, String targetType, String targetId, AuditEvent.Metadata metadata) {
        append(new AuditEvent(1, UUID.randomUUID(), clock.instant(), "system", "application", "lifecycle",
                action, outcome, null, null, targetType, targetId, metadata));
    }

    /** Fail open: a lost event is counted and warned about, and the caller carries on. */
    public void append(AuditEvent event) {
        try {
            sink.append(event);
        } catch (RuntimeException e) {
            failures.increment();
            LOG.warn(WARNING);
        }
    }
}
