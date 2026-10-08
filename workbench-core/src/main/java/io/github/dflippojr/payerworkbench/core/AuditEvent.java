package io.github.dflippojr.payerworkbench.core;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;

/** Versioned audit contract. Metadata has no arbitrary map or diagnostic payload. */
public record AuditEvent(int schemaVersion, UUID eventId, Instant occurredAt,
        String actorType, String actorId, String source, String action, String outcome,
        UUID requestId, String runId, String targetType, String targetId, Metadata metadata) {
    public record Metadata(Integer httpStatus, String reasonCode, String payerId, Environment environment,
            String sampleId, AuthType authType, String verdict, List<OverrideField> overrides,
            String reportFormat, String credentialId, Boolean available) {
        public Metadata {
            overrides = overrides == null ? List.of() : List.copyOf(overrides);
        }
    }
    public enum OverrideField { baseUrl, igVersion, clientId }
}
