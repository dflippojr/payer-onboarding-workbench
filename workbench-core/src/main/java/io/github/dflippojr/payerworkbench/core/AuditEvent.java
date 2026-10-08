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
            String reportFormat, String credentialId, Boolean available, Faults faults, Lifecycle lifecycle) {
        public Metadata {
            overrides = overrides == null ? List.of() : List.copyOf(overrides);
        }

        /** The run and report shape from before fault and lifecycle details existed. */
        public Metadata(Integer httpStatus, String reasonCode, String payerId, Environment environment,
                String sampleId, AuthType authType, String verdict, List<OverrideField> overrides,
                String reportFormat, String credentialId, Boolean available) {
            this(httpStatus, reasonCode, payerId, environment, sampleId, authType, verdict, overrides,
                    reportFormat, credentialId, available, null, null);
        }

        public static Metadata ofFaults(Integer httpStatus, String reasonCode, String payerId, Faults faults) {
            return new Metadata(httpStatus, reasonCode, payerId, null, null, null, null, null, null, null, null,
                    faults, null);
        }

        public static Metadata ofLifecycle(String reasonCode, String payerId, String credentialId,
                Lifecycle lifecycle) {
            return new Metadata(null, reasonCode, payerId, null, null, null, null, null, null, credentialId, null,
                    null, lifecycle);
        }
    }

    /**
     * Fault state around one change: fault IDs are a fixed enum and the delay is a duration, so both
     * are safe to log. {@code changed} is false for a no-op or a rejected attempt.
     */
    public record Faults(List<String> before, List<String> after, long delayBeforeMs, long delayAfterMs,
            boolean changed) {
        public Faults {
            before = before == null ? List.of() : List.copyOf(before);
            after = after == null ? List.of() : List.copyOf(after);
        }
    }

    /**
     * Safe startup configuration (booleans and durations only) and cleanup counts. Unused fields stay null.
     */
    public record Lifecycle(Boolean customEndpointsEnabled, Integer maxRuns, Long latencyWarnMs,
            Long latencyFailMs, Long requestTimeoutMs, Integer attempted, Integer deleted, Integer failed) {
        public static Lifecycle configuration(boolean customEndpoints, int maxRuns, long warnMs, long failMs,
                long timeoutMs) {
            return new Lifecycle(customEndpoints, maxRuns, warnMs, failMs, timeoutMs, null, null, null);
        }

        public static Lifecycle cleanup(int attempted, int deleted, int failed) {
            return new Lifecycle(null, null, null, null, null, attempted, deleted, failed);
        }
    }

    public enum OverrideField { baseUrl, igVersion, clientId }
}
