package io.github.dflippojr.payerworkbench.diagnostics;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Tunable thresholds and expectations for the built-in checks.
 *
 * @param requiredHooks hooks the caller intends to call; {@code discovery.services}
 *     fails if the payer does not advertise one of them
 * @param latencyWarn hook latency above which {@code perf.latency} warns
 * @param latencyFail hook latency above which {@code perf.latency} fails; CDS Hooks
 *     clients often give up near 10 seconds
 * @param clockSkewTolerance how far a JWT's {@code iat} may differ from the payer's
 *     clock before {@code auth.clock-skew} reports it
 */
public record DiagnosticsConfig(
        Set<String> requiredHooks,
        Duration latencyWarn,
        Duration latencyFail,
        Duration clockSkewTolerance
) {
    public DiagnosticsConfig {
        requiredHooks = requiredHooks == null ? Set.of() : Set.copyOf(requiredHooks);
        Objects.requireNonNull(latencyWarn, "latencyWarn");
        Objects.requireNonNull(latencyFail, "latencyFail");
        Objects.requireNonNull(clockSkewTolerance, "clockSkewTolerance");
    }

    /** {@code order-sign} required, 5 s warn, 10 s fail, 60 s clock skew tolerance. */
    public static DiagnosticsConfig defaults() {
        return new DiagnosticsConfig(Set.of("order-sign"), Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(60));
    }

    /** A copy of this config with different required hooks. */
    public DiagnosticsConfig withRequiredHooks(Set<String> hooks) {
        return new DiagnosticsConfig(hooks, latencyWarn, latencyFail, clockSkewTolerance);
    }
}
