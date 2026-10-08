package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.AuditEvent;
import org.springframework.stereotype.Component;

/**
 * Records the effective safe runtime settings once at startup, as the application itself. Names and
 * values are an allowlist of booleans and durations; no environment, arguments, paths or property
 * objects are read.
 */
@Component
class StartupAudit {

    StartupAudit(AuditLog log, WorkbenchProperties properties) {
        log.lifecycle("startup.configuration", "success", "configuration", null,
                AuditEvent.Metadata.ofLifecycle(null, null, null, AuditEvent.Lifecycle.configuration(
                        properties.customEndpoints().enabled(), properties.maxRuns(),
                        properties.latencyWarn().toMillis(), properties.latencyFail().toMillis(),
                        properties.requestTimeout().toMillis())));
    }
}
