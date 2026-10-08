package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import java.util.List;
import java.util.UUID;

/** Synchronous MVC request scope, removed in the filter's finally block. Never contains request bodies. */
final class AuditContext {
    private static final ThreadLocal<AuditContext> CURRENT = new ThreadLocal<>();
    final UUID requestId = UUID.randomUUID();
    final AuditLog log;
    String runId;
    String payerId;
    Environment environment;
    String sampleId;
    AuthType authType;
    String verdict;
    String reasonCode;
    String reportFormat;
    List<AuditEvent.OverrideField> overrides = List.of();

    AuditContext(AuditLog log) { this.log = log; }
    static AuditContext current() { return CURRENT.get(); }
    static void bind(AuditContext context) { CURRENT.set(context); }
    static void clear() { CURRENT.remove(); }

    AuditEvent.Metadata metadata(Integer status) {
        return new AuditEvent.Metadata(status, reasonCode, payerId, environment, sampleId, authType,
                verdict, overrides, reportFormat, null, null);
    }

    static void credential(String reference, boolean available) {
        AuditContext context = current();
        if (context == null || context.runId == null) { return; }
        String safeId = switch (reference == null ? "" : reference) {
            case "northwind-client-secret", "fabrikam-signing-key", "tailspin-signing-key" -> reference;
            case "custom-endpoint-credential" -> "custom-" + context.runId;
            default -> null;
        };
        context.log.emit(context, "credential.resolved", available ? "available" : "missing", "credential", safeId,
                new AuditEvent.Metadata(null, null, context.payerId, context.environment, context.sampleId,
                        context.authType, null, List.of(), null, safeId, available));
    }
}
