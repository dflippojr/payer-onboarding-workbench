package io.github.dflippojr.payerworkbench.core;

/** Append-only destination; callers must handle write failure without retrying side effects. */
@FunctionalInterface
public interface AuditSink {
    void append(AuditEvent event);
}
