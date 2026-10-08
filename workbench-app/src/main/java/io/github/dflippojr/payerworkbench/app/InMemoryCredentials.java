package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.payerworkbench.core.AuditEvent;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secrets generated at startup for the synthetic payers. They live only in this
 * process's memory: never written to disk, logged or returned by the API.
 *
 * <p>With an {@link AuditLog}, each put and remove is recorded as an application lifecycle event
 * naming only the logical reference, never the value.
 */
final class InMemoryCredentials implements CredentialProvider {

    private final Map<String, String> secrets = new ConcurrentHashMap<>();
    private final AuditLog lifecycleAudit;

    InMemoryCredentials() {
        this(null);
    }

    InMemoryCredentials(AuditLog lifecycleAudit) {
        this.lifecycleAudit = lifecycleAudit;
    }

    @Override
    public Optional<String> resolve(String credentialRef) {
        Optional<String> value = peek(credentialRef);
        AuditContext.credential(credentialRef, value.isPresent());
        return value;
    }

    Optional<String> peek(String credentialRef) {
        return credentialRef == null ? Optional.empty() : Optional.ofNullable(secrets.get(credentialRef));
    }

    @Override
    public void put(String credentialRef, String secretValue) {
        secrets.put(credentialRef, secretValue);
        audit("credential.put", credentialRef);
    }

    @Override
    public void remove(String credentialRef) {
        boolean existed = secrets.remove(credentialRef) != null;
        if (existed) {
            audit("credential.removed", credentialRef);
        }
    }

    /** Removes every reference, one audited remove each; used at shutdown. */
    void removeAll() {
        secrets.keySet().forEach(this::remove);
    }

    private void audit(String action, String credentialRef) {
        if (lifecycleAudit == null) {
            return;
        }
        String safeId = AuditContext.safeCredentialId(credentialRef, null);
        lifecycleAudit.lifecycle(action, "success", "credential", safeId,
                AuditEvent.Metadata.ofLifecycle(null, null, safeId, null));
    }

    @Override
    public String toString() {
        return "InMemoryCredentials[" + secrets.size() + " refs]";
    }
}
