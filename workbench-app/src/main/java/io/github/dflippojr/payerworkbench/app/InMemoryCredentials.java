package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secrets generated at startup for the synthetic payers. They live only in this
 * process's memory: never written to disk, logged or returned by the API.
 */
final class InMemoryCredentials implements CredentialProvider {

    private final Map<String, String> secrets = new ConcurrentHashMap<>();

    @Override
    public Optional<String> resolve(String credentialRef) {
        return credentialRef == null ? Optional.empty() : Optional.ofNullable(secrets.get(credentialRef));
    }

    @Override
    public void put(String credentialRef, String secretValue) {
        secrets.put(credentialRef, secretValue);
    }

    @Override
    public void remove(String credentialRef) {
        secrets.remove(credentialRef);
    }

    @Override
    public String toString() {
        return "InMemoryCredentials[" + secrets.size() + " refs]";
    }
}
