package io.github.dflippojr.payerworkbench.core;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.util.List;
import java.util.Objects;

/**
 * A view of a {@link ConnectionRecord} that is safe to show and report: the
 * credential references are reduced to whether they are configured.
 *
 * @param credentialConfigured whether the record has a {@code credentialRef}
 * @param mtlsConfigured whether the record has an {@code mtlsCredentialRef}
 */
public record RedactedConnection(
        String payerId,
        String displayName,
        Environment environment,
        String baseUrl,
        AuthType authType,
        String tokenEndpoint,
        String clientId,
        String keyId,
        String jwksUrl,
        String tenant,
        List<String> scopes,
        boolean credentialConfigured,
        boolean mtlsConfigured,
        String igVersion,
        ConnectionStatus status
) {
    public RedactedConnection {
        Objects.requireNonNull(payerId, "payerId");
        Objects.requireNonNull(environment, "environment");
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }

    /** Builds the redacted view of {@code record}. */
    public static RedactedConnection of(ConnectionRecord record) {
        return new RedactedConnection(
                record.payerId(),
                record.displayName(),
                record.environment(),
                record.baseUrl(),
                record.authType(),
                record.tokenEndpoint(),
                record.clientId(),
                record.keyId(),
                record.jwksUrl(),
                record.tenant(),
                record.scopes(),
                isSet(record.credentialRef()),
                isSet(record.mtlsCredentialRef()),
                record.igVersion(),
                record.status());
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }
}
