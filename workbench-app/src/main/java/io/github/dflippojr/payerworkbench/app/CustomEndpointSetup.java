package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

/**
 * What a custom-endpoint run needs before it starts: the guard that approves and pins its destinations, a
 * credential store made for this run alone, and the connection record built from the request. Building it
 * refuses an endpoint, authentication type or credential that is not acceptable.
 */
final class CustomEndpointSetup {
    private static final String CREDENTIAL_REF = "custom-endpoint-credential";

    private final EndpointGuard guard = new EndpointGuard();
    private final InMemoryCredentials credentials = new InMemoryCredentials();
    private final ConnectionRecord record;

    /** @throws RunRejection if the endpoint, authentication type or credential is not acceptable */
    CustomEndpointSetup(RunRequest request) {
        this.record = customRecord(request, guard, credentials);
    }

    EndpointGuard guard() {
        return guard;
    }

    InMemoryCredentials credentials() {
        return credentials;
    }

    ConnectionRecord record() {
        return record;
    }

    /** Drops the run's credential; called when the run ends or is refused. */
    void forgetCredential() {
        credentials.remove(CREDENTIAL_REF);
    }

    /**
     * A refused custom endpoint is audited {@code invalid_custom_endpoint}, so a run that passed these checks and
     * then fails with a server error is audited {@code request_failed} instead (#378).
     */
    static RunRejection refuse(String message) {
        return new RunRejection("invalid_custom_endpoint", message);
    }

    private static java.net.URI approveDestination(EndpointGuard guard, String label, String url) {
        try { return guard.approve(label, url); }
        catch (IllegalArgumentException e) {
            throw new RunRejection("destination_rejected", e.getMessage());
        }
    }

    private static ConnectionRecord customRecord(RunRequest request, EndpointGuard guard,
                                                 InMemoryCredentials credentials) {
        RunRequest.CustomEndpoint endpoint = request.customEndpoint();
        AuthType auth = endpoint.authType() == null ? AuthType.NONE : endpoint.authType();
        if (auth != AuthType.NONE && auth != AuthType.OAUTH2_CLIENT_CREDENTIALS && auth != AuthType.CDS_HOOKS_JWT
                && auth != AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            throw refuse("authType must be NONE, OAUTH2_CLIENT_CREDENTIALS, CDS_HOOKS_JWT or OAUTH2_PRIVATE_KEY_JWT");
        }
        String baseUrl = approveDestination(guard, "Base URL", endpoint.baseUrl()).toString();
        ConnectionRecord.Builder builder = ConnectionRecord.builder()
                .payerId(RunRequest.CUSTOM_PAYER_ID)
                .displayName("Custom endpoint")
                .environment(request.environment())
                .baseUrl(baseUrl)
                .authType(auth)
                .igVersion(isSet(endpoint.igVersion()) ? endpoint.igVersion().trim() : "2.0.1")
                .contactInfo("user-supplied endpoint");
        if (auth == AuthType.NONE) {
            if (isSet(endpoint.credential())) {
                throw refuse("authType NONE takes no credential");
            }
            return builder.build();
        }
        if (!isSet(endpoint.clientId())) {
            throw refuse("clientId is required for " + auth);
        }
        if (!isSet(endpoint.credential())) {
            throw refuse("credential is required for " + auth);
        }
        builder.clientId(endpoint.clientId().trim());
        if (auth == AuthType.OAUTH2_CLIENT_CREDENTIALS || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            builder.tokenEndpoint(approveDestination(guard, "Token endpoint", endpoint.tokenEndpoint()).toString());
        }
        if (auth == AuthType.CDS_HOOKS_JWT || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            if (!isSet(endpoint.keyId())) {
                throw refuse("keyId is required for " + auth);
            }
            builder.keyId(endpoint.keyId().trim());
        }
        credentials.put(CREDENTIAL_REF, endpoint.credential());
        return builder.credentialRef(CREDENTIAL_REF).build();
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }
}
