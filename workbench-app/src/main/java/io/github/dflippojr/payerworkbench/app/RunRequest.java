package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.util.List;

/**
 * Body of {@code POST /api/runs}.
 *
 * @param payerId             which synthetic payer to onboard
 * @param environment         which connection record to resolve; defaults to {@code SANDBOX}
 * @param sampleId            the sample hook request to send (see {@code GET /api/samples})
 * @param faults              mock payer fault ids to switch on for this run only
 * @param slowResponseDelayMs the {@code slow-response} delay; defaults to {@code workbench.slow-response-delay}
 * @param connection          edits to the stored connection settings, for this run only
 * @param customEndpoint      a payer endpoint to run against instead of a synthetic payer; when set,
 *                            {@code payerId} is ignored and replaced by {@value #CUSTOM_PAYER_ID}
 */
public record RunRequest(
        String payerId,
        Environment environment,
        String sampleId,
        List<String> faults,
        Long slowResponseDelayMs,
        ConnectionOverrides connection,
        CustomEndpoint customEndpoint
) {
    /** A run against a synthetic payer. */
    public RunRequest(String payerId, Environment environment, String sampleId, List<String> faults,
                      Long slowResponseDelayMs, ConnectionOverrides connection) {
        this(payerId, environment, sampleId, faults, slowResponseDelayMs, connection, null);
    }

    /** The payer id a run against a {@link CustomEndpoint} carries. */
    public static final String CUSTOM_PAYER_ID = "custom-endpoint";

    public RunRequest {
        payerId = customEndpoint == null ? payerId : CUSTOM_PAYER_ID;
        environment = environment == null ? Environment.SANDBOX : environment;
        faults = faults == null ? List.of() : List.copyOf(faults);
        connection = connection == null ? ConnectionOverrides.NONE : connection;
    }

    /**
     * Connection settings a user may change to reproduce a misconfiguration. Blank
     * fields keep the stored value. There is deliberately no field for a secret.
     *
     * @param baseUrlSuffix appended to the stored base URL, e.g. {@code /r4} or {@code /}
     * @param igVersion     replaces the CRD IG version the connection expects
     * @param clientId      replaces the client id (the JWT {@code iss}, or the OAuth2 client)
     */
    public record ConnectionOverrides(String baseUrlSuffix, String igVersion, String clientId) {
        static final ConnectionOverrides NONE = new ConnectionOverrides(null, null, null);
    }

    /**
     * A payer endpoint the user supplies instead of a synthetic payer. Only accepted when
     * {@code workbench.custom-endpoints.enabled=true}. The credential is read from the request
     * body, held in memory for this run only, and never stored, echoed, logged or reported;
     * {@link #toString()} leaves it out so an accidental log line can't carry it either.
     *
     * @param baseUrl       the CDS Hooks base URL, e.g. {@code http://127.0.0.1:18090/r4}
     * @param authType      {@code NONE}, {@code OAUTH2_CLIENT_CREDENTIALS}, {@code CDS_HOOKS_JWT}
     *                      or {@code OAUTH2_PRIVATE_KEY_JWT} (SMART Backend Services)
     * @param clientId      the OAuth2 client, or the JWT {@code iss}
     * @param tokenEndpoint the OAuth2 token endpoint (client credentials or SMART)
     * @param keyId         the JWT {@code kid} the payer knows the public key by (CDS Hooks JWT or SMART)
     * @param igVersion     the CRD IG version the connection expects; defaults to {@code 2.0.1}
     * @param credential    the client secret (client credentials) or PKCS#8 private key PEM (CDS Hooks JWT or SMART)
     */
    public record CustomEndpoint(String baseUrl, AuthType authType, String clientId, String tokenEndpoint,
                                 String keyId, String igVersion, String credential) {
        @Override
        public String toString() {
            return "CustomEndpoint[baseUrl=" + baseUrl + ", authType=" + authType + "]";
        }
    }
}
