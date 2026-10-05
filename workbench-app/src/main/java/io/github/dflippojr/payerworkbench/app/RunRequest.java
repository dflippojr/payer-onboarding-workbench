package io.github.dflippojr.payerworkbench.app;

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
 */
public record RunRequest(
        String payerId,
        Environment environment,
        String sampleId,
        List<String> faults,
        Long slowResponseDelayMs,
        ConnectionOverrides connection
) {
    public RunRequest {
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
}
