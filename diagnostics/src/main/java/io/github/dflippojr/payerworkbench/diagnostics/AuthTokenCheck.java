package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.util.List;
import java.util.Optional;

/**
 * {@code auth.token}: the OAuth2 token endpoint issued a usable access token. Reports
 * rejected clients (401 / {@code invalid_client}), {@code invalid_scope}, other
 * token errors, an unreachable endpoint, and a missing {@code expires_in}.
 */
public final class AuthTokenCheck implements DiagnosticCheck {

    public static final String ID = "auth.token";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        TokenResponseMetadata token = obs.tokenResponse();
        Optional<HttpExchange> exchange = Support.tokenExchange(obs);
        if (token == null && exchange.isEmpty()) {
            return List.of();
        }
        String evidence = exchange.map(Support::describe).orElse("token endpoint: " + obs.connection().tokenEndpoint());
        if (token != null) {
            evidence += "\ntoken response: error=" + token.error()
                    + (token.errorDescription() == null ? "" : " (" + token.errorDescription() + ")")
                    + ", access_token present=" + token.accessTokenPresent()
                    + ", token_type=" + token.tokenType()
                    + ", expires_in=" + token.expiresInSeconds()
                    + ", scope=" + String.join(" ", token.scopes());
        }
        if (exchange.isPresent() && !exchange.get().responded()) {
            return List.of(new Finding(ID, Severity.FAIL, "Token endpoint unreachable",
                    "The workbench could not get any HTTP response from the token endpoint (the OAuth2 URL "
                            + "that exchanges client credentials for an access token), so no hook call can be "
                            + "authorized.",
                    evidence,
                    "Check the tokenEndpoint in the connection record and network access to its host; if the "
                            + "error mentions TLS or certificates, see the tls.handshake finding."));
        }
        int status = exchange.map(HttpExchange::status).orElse(200);
        String error = token == null ? null : token.error();
        if (status == 401 || "invalid_client".equals(error)) {
            return List.of(new Finding(ID, Severity.FAIL, "Token request rejected: client not authenticated",
                    "The token endpoint did not accept this client's credentials (HTTP " + status
                            + (error == null ? "" : ", " + error) + "). The payer either does not know this "
                            + "client_id in this environment or could not verify its secret or signed JWT.",
                    evidence,
                    "Confirm the client_id '" + obs.connection().clientId() + "' is registered for the "
                            + obs.connection().environment() + " environment, that the secret or signing key "
                            + "is the current one (and its key id matches the payer's JWKS), and check any "
                            + "auth.jwt-audience or auth.clock-skew finding for the signed-JWT case."));
        }
        if ("invalid_scope".equals(error)) {
            return List.of(new Finding(ID, Severity.FAIL, "Token request rejected: invalid_scope",
                    "The payer refused one or more requested scopes (the permissions an access token is "
                            + "asked to carry). Payers often name scopes differently or only grant some per client.",
                    evidence + "\nrequested scopes: " + String.join(" ", obs.connection().scopes()),
                    "Request exactly the scopes in the payer's onboarding guide (for example system/*.read or "
                            + "a payer-specific CRD scope) and update the connection record's scopes to match."));
        }
        if (error != null || !Support.isSuccess(status)) {
            return List.of(new Finding(ID, Severity.FAIL,
                    "Token request failed" + (error == null ? ": HTTP " + status : ": " + error),
                    "The token endpoint did not issue an access token, so hook calls cannot be authorized.",
                    evidence,
                    "Compare the token request (grant_type, client authentication method, scopes) with the "
                            + "payer's onboarding guide; the error description above usually names the field."));
        }
        if (token == null) {
            return List.of();
        }
        if (!token.accessTokenPresent()) {
            return List.of(new Finding(ID, Severity.FAIL, "Token response has no access_token",
                    "The token endpoint answered successfully but returned no access_token, so there is "
                            + "nothing to send on hook calls.",
                    evidence,
                    "Confirm the request uses grant_type=client_credentials and ask the payer why no token "
                            + "was issued."));
        }
        if (token.expiresInSeconds() == null) {
            return List.of(new Finding(ID, Severity.WARN, "Token response lacks expires_in",
                    "An access token was issued, but the response does not say how long it lasts "
                            + "(expires_in, in seconds). Without it a client cannot tell when to fetch a new "
                            + "token, and may keep using an expired one and get 401s mid-session.",
                    evidence,
                    "Ask the payer to return expires_in, as SMART Backend Services requires; meanwhile "
                            + "configure a conservative token lifetime (for example 5 minutes) in the client."));
        }
        return List.of(new Finding(ID, Severity.PASS, "Access token obtained",
                "The token endpoint issued an access token with an expiry of " + token.expiresInSeconds()
                        + " seconds.",
                evidence, null));
    }
}
