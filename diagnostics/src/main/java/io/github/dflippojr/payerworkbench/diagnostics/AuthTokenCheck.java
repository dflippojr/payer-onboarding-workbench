package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * {@code auth.token}: the OAuth2 token endpoint issued a usable access token. Reports
 * rejected clients (401 / {@code invalid_client}), {@code invalid_scope}, other
 * token errors, an unreachable endpoint, a missing {@code token_type} or one other than Bearer (the router
 * SDK sends every token as Bearer, so it cannot use another type; #218), and a missing or unusable
 * {@code expires_in}. A numeric-string {@code expires_in} passes with a note, as the router SDK accepts it
 * (fhir-crd-router#105, #177); a fractional one warns, and says the SDK truncates and caches it.
 */
public final class AuthTokenCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "auth.token";

    /** The router SDK's {@code MAX_CACHE_LIFETIME}: it caches no token for longer, whatever {@code expires_in} says. */
    static final long SDK_MAX_CACHE_SECONDS = 24 * 60 * 60;

    /** The router SDK's rule for {@code expires_in}, in the words of the decision on fhir-crd-router#105. */
    static final String SDK_RULE = "The router SDK accepts a numeric-string expires_in, keeps the 24 h cap, "
            + "and caches nothing else";

    /** A JSON number with a fraction or exponent, which Jackson reads as a double. */
    private static final Pattern JSON_FLOAT = Pattern.compile("-?[0-9]+(\\.[0-9]+([eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)");

    @Override
    public String id() {
        return CHECK_ID;
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
                    + ", expires_in=" + token.expiresInSent()
                    + ", scope=" + String.join(" ", token.scopes())
                    + (token.scopesNotShown() == 0 ? "" : " and " + token.scopesNotShown() + " more not shown");
        }
        if (exchange.isPresent() && !exchange.get().responded()) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Token endpoint unreachable",
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
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Token request rejected: client not authenticated",
                    "The token endpoint did not accept this client's credentials (HTTP " + status
                            + (error == null ? "" : ", " + error) + "). The payer either does not know this "
                            + "client_id in this environment or could not verify its secret or signed JWT.",
                    evidence,
                    "Confirm the client_id '" + obs.connection().clientId() + "' is registered for the "
                            + obs.connection().environment() + " environment, that the secret or signing key "
                            + "is the current one (and its key id matches the payer's JWKS), and check any "
                            + "auth.client-assertion or auth.clock-skew finding for the signed-JWT case."));
        }
        if ("invalid_scope".equals(error)) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Token request rejected: invalid_scope",
                    "The payer refused one or more requested scopes (the permissions an access token is "
                            + "asked to carry). Payers often name scopes differently or only grant some per client.",
                    evidence + "\nrequested scopes: " + String.join(" ", obs.connection().scopes()),
                    "Request exactly the scopes in the payer's onboarding guide (for example system/*.read or "
                            + "a payer-specific CRD scope) and update the connection record's scopes to match."));
        }
        if (error != null || !Support.isSuccess(status)) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL,
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
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Token response has no access_token",
                    "The token endpoint answered successfully but returned no access_token, so there is "
                            + "nothing to send on hook calls.",
                    evidence,
                    "Confirm the request uses grant_type=client_credentials and ask the payer why no token "
                            + "was issued."));
        }
        // Checked before expires_in: the type decides how the token is sent, so a wrong one matters more.
        String tokenType = token.tokenType() == null ? "" : token.tokenType().strip();
        if (tokenType.isEmpty()) {
            return List.of(new Finding(CHECK_ID, Severity.WARN, "Token response lacks token_type",
                    "An access token was issued, but the response does not say its token_type. RFC 6749 §5.1 "
                            + "makes token_type REQUIRED, and §7.1 says a client must not use an access token whose type it "
                            + "does not understand. The router SDK sends every token as Bearer whatever the response says, "
                            + "so the client cannot tell whether the payer accepts it that way.",
                    evidence,
                    "Ask the payer to return token_type: \"Bearer\" in the token response, as RFC 6749 §5.1 and SMART "
                            + "Backend Services require. The router SDK sends the token as Bearer either way."));
        }
        if (!"bearer".equalsIgnoreCase(tokenType)) {
            return List.of(new Finding(CHECK_ID, Severity.WARN, "Token response's token_type is not Bearer",
                    "An access token was issued with token_type \"" + token.tokenType() + "\". The router SDK implements "
                            + "only Bearer: it sends every token as Authorization: Bearer, so a token bound to another type, "
                            + "such as DPoP or mac, is likely to be refused at the hook call.",
                    evidence,
                    "Ask the payer to issue a Bearer token (SMART Backend Services fixes the type as bearer). The router "
                            + "SDK cannot send a DPoP or mac token, so hook calls on this connection may fail until the payer "
                            + "does."));
        }
        if (token.expiresInSeconds() == null) {
            String sent = token.expiresInSent();
            Long truncated = sdkTruncatedSeconds(sent);
            String explanation;
            if (sent == null) {
                explanation = "An access token was issued, but the response does not say how long it lasts "
                        + "(expires_in, in seconds). Without it a client cannot tell when to fetch a new token";
            } else if (truncated == null) {
                explanation = "An access token was issued, but its expires_in (" + sent + ") was present but not "
                        + "usable: it is not a positive whole number of seconds, and RFC 6749 §5.1 requires a JSON "
                        + "number. " + SDK_RULE + ", so it treats this response as having no expires_in and does "
                        + "not cache the token. Without it a client cannot tell when to fetch a new token";
            } else {
                explanation = "An access token was issued, but its expires_in (" + sent + ") was present but not "
                        + "usable: it is not a positive whole number of seconds. The router SDK reads a JSON number "
                        + "with Jackson's asLong(), which truncates it to " + truncated + ", so it caches this token "
                        + "for " + (truncated > SDK_MAX_CACHE_SECONDS
                                ? "at most 24 h (" + SDK_MAX_CACHE_SECONDS + " seconds)" : truncated + " seconds")
                        + ". A client that rejects a fraction cannot tell when to fetch a new token";
            }
            return List.of(new Finding(CHECK_ID, Severity.WARN, "Token response lacks expires_in",
                    explanation + ", and may keep using an expired one and get 401s mid-session.",
                    evidence,
                    "Ask the payer to return expires_in as a whole JSON number of seconds, as RFC 6749 and SMART "
                            + "Backend Services require; meanwhile configure a conservative token lifetime (for "
                            + "example 5 minutes) in the client."));
        }
        long seconds = token.expiresInSeconds();
        StringBuilder explanation = new StringBuilder("The token endpoint issued an access token with an expiry of ")
                .append(seconds).append(" seconds.");
        if (token.expiresInSent() != null && token.expiresInSent().startsWith("\"")) {
            explanation.append(" Its expires_in was sent as a JSON string (").append(token.expiresInSent())
                    .append("), where RFC 6749 §5.1 requires a JSON number. ").append(SDK_RULE)
                    .append(", so it caches this token for at most 24 h.");
        }
        if (seconds > SDK_MAX_CACHE_SECONDS) {
            explanation.append(" That is more than 24 h: the router SDK caches a token for at most 24 h (")
                    .append(SDK_MAX_CACHE_SECONDS).append(" seconds), not the ").append(seconds).append(" sent.");
        }
        return List.of(new Finding(CHECK_ID, Severity.PASS, "Access token obtained", explanation.toString(),
                evidence, null));
    }

    /**
     * The seconds the router SDK caches a fractional JSON {@code expires_in} for, before its 24 h cap, or
     * {@code null} if it caches nothing. Jackson reads a fraction as a double, whose {@code canConvertToLong()}
     * checks only the range and whose {@code asLong()} truncates; the SDK caches only a positive result.
     */
    static Long sdkTruncatedSeconds(String sent) {
        if (sent == null || !JSON_FLOAT.matcher(sent).matches()) {
            return null;
        }
        double value = Double.parseDouble(sent);
        long seconds = (long) value;
        return value <= Long.MAX_VALUE && seconds > 0 ? seconds : null;
    }
}
