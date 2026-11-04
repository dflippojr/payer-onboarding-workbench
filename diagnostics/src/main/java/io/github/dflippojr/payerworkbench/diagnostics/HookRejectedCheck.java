package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Explains resource-server credential rejections, leaving client JWT audiences to their specific check. */
public final class HookRejectedCheck implements DiagnosticCheck {
    public static final String CHECK_ID = "auth.hook-rejected";

    @Override
    public String id() {
        return CHECK_ID;
    }

    static boolean explains(HookResponse hook) {
        int status = hook.exchange().status();
        return (status == 401 || status == 403) && !JwtAudienceCheck.explains(hook);
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        for (HookResponse hook : obs.hookResponses()) {
            if (!explains(hook)) {
                continue;
            }
            HttpExchange exchange = hook.exchange();
            String header = Support.header(exchange.responseHeaders(), "WWW-Authenticate").orElse("");
            JsonNode body = Support.parseJson(exchange.responseBody()).orElse(null);
            // Several challenges: the parameters come from the first one carrying an error (AuthChallenge.param).
            List<AuthChallenge> challenges = AuthChallenge.parse(header);
            String error = value(challenges, body, "error");
            String reason = value(challenges, body, "error_description");
            String scope = value(challenges, body, "scope");
            String scheme = AuthChallenge.scheme(challenges).orElse("unspecified");
            // A run with authType NONE sends no Authorization header; say so rather than blame a token.
            boolean unauthenticated = hook.clientJwt() == null
                    && Support.header(exchange.requestHeaders(), "Authorization").isEmpty();
            String credential = hook.clientJwt() == null ? "access token" : "CDS Hooks client JWT";
            String rejected = unauthenticated
                    ? "The hook request carried no credentials, and the payer asks for " + scheme + " authentication."
                    : "The payer rejected the " + credential + " using " + scheme + " authentication.";
            findings.add(new Finding(CHECK_ID, Severity.FAIL,
                    (unauthenticated ? "Hook request without credentials rejected by " : "Hook credential rejected by ")
                            + hook.serviceId() + " (HTTP " + exchange.status() + ")",
                    rejected + " Reason: "
                            + (reason.isBlank() ? (error.isBlank() ? "payer supplied no reason" : error) : reason)
                            + (scope.isBlank() ? "" : ". Required scope: " + scope) + ".",
                    Support.describe(exchange) + "\nWWW-Authenticate: " + (header.isBlank() ? "(missing)" : header),
                    unauthenticated ? "Configure the authentication this payer requires (an authType other than "
                            + "NONE, with its client id and credential) and run again." : fix(error, scope)));
        }
        return findings;
    }

    private static String value(List<AuthChallenge> challenges, JsonNode body, String name) {
        Optional<String> param = AuthChallenge.param(challenges, name);
        if (param.isPresent()) {
            return param.get();
        }
        return body == null ? "" : body.path(name).asText("");
    }

    private static String fix(String error, String scope) {
        return switch (Support.lower(error)) {
            case "invalid_token" -> "Obtain a fresh access token or sign a new client JWT; verify expiry, issuer, audience "
                    + "and signing keys against the payer's requirements.";
            case "insufficient_scope" -> "Request and obtain the payer's required scopes"
                    + (scope.isBlank() ? "" : ": " + scope) + " before calling the hook again.";
            case "invalid_request" -> "Correct the authentication request: send one well-formed Authorization header "
                    + "with the required scheme and credential; avoid duplicate token parameters.";
            default -> "Verify the credential type, registered client id, signing keys and permissions with the payer; "
                    + "use the quoted error to correct the rejected credential.";
        };
    }
}
