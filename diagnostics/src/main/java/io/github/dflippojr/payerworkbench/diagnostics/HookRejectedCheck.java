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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Explains resource-server credential rejections, leaving client JWT audiences to their specific check. */
public final class HookRejectedCheck implements DiagnosticCheck {
    public static final String CHECK_ID = "auth.hook-rejected";
    // Quoted strings may contain commas and escaped quotes; do not split the header on commas.
    private static final Pattern PARAMETER = Pattern.compile(
            "(?i)(error_description|error|scope)\\s*=\\s*(?:\"((?:\\\\.|[^\"\\\\])*)\"|([^,\\s]+))");

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
            String error = value(header, body, "error");
            String reason = value(header, body, "error_description");
            String scope = value(header, body, "scope");
            String scheme = header.isBlank() ? "unspecified" : header.strip().split("\\s+", 2)[0];
            String credential = hook.clientJwt() == null ? "access token" : "CDS Hooks client JWT";
            findings.add(new Finding(CHECK_ID, Severity.FAIL,
                    "Hook credential rejected by " + hook.serviceId() + " (HTTP " + exchange.status() + ")",
                    "The payer rejected the " + credential + " using " + scheme + " authentication. Reason: "
                            + (reason.isBlank() ? (error.isBlank() ? "payer supplied no reason" : error) : reason)
                            + (scope.isBlank() ? "" : ". Required scope: " + scope) + ".",
                    Support.describe(exchange) + "\nWWW-Authenticate: " + (header.isBlank() ? "(missing)" : header),
                    fix(error, scope)));
        }
        return findings;
    }

    private static String value(String header, JsonNode body, String name) {
        Matcher matcher = PARAMETER.matcher(header);
        while (matcher.find()) {
            if (matcher.group(1).equalsIgnoreCase(name)) {
                return matcher.group(2) == null ? matcher.group(3)
                        : matcher.group(2).replace("\\\"", "\"").replace("\\\\", "\\");
            }
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
