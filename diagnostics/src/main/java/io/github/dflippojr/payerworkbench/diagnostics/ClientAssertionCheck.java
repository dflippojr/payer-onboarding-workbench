package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/** Diagnoses SMART Backend Services assertion claims without retaining a signed assertion. */
public final class ClientAssertionCheck implements DiagnosticCheck {
    public static final String CHECK_ID = "auth.client-assertion";
    @Override public String id() { return CHECK_ID; }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        JwtClaims claims = obs.clientAssertion();
        if (claims == null) { return List.of(); }
        TokenResponseMetadata token = obs.tokenResponse();
        String evidence = "sent iss=" + claims.iss() + ", sub=" + claims.sub() + ", aud=" + claims.aud()
                + ", exp=" + claims.exp() + ", iat=" + claims.iat() + ", jti=" + claims.jti() + ", kid=" + claims.kid()
                + "\nexpected client id=" + obs.connection().clientId()
                + ", token endpoint aud=" + obs.connection().tokenEndpoint();
        String cause = claimProblem(obs, claims);
        if (token != null && token.errorDescription() != null) {
            evidence += "\npayer error_description: " + token.errorDescription();
        }
        if (cause == null && token != null && "invalid_client".equals(token.error())) {
            cause = token.errorDescription() == null ? "The payer rejected the client assertion" : token.errorDescription();
        }
        if (cause != null) {
            return List.of(new Finding(CHECK_ID, Severity.FAIL, "Client assertion rejected: " + cause,
                    "The SMART Backend Services token request could not authenticate the client assertion.", evidence,
                    "Set iss and sub to the registered client id, aud to the payer's exact token endpoint, "
                            + "exp at most five minutes after iat, and use a fresh jti for each request. "
                            + "For signature or kid errors, register the matching public JWKS with the payer."));
        }
        if (token != null && token.error() == null && token.accessTokenPresent()
                && Support.tokenExchange(obs).map(e -> Support.isSuccess(e.status())).orElse(false)) {
            return List.of(new Finding(CHECK_ID, Severity.PASS, "Client assertion accepted",
                    "The token endpoint issued an access token for this signed client assertion.", evidence, null));
        }
        return List.of();
    }

    private static String claimProblem(RunObservations obs, JwtClaims claims) {
        if (!Objects.equals(obs.connection().clientId(), claims.iss())
                || !Objects.equals(obs.connection().clientId(), claims.sub())) {
            return "iss and sub must equal the registered client id";
        }
        if (!List.of(obs.connection().tokenEndpoint()).equals(claims.aud())) {
            return "aud must equal '" + obs.connection().tokenEndpoint() + "', sent " + claims.aud();
        }
        if (claims.exp() == null || claims.iat() == null || !claims.exp().isAfter(claims.iat())
                || Duration.between(claims.iat(), claims.exp()).compareTo(Duration.ofMinutes(5)) > 0) {
            return "exp/iat lifetime must be positive and at most 5 minutes";
        }
        var payerTime = Support.tokenExchange(obs).flatMap(Support::serverDate);
        if (payerTime.isPresent() && (!claims.exp().isAfter(payerTime.get())
                || claims.exp().isAfter(payerTime.get().plus(Duration.ofMinutes(5))))) {
            return "exp must be in the future and at most 5 minutes ahead of the payer clock";
        }
        if (claims.jti() == null || claims.jti().isBlank()) { return "jti is required for replay protection"; }
        return null;
    }
}
