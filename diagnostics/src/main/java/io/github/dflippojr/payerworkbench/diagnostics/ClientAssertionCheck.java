package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Diagnoses SMART Backend Services assertion claims without retaining a signed assertion.
 *
 * <p>The payer's clock is blamed only when no token was issued, the rejection points at the
 * assertion ({@code invalid_client}, or error text naming {@code exp}, {@code iat}, {@code nbf} or
 * {@code expired}), the assertion's {@code iat} is more than the clock-skew tolerance from the
 * payer's {@code Date} (measured as {@code auth.clock-skew} measures it), and {@code exp} falls
 * outside the payer clock's five-minute window.
 */
public final class ClientAssertionCheck implements DiagnosticCheck {
    public static final String CHECK_ID = "auth.client-assertion";
    private static final Pattern ASSERTION_TIME_WORD = Pattern.compile("(?i)\\b(exp|iat|nbf|expired)\\b");

    private final Duration clockSkewTolerance;

    /** Uses the default {@link DiagnosticsConfig#clockSkewTolerance()}. */
    public ClientAssertionCheck() {
        this(DiagnosticsConfig.defaults().clockSkewTolerance());
    }

    /** @param clockSkewTolerance the {@code auth.clock-skew} tolerance; an offset strictly greater is over it */
    public ClientAssertionCheck(Duration clockSkewTolerance) {
        this.clockSkewTolerance = Objects.requireNonNull(clockSkewTolerance, "clockSkewTolerance");
    }

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
        boolean issued = token != null && token.error() == null && token.accessTokenPresent()
                && Support.tokenExchange(obs).map(e -> Support.isSuccess(e.status())).orElse(false);
        String cause = claimProblem(obs, claims, issued ? null : token);
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
        if (issued) {
            return List.of(new Finding(CHECK_ID, Severity.PASS, "Client assertion accepted",
                    "The token endpoint issued an access token for this signed client assertion.", evidence, null));
        }
        return List.of();
    }

    /**
     * A claim the client got wrong. The comparison with the payer's {@code Date} only explains a
     * rejection of the assertion: a payer that issued a token accepted the times within its own
     * clock-skew leeway (RFC 7523 §3), a rejection for another reason (a scope, a 5xx) says nothing
     * about them, and an offset within tolerance is not clock evidence. {@code rejection} is the
     * token response when no token was issued, else null.
     */
    private String claimProblem(RunObservations obs, JwtClaims claims, TokenResponseMetadata rejection) {
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
        Optional<Instant> payerTime = Support.tokenExchange(obs).flatMap(Support::serverDate);
        if (pointsAtAssertion(rejection) && payerTime.isPresent()
                && Support.iatOffsetOverTolerance(claims.iat(), payerTime.get(), clockSkewTolerance)
                && (!claims.exp().isAfter(payerTime.get())
                        || claims.exp().isAfter(payerTime.get().plus(Duration.ofMinutes(5))))) {
            return "exp must be in the future and at most 5 minutes ahead of the payer clock";
        }
        if (claims.jti() == null || claims.jti().isBlank()) { return "jti is required for replay protection"; }
        return null;
    }

    /** True when the payer's error is {@code invalid_client} or its text names an assertion time claim. */
    private static boolean pointsAtAssertion(TokenResponseMetadata rejection) {
        return rejection != null && ("invalid_client".equals(rejection.error())
                || namesAssertionTime(rejection.error()) || namesAssertionTime(rejection.errorDescription()));
    }

    private static boolean namesAssertionTime(String text) {
        return text != null && ASSERTION_TIME_WORD.matcher(text).find();
    }
}
