package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * {@code auth.clock-skew}: a measured JWT issue-time difference beyond tolerance,
 * a rejected JWT whose exp the payer's clock has passed, or an explicit payer
 * error indicating a clock difference. An expiry error with no JWT time to
 * measure does not establish skew: the credential may simply be stale.
 *
 * <p>The JWT times come from the claims the caller recorded: a hook call's
 * {@link HookResponse#clientJwt()} and the run's {@link RunObservations#clientAssertion()}
 * on the token exchange. A JWT readable in the recorded request is the fallback,
 * because {@code Redactor} masks a bearer JWT whole.
 */
public final class ClockSkewCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "auth.clock-skew";

    private static final Pattern TIME_ERROR = Pattern.compile(
            "(?i)\\b(not yet valid|issued in the future|in the future|clock|skew|used before)\\b");

    private final Duration tolerance;

    public ClockSkewCheck(Duration tolerance) {
        this.tolerance = Objects.requireNonNull(tolerance, "tolerance");
    }

    @Override
    public String id() {
        return CHECK_ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        List<String> verified = new ArrayList<>();
        for (HttpExchange exchange : obs.exchanges()) {
            Optional<Instant> serverNow = Support.serverDate(exchange);
            Measurement m = serverNow.map(now -> measure(obs, exchange, now)).orElse(null);
            boolean rejected = exchange.status() == 400 || exchange.status() == 401 || exchange.status() == 403;
            boolean timeError = rejected && exchange.responseBody() != null
                    && TIME_ERROR.matcher(exchange.responseBody()).find();
            boolean skewed = m != null && (m.skewOverTolerance(tolerance));

            if (rejected && (timeError || skewed || (m != null && m.expired()))) {
                findings.add(new Finding(CHECK_ID, Severity.FAIL, "Rejection consistent with clock skew",
                        "The payer rejected the request" + (timeError ? " with an error about token timing" : "")
                                + (m == null ? "" : ", and " + m.describe(tolerance))
                                + ". Signed JWTs carry iat (issued-at) and exp (expiry) times, and the payer "
                                + "rejects them if its own clock disagrees by more than a small margin, so a "
                                + "client clock that is off makes valid credentials look expired or not yet valid.",
                        Support.describe(exchange) + (m == null ? "" : "\n" + m.evidence()),
                        "Sync the client host's clock with NTP and re-run; set iat to the current time and exp "
                                + "no more than 5 minutes later, as SMART Backend Services requires."));
            } else if (Support.isSuccess(exchange.status()) && skewed) {
                findings.add(new Finding(CHECK_ID, Severity.WARN, "Client clock differs from the payer's",
                        "The request succeeded, but " + m.describe(tolerance) + ". A payer with a stricter tolerance "
                                + "for JWT iat (issued-at) and exp (expiry) times would reject it.",
                        Support.describe(exchange) + "\n" + m.evidence(),
                        "Sync the client host's clock with NTP."));
            } else if (m != null && m.iat() != null && Support.isSuccess(exchange.status())) {
                verified.add(exchange.url() + " (iat offset " + m.skewSeconds() + " s)");
            }
        }
        if (findings.isEmpty() && !verified.isEmpty()) {
            findings.add(new Finding(CHECK_ID, Severity.PASS, "Client and payer clocks agree",
                    "JWT issue times were within " + tolerance.toSeconds() + " seconds of the payer's clock "
                            + "(its Date response header).",
                    String.join("\n", verified), null));
        }
        return findings;
    }

    private static Measurement measure(RunObservations obs, HttpExchange exchange, Instant serverNow) {
        JwtClaims recorded = recordedClaims(obs, exchange);
        if (recorded != null && (recorded.iat() != null || recorded.exp() != null)) {
            return new Measurement(recorded.iat(), recorded.exp(), serverNow);
        }
        for (JsonNode claims : Support.requestJwtClaims(exchange)) {
            Instant iat = numericDate(claims.get("iat"));
            Instant exp = numericDate(claims.get("exp"));
            if (iat != null || exp != null) {
                return new Measurement(iat, exp, serverNow);
            }
        }
        return null;
    }

    /** A NumericDate claim, or null when it is missing, not a number or beyond the seconds an Instant holds. */
    private static Instant numericDate(JsonNode claim) {
        long seconds = claim != null && claim.canConvertToLong() ? claim.asLong() : Long.MIN_VALUE;
        return seconds >= Instant.MIN.getEpochSecond() && seconds <= Instant.MAX.getEpochSecond()
                ? Instant.ofEpochSecond(seconds) : null;
    }

    /** The client JWT claims recorded for this exchange: a hook call's client JWT or the token request's assertion. */
    private static JwtClaims recordedClaims(RunObservations obs, HttpExchange exchange) {
        for (HookResponse hook : obs.hookResponses()) {
            if (hook.clientJwt() != null && hook.exchange().equals(exchange)) {
                return hook.clientJwt();
            }
        }
        if (obs.clientAssertion() != null
                && Support.tokenExchange(obs).filter(exchange::equals).isPresent()) {
            return obs.clientAssertion();
        }
        return null;
    }

    /** The JWT times of one exchange; {@code iat} is null when the JWT has none, and then no skew is measured. */
    private record Measurement(Instant iat, Instant exp, Instant serverNow) {

        /** Seconds from the payer's clock to iat; call only when iat is present. */
        long skewSeconds() {
            return Duration.between(serverNow, iat).toSeconds();
        }

        boolean skewOverTolerance(Duration tolerance) {
            return iat != null && Math.abs(skewSeconds()) > tolerance.toSeconds();
        }

        boolean expired() {
            return exp != null && exp.isBefore(serverNow);
        }

        String describe(Duration tolerance) {
            if (iat == null && !expired()) {
                return "the JWT has no iat (issued-at), so its issue time could not be compared with the payer's "
                        + "clock";
            }
            if (!skewOverTolerance(tolerance) && !expired()) {
                return "the JWT times were within " + tolerance.toSeconds() + " seconds of the payer's clock, "
                        + "so check the JWT lifetime (exp minus iat) as well";
            }
            if (iat != null && skewSeconds() > 0) {
                return "the JWT says it was issued " + skewSeconds() + " seconds after the payer's current time "
                        + "(the client clock is ahead)";
            }
            if (expired()) {
                return "the JWT had already expired by the payer's clock ("
                        + Duration.between(exp, serverNow).toSeconds() + " seconds ago; the client clock is behind "
                        + "or the JWT was reused)";
            }
            if (iat != null && skewSeconds() < 0) {
                return "the JWT says it was issued " + -skewSeconds() + " seconds before the payer's current time "
                        + "(the client clock is behind)";
            }
            return "the JWT times disagree with the payer's clock";
        }

        String evidence() {
            return "JWT iat=" + (iat == null ? "(none)" : iat) + ", exp=" + exp + "; payer Date header=" + serverNow
                    + (iat == null ? "" : "; iat offset=" + skewSeconds() + " s");
        }
    }
}
