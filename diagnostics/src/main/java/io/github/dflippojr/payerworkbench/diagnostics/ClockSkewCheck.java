package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
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
 * or an explicit payer error indicating a clock difference. Expiry alone does
 * not establish skew: the credential may simply be stale.
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
            List<JsonNode> jwts = Support.requestJwtClaims(exchange);
            Measurement m = serverNow.map(now -> measure(jwts, now)).orElse(null);
            boolean rejected = exchange.status() == 400 || exchange.status() == 401 || exchange.status() == 403;
            boolean timeError = rejected && exchange.responseBody() != null
                    && TIME_ERROR.matcher(exchange.responseBody()).find();
            boolean skewed = m != null && (m.skewOverTolerance(tolerance));

            if (rejected && (timeError || skewed)) {
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
            } else if (m != null && Support.isSuccess(exchange.status())) {
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

    private static Measurement measure(List<JsonNode> jwts, Instant serverNow) {
        for (JsonNode claims : jwts) {
            JsonNode iat = claims.get("iat");
            JsonNode exp = claims.get("exp");
            if ((iat != null && iat.canConvertToLong()) || (exp != null && exp.canConvertToLong())) {
                return new Measurement(
                        iat != null && iat.canConvertToLong() ? Instant.ofEpochSecond(iat.asLong()) : null,
                        exp != null && exp.canConvertToLong() ? Instant.ofEpochSecond(exp.asLong()) : null,
                        serverNow);
            }
        }
        return null;
    }

    private record Measurement(Instant iat, Instant exp, Instant serverNow) {

        long skewSeconds() {
            return iat == null ? 0 : Duration.between(serverNow, iat).toSeconds();
        }

        boolean skewOverTolerance(Duration tolerance) {
            return iat != null && Math.abs(skewSeconds()) > tolerance.toSeconds();
        }

        boolean expired() {
            return exp != null && exp.isBefore(serverNow);
        }

        String describe(Duration tolerance) {
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
            return "JWT iat=" + iat + ", exp=" + exp + "; payer Date header=" + serverNow
                    + "; iat offset=" + skewSeconds() + " s";
        }
    }
}
