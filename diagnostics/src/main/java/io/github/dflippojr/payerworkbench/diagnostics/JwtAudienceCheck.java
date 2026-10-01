package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code auth.jwt-audience}: a request carrying a JWT was rejected and the JWT's
 * {@code aud} claim is not exactly the URL it was sent to (a trailing slash, a
 * missing or extra {@code /r4} path segment, a different host). Payers compare
 * {@code aud} as an exact string.
 *
 * <p>Two kinds of JWT are examined. A {@code client_assertion} in a token request
 * body keeps its claims after redaction, so it is read from the recorded request.
 * A CDS Hooks client JWT travels as a bearer token, which {@code Redactor} masks
 * whole, so its claims come from {@link HookResponse#clientJwt()}. When a hook
 * call's {@code aud} already is the service URL, a 401 whose error is about the
 * audience means the payer validates against some other URL; that FAILs too.
 */
public final class JwtAudienceCheck implements DiagnosticCheck {

    public static final String ID = "auth.jwt-audience";

    private static final Pattern CITES_AUDIENCE = Pattern.compile("\\baud\\b|audience");
    private static final Pattern URL = Pattern.compile("https?://[^\\s'\"<>,\\[\\]]+");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        List<String> verified = new ArrayList<>();
        for (HttpExchange exchange : obs.exchanges()) {
            String target = Support.withoutQuery(exchange.url());
            for (JsonNode claims : Support.requestJwtClaims(exchange)) {
                List<String> auds = Support.stringValues(claims.get("aud"));
                if (auds.isEmpty()) {
                    continue;
                }
                if (auds.contains(target)) {
                    if (Support.isSuccess(exchange.status())) {
                        verified.add(target);
                    }
                    continue;
                }
                mismatch(exchange, auds, target, "the JWT it carried", isRejected(exchange)).ifPresent(findings::add);
            }
        }
        for (HookResponse hook : obs.hookResponses()) {
            JwtClaims jwt = hook.clientJwt();
            if (jwt == null || jwt.aud().isEmpty()) {
                continue;
            }
            HttpExchange exchange = hook.exchange();
            String target = Support.withoutQuery(exchange.url());
            if (!jwt.aud().contains(target)) {
                mismatch(exchange, jwt.aud(), target, "the CDS Hooks client JWT sent as its bearer token",
                        exchange.status() == 401).ifPresent(findings::add);
            } else if (exchange.status() == 401 && citesAudience(exchange)) {
                findings.add(otherAudienceExpected(exchange, jwt, target));
            } else if (Support.isSuccess(exchange.status())) {
                verified.add(target);
            }
        }
        if (findings.isEmpty() && !verified.isEmpty()) {
            findings.add(new Finding(ID, Severity.PASS, "JWT audience matches the target URL",
                    "Every JWT the workbench could inspect named exactly the URL it was sent to as its audience.",
                    "verified: " + String.join(", ", verified.stream().distinct().toList()), null));
        }
        return findings;
    }

    /**
     * Whether this check FAILs the hook call, so {@code response.schema} need not
     * report the same 401 again.
     */
    static boolean explains(HookResponse hook) {
        JwtClaims jwt = hook.clientJwt();
        HttpExchange exchange = hook.exchange();
        if (jwt == null || jwt.aud().isEmpty() || exchange.status() != 401) {
            return false;
        }
        return !jwt.aud().contains(Support.withoutQuery(exchange.url())) || citesAudience(exchange);
    }

    private static Optional<Finding> mismatch(HttpExchange exchange, List<String> auds, String target, String carrier,
            boolean rejected) {
        String aud = auds.get(0);
        String evidence = Support.describe(exchange) + "\nJWT aud: " + String.join(", ", auds)
                + "\nrequest URL: " + target;
        if (rejected) {
            return Optional.of(new Finding(ID, Severity.FAIL, "JWT audience does not match the URL it was sent to",
                    "The request was rejected, and " + carrier + " names a different audience (the aud claim, "
                            + "which says which server the token is meant for) than the URL it was sent to: "
                            + difference(aud, target) + ". Servers compare aud character for character, so even "
                            + "a trailing slash makes it invalid.",
                    evidence,
                    "Set the JWT aud to exactly " + target + " (copy it from the URL the request goes to, not "
                            + "from the base URL in the connection record), then retry."));
        }
        if (Support.isSuccess(exchange.status())) {
            return Optional.of(new Finding(ID, Severity.INFO, "Payer accepted a JWT whose audience differs from the URL",
                    "This payer accepted the JWT even though its aud claim (the server the token is meant for) "
                            + "is not exactly the URL it was sent to: " + difference(aud, target) + ". A stricter "
                            + "environment of the same payer may reject it.",
                    evidence,
                    "Set the JWT aud to exactly " + target + " so the integration does not depend on lenient "
                            + "validation."));
        }
        return Optional.empty();
    }

    private static Finding otherAudienceExpected(HttpExchange exchange, JwtClaims jwt, String target) {
        Optional<String> named = urlNamedByPayer(exchange, target);
        String evidence = Support.describe(exchange) + "\nJWT aud: " + String.join(", ", jwt.aud())
                + "\nrequest URL: " + target + named.map(url -> "\nURL named in the payer's error: " + url).orElse("");
        return new Finding(ID, Severity.FAIL, "Payer expects a different JWT audience",
                "The hook call was rejected with 401 and the payer's error is about the audience (the aud claim, "
                        + "which says which server the token is meant for). The CDS Hooks client JWT already names "
                        + "exactly the URL it was sent to, so the payer checks aud against some other URL"
                        + named.map(url -> ", apparently " + url).orElse("") + ". Payers usually do this when "
                        + "they validate against their public URL behind a gateway, or against another "
                        + "environment's URL.",
                evidence,
                "Ask the payer which exact URL they expect as aud for this service. If the service is published "
                        + "at that URL, point the connection's base URL there so calls and aud both use it; "
                        + "otherwise ask the payer to accept " + target + ".");
    }

    /** The first URL in the payer's error that is not the URL the request went to. */
    private static Optional<String> urlNamedByPayer(HttpExchange exchange, String target) {
        Matcher m = URL.matcher(exchange.responseBody() == null ? "" : exchange.responseBody());
        while (m.find()) {
            if (!m.group().equals(target)) {
                return Optional.of(m.group());
            }
        }
        return Optional.empty();
    }

    private static boolean citesAudience(HttpExchange exchange) {
        String said = Support.lower(exchange.responseBody()) + "\n"
                + Support.lower(Support.header(exchange.responseHeaders(), "WWW-Authenticate").orElse(""));
        return CITES_AUDIENCE.matcher(said).find();
    }

    private static boolean isRejected(HttpExchange exchange) {
        if (exchange.status() == 401) {
            return true;
        }
        if (exchange.status() == 400) {
            String body = Support.lower(exchange.responseBody());
            return body.contains("invalid_client") || body.contains("invalid_grant");
        }
        return false;
    }

    /** Plain-language description of how {@code aud} differs from {@code target}. */
    static String difference(String aud, String target) {
        if (aud.equalsIgnoreCase(target)) {
            return "they differ only in upper/lower case";
        }
        if (stripSlash(aud).equals(stripSlash(target))) {
            return aud.endsWith("/") ? "aud has a trailing slash the URL lacks" : "the URL has a trailing slash aud lacks";
        }
        try {
            URI a = URI.create(aud);
            URI t = URI.create(target);
            if (a.getScheme() != null && !a.getScheme().equalsIgnoreCase(t.getScheme())) {
                return "aud uses " + a.getScheme() + " but the URL uses " + t.getScheme();
            }
            if (a.getHost() != null && !a.getHost().equalsIgnoreCase(t.getHost())) {
                return "aud names host " + a.getHost() + " but the request went to " + t.getHost();
            }
            if (a.getPort() != t.getPort()) {
                return "aud names port " + a.getPort() + " but the request went to port " + t.getPort();
            }
            String ap = stripSlash(nullToEmpty(a.getPath()));
            String tp = stripSlash(nullToEmpty(t.getPath()));
            String extra = segmentDifference(tp, ap);
            if (extra != null) {
                return "aud lacks the path segment " + extra + " that the URL has";
            }
            extra = segmentDifference(ap, tp);
            if (extra != null) {
                return "aud has the extra path segment " + extra + " that the URL lacks";
            }
            return "aud path " + (ap.isEmpty() ? "/" : ap) + " differs from the URL path " + (tp.isEmpty() ? "/" : tp);
        } catch (IllegalArgumentException e) {
            return "aud is \"" + aud + "\"";
        }
    }

    /** If {@code longer} is {@code shorter} with path segments inserted at one place, those segments. */
    private static String segmentDifference(String longer, String shorter) {
        List<String> l = segments(longer);
        List<String> s = segments(shorter);
        int k = l.size() - s.size();
        if (k <= 0) {
            return null;
        }
        for (int i = 0; i <= s.size(); i++) {
            if (l.subList(0, i).equals(s.subList(0, i)) && l.subList(i + k, l.size()).equals(s.subList(i, s.size()))) {
                return "/" + String.join("/", l.subList(i, i + k));
            }
        }
        return null;
    }

    private static List<String> segments(String path) {
        return Arrays.stream(path.split("/")).filter(seg -> !seg.isEmpty()).toList();
    }

    private static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
