package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Class-level guard for #217: the payer's clock does not depend on which HTTP-date form its {@code Date}
 * header uses. RFC 9110 section 5.6.7 requires a recipient to accept all three forms, so a run whose payer
 * dates are RFC 850 or asctime must produce the same findings as the same run dated IMF-fixdate. A form that
 * is dropped instead turns the clock measurement off without a word.
 *
 * <p>The scenarios reach the three checks that read the payer's {@code Date} header: {@code auth.clock-skew}
 * and {@code auth.client-assertion} through an accepted or a rejected token exchange with a client assertion,
 * and {@code perf.rate-limit} through a 429 whose {@code Retry-After} is an absolute time.
 */
class HttpDateFormsInvariantTest {

    enum Scenario { ACCEPTED, REJECTED, THROTTLED }

    static Stream<Arguments> offsetsInObsoleteForms() {
        return LongStream.of(-3600, -361, -120, -61, -60, -59, -1, 0, 1, 59, 60, 61, 120, 361, 3600)
                .boxed()
                .flatMap(offset -> Stream.of("RFC 850", "asctime")
                        .flatMap(form -> Stream.of(Scenario.values())
                                .map(scenario -> Arguments.of(offset, form, scenario))));
    }

    @ParameterizedTest(name = "payer clock {0} s from the client's, Date as {1}, {2}")
    @MethodSource("offsetsInObsoleteForms")
    void findingsDoNotDependOnTheDateForm(long offsetSeconds, String form, Scenario scenario) {
        assertEquals(findings(offsetSeconds, "IMF-fixdate", scenario), findings(offsetSeconds, form, scenario));
    }

    private static List<Finding> findings(long offsetSeconds, String form, Scenario scenario) {
        Instant payerNow = NOW.plusSeconds(offsetSeconds);
        Run run = healthy();
        run.clientAssertion = new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(300), NOW, "jti-217",
                "synthetic-kid", CLIENT_ID);
        run.discovery = withDate(run.discovery, inForm(payerNow, form));
        run.token = withDate(run.token, inForm(payerNow, form));
        if (scenario == Scenario.REJECTED) {
            run.token = respond(run.token, 401, run.token.responseHeaders(), "{\"error\":\"invalid_client\"}");
            run.tokenResponse = tokenError("invalid_client", "The client assertion was rejected");
        }
        List<HookResponse> hooks = new ArrayList<>();
        for (HookResponse h : run.hooks) {
            HttpExchange e = withDate(h.exchange(), inForm(payerNow, form));
            e = switch (scenario) {
                case ACCEPTED -> e;
                case REJECTED -> respond(e, 401, e.responseHeaders(),
                        "{\"error\":\"invalid_token\",\"error_description\":\"The token is not yet valid\"}");
                case THROTTLED -> respond(e, 429, withRetryAfter(e.responseHeaders()), "{\"error\":\"rate_limited\"}");
            };
            hooks.add(orderSign(e, ORDER_SIGN_URL));
        }
        run.hooks = hooks;
        return new DiagnosticEngine().run(run.build());
    }

    /** {@code date} written as the payer would send it in the named form. */
    private static String inForm(Instant date, String form) {
        ZonedDateTime utc = date.atZone(ZoneOffset.UTC);
        return switch (form) {
            case "IMF-fixdate" -> httpDate(date);
            case "RFC 850" -> DateTimeFormatter.ofPattern("EEEE, dd-MMM-uu HH:mm:ss 'GMT'", Locale.US).format(utc);
            case "asctime" -> String.format(Locale.US, "%1$ta %1$tb %2$2d %1$tT %1$tY", utc, utc.getDayOfMonth());
            default -> throw new IllegalArgumentException(form);
        };
    }

    private static HttpExchange withDate(HttpExchange e, String date) {
        Map<String, List<String>> headers = new LinkedHashMap<>(e.responseHeaders());
        headers.keySet().removeIf("Date"::equalsIgnoreCase);
        headers.put("Date", List.of(date));
        return new HttpExchange(e.method(), e.url(), e.status(), e.latency(), e.requestHeaders(), e.requestBody(),
                headers, e.responseBody(), e.transportError());
    }

    /** {@code e} with another status, headers and body, the same request. */
    private static HttpExchange respond(HttpExchange e, int status, Map<String, List<String>> headers, String body) {
        return new HttpExchange(e.method(), e.url(), status, e.latency(), e.requestHeaders(), e.requestBody(),
                headers, body, e.transportError());
    }

    private static Map<String, List<String>> withRetryAfter(Map<String, List<String>> headers) {
        Map<String, List<String>> out = new LinkedHashMap<>(headers);
        out.put("Retry-After", List.of(httpDate(NOW.plusSeconds(30))));
        return out;
    }
}
