package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Class-level guard for #215: when the payer accepted every request, a difference
 * between its clock (the {@code Date} header) and the client's is never a FAIL from
 * any check. The payer's own answer shows the time claims were acceptable to it;
 * a measured offset may only be reported as a WARN by {@code auth.clock-skew}.
 * The sweep runs the default engine over every second within six minutes either
 * way, then out to an hour.
 */
class PayerClockOffsetInvariantTest {

    static Stream<Long> payerClockOffsets() {
        return Stream.concat(LongStream.rangeClosed(-360, 360).boxed(),
                Stream.of(-3600L, -900L, -600L, 600L, 900L, 3600L));
    }

    @ParameterizedTest(name = "payer clock {0} s from the client's")
    @MethodSource("payerClockOffsets")
    void acceptedRunIsNeverFailedForAClockOffset(long offsetSeconds) {
        Instant payerNow = NOW.plusSeconds(offsetSeconds);
        Run run = healthy();
        run.discovery = withDate(run.discovery, payerNow);
        run.token = withDate(run.token, payerNow);
        run.clientAssertion = new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(300), NOW, "jti-215",
                "synthetic-kid", CLIENT_ID);
        List<HookResponse> hooks = new ArrayList<>();
        for (HookResponse h : run.hooks) {
            hooks.add(orderSign(withDate(h.exchange(), payerNow), ORDER_SIGN_URL));
        }
        run.hooks = hooks;

        List<Finding> findings = new DiagnosticEngine().run(run.build());

        assertTrue(findings.stream().noneMatch(f -> f.severity() == Severity.FAIL),
                () -> "payer accepted every request with its clock " + offsetSeconds + " s off, yet: " + findings);
    }

    private static HttpExchange withDate(HttpExchange e, Instant date) {
        Map<String, List<String>> headers = new LinkedHashMap<>(e.responseHeaders());
        headers.keySet().removeIf("Date"::equalsIgnoreCase);
        headers.put("Date", List.of(httpDate(date)));
        return new HttpExchange(e.method(), e.url(), e.status(), e.latency(), e.requestHeaders(), e.requestBody(),
                headers, e.responseBody(), e.transportError());
    }
}
