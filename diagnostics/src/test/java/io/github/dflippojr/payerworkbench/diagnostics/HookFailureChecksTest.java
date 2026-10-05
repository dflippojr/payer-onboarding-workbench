package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class HookFailureChecksTest {
    private Fixtures.Run run(int status, Map<String, List<String>> headers, String body) {
        var run = Fixtures.healthy();
        run.hooks = List.of(Fixtures.orderSign(new HttpExchange("POST", Fixtures.ORDER_SIGN_URL, status,
                Duration.ofMillis(20), Map.of("Authorization", List.of("Bearer secret-value")), null,
                headers, body, null)));
        return run;
    }

    @ParameterizedTest
    @CsvSource({"invalid_token,fresh access token", "insufficient_scope,required scopes", "invalid_request,Authorization header"})
    void rfc6750ErrorsHaveSpecificFixes(String error, String fix) {
        var obs = run(403, Map.of("www-authenticate", List.of("Bearer error=\"" + error
                + "\", error_description=\"Rejected, please correct\", scope=\"system/*.read\"")), "{}").build();
        var finding = Fixtures.assertOnly(new HookRejectedCheck().evaluate(obs), Severity.FAIL);
        assertTrue(finding.suggestedFix().contains(fix));
        assertTrue(finding.explanation().contains("access token using Bearer"));
        assertTrue(finding.explanation().contains("Rejected, please correct"));
        assertTrue(finding.explanation().contains("system/*.read"));
        assertTrue(finding.evidence().contains("WWW-Authenticate: Bearer"));
        assertTrue(new ResponseSchemaCheck().evaluate(obs).isEmpty());
        assertFalse(finding.toString().contains("secret-value"));
    }

    @Test
    void unquotedHeaderErrorOverridesBody() {
        var finding = Fixtures.assertOnly(new HookRejectedCheck().evaluate(run(401,
                Map.of("WWW-Authenticate", List.of("Bearer error=invalid_request")),
                "{\"error\":\"invalid_token\",\"error_description\":\"Duplicate credentials\"}").build()), Severity.FAIL);
        assertTrue(finding.suggestedFix().contains("duplicate token parameters"));
        assertTrue(finding.explanation().contains("Duplicate credentials"));
    }

    @Test
    void escapedQuotesInChallengeAreParsed() {
        var finding = Fixtures.assertOnly(new HookRejectedCheck().evaluate(run(401,
                Map.of("WWW-Authenticate", List.of("Bearer error=\"invalid_token\", error_description=\"Rejected \\\"credential\\\"\"")),
                "{}").build()), Severity.FAIL);
        assertTrue(finding.explanation().contains("Rejected \"credential\""));
    }

    @Test
    void missingHeaderUsesJsonError() {
        var finding = Fixtures.assertOnly(new HookRejectedCheck().evaluate(run(401, Map.of(),
                "{\"error\":\"invalid_token\",\"error_description\":\"Token expired\"}").build()), Severity.FAIL);
        assertTrue(finding.explanation().contains("Token expired"));
        assertTrue(finding.suggestedFix().contains("fresh"));
        assertTrue(finding.evidence().contains("WWW-Authenticate: (missing)"));
    }

    @Test
    void unknownReasonAndMissingBodyHaveFallback() {
        var finding = Fixtures.assertOnly(new HookRejectedCheck().evaluate(run(401, Map.of(), null).build()), Severity.FAIL);
        assertTrue(finding.explanation().contains("no reason"));
        assertTrue(finding.suggestedFix().contains("registered client id"));
        assertTrue(new HookRejectedCheck().evaluate(Fixtures.healthy().build()).isEmpty());
    }

    @Test
    void clientJwtAudienceTakesPrecedence() {
        var run = run(401, Map.of(), "{}");
        run.hooks = List.of(Fixtures.orderSign(run.hooks.getFirst().exchange(), Fixtures.ORDER_SIGN_URL + "/"));
        assertTrue(new HookRejectedCheck().evaluate(run.build()).isEmpty());
        assertTrue(new ResponseSchemaCheck().evaluate(run.build()).isEmpty());
        Fixtures.assertOnly(new JwtAudienceCheck().evaluate(run.build()), Severity.FAIL);
    }

    @Test
    void expiredRejectionWithAgreeingClocksIsNotSkew() {
        var obs = run(401, Map.of("Date", List.of(Fixtures.httpDate(Fixtures.NOW))),
                "{\"error\":\"invalid_token\",\"error_description\":\"Token expired\"}").build();
        assertTrue(new ClockSkewCheck(Duration.ofSeconds(60)).evaluate(obs).stream()
                .noneMatch(f -> f.severity() == Severity.FAIL));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void retryAfterSecondsAndDate(boolean httpDate) {
        String retry = httpDate ? Fixtures.httpDate(Fixtures.NOW.plusSeconds(30)) : "30";
        var obs = run(429, Map.of("Retry-After", List.of(retry), "Date", List.of(Fixtures.httpDate(Fixtures.NOW))),
                "{\"error\":\"rate_limited\"}").build();
        var finding = Fixtures.assertOnly(new RateLimitCheck().evaluate(obs), Severity.FAIL);
        assertTrue(finding.evidence().contains("Retry-After: " + retry));
        assertTrue(finding.suggestedFix().contains("Wait at least 30 seconds"));
        assertTrue(new ResponseSchemaCheck().evaluate(obs).isEmpty());
        assertTrue(new HookRejectedCheck().evaluate(obs).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "nonsense", "-1", "999999999999999999999999999"})
    void unusableRetryAfterStillExplains429(String retry) {
        Fixtures.assertOnly(new RateLimitCheck().evaluate(run(429,
                Map.of("Retry-After", List.of(retry)), "{}").build()), Severity.FAIL);
        assertTrue(new RateLimitCheck().evaluate(Fixtures.healthy().build()).isEmpty());
    }

    @Test
    void dateWithoutPayerClockReportsAbsoluteDeadline() {
        var finding = Fixtures.assertOnly(new RateLimitCheck().evaluate(run(429,
                Map.of("Retry-After", List.of(Fixtures.httpDate(Fixtures.NOW))), "{}").build()), Severity.FAIL);
        assertTrue(finding.suggestedFix().contains("Wait until " + Fixtures.NOW));
    }
}
