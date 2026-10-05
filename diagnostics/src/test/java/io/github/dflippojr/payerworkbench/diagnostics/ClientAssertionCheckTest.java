package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.*;

class ClientAssertionCheckTest {
    private final ClientAssertionCheck check = new ClientAssertionCheck();
    private JwtClaims claims(String iss, String sub, String aud, long lifetime, String jti) {
        return new JwtClaims(iss, List.of(aud), NOW.plusSeconds(lifetime), NOW, jti, "kid", sub);
    }
    private RunObservations run(JwtClaims claims, String error) {
        return RunObservations.builder(connection("2.2.1", false))
                .clientAssertion(claims)
                .exchange(token(error == null ? 200 : 401, null, "{}", NOW))
                .tokenResponse(error == null ? okToken() : tokenError("invalid_client", error)).build();
    }
    private JwtClaims healthyClaims() { return claims(CLIENT_ID, CLIENT_ID, TOKEN_URL, 300, "unique"); }

    @Test void successfulAssertionPasses() {
        assertOnly(check.evaluate(run(healthyClaims(), null)), Severity.PASS);
    }
    @Test void doesNotApplyWithoutAssertion() {
        assertTrue(check.evaluate(healthy().build()).isEmpty());
    }
    @Test void audienceMismatchNamesExpectedAndSent() {
        Finding f = assertOnly(check.evaluate(run(claims(CLIENT_ID, CLIENT_ID, TOKEN_URL + "/", 300, "jti"), "aud")), Severity.FAIL);
        assertTrue(f.title().contains(TOKEN_URL));
        assertTrue(f.evidence().contains(TOKEN_URL + "/"));
    }
    @Test void payerAudienceErrorNamesDifferentExpectedHost() {
        Finding f = assertOnly(check.evaluate(run(healthyClaims(), "aud must be https://auth.tailspin-health.example/token")), Severity.FAIL);
        assertTrue(f.evidence().contains("https://auth.tailspin-health.example/token"));
        assertTrue(f.evidence().contains(TOKEN_URL));
    }
    @ParameterizedTest @ValueSource(strings = {"iss", "sub"})
    void identityMismatchFails(String changed) {
        JwtClaims c = claims(changed.equals("iss") ? "other" : CLIENT_ID,
                changed.equals("sub") ? "other" : CLIENT_ID, TOKEN_URL, 300, "jti");
        assertTrue(assertOnly(check.evaluate(run(c, null)), Severity.FAIL).title().contains("iss and sub"));
    }
    @ParameterizedTest @ValueSource(longs = {0, -1, 301})
    void invalidLifetimeFails(long seconds) {
        assertTrue(assertOnly(check.evaluate(run(claims(CLIENT_ID, CLIENT_ID, TOKEN_URL, seconds, "jti"), null)), Severity.FAIL)
                .title().contains("lifetime"));
    }
    @Test void missingExpiryFails() {
        assertOnly(check.evaluate(run(new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), null, NOW, "jti", "kid", CLIENT_ID), null)), Severity.FAIL);
    }
    @Test void recordedExpiryComparedWithPayerClockFails() {
        JwtClaims expired = new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.minusSeconds(1), NOW.minusSeconds(301), "jti", "kid", CLIENT_ID);
        assertTrue(assertOnly(check.evaluate(run(expired, null)), Severity.FAIL).title().contains("payer clock"));
        JwtClaims future = new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(301), NOW.plusSeconds(1), "jti", "kid", CLIENT_ID);
        assertOnly(check.evaluate(run(future, null)), Severity.FAIL);
    }
    @Test void payerExpiredAssertionFails() {
        assertTrue(assertOnly(check.evaluate(run(healthyClaims(), "exp expired")), Severity.FAIL).title().contains("exp expired"));
    }
    @Test void replayedJtiFailsWithPayerCause() {
        Finding f = assertOnly(check.evaluate(run(healthyClaims(), "jti was already used (replay)")), Severity.FAIL);
        assertTrue(f.title().contains("replay"));
        assertTrue(f.evidence().contains("jti=unique"));
    }
    @Test void missingJtiFails() {
        assertOnly(check.evaluate(run(claims(CLIENT_ID, CLIENT_ID, TOKEN_URL, 300, null), null)), Severity.FAIL);
    }
    @Test void rejectedWithoutDescriptionFails() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .tokenResponse(tokenError("invalid_client", null)).build();
        assertOnly(check.evaluate(obs), Severity.FAIL);
    }
    @Test void unrelatedFailureDoesNotClaimAssertionAccepted() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .tokenResponse(tokenError("invalid_scope", "unknown scope")).build();
        assertTrue(check.evaluate(obs).isEmpty());
    }
}
