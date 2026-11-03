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
        assertTrue(assertOnly(check.evaluate(run(expired, "invalid assertion")), Severity.FAIL).title().contains("payer clock"));
        JwtClaims future = new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(361), NOW.plusSeconds(61), "jti", "kid", CLIENT_ID);
        assertTrue(assertOnly(check.evaluate(run(future, "invalid assertion")), Severity.FAIL).title().contains("payer clock"));
    }
    /** RFC 7523 §3 allows clock skew: a payer that issued a token accepted the assertion, whatever its Date says. */
    @ParameterizedTest @ValueSource(longs = {1, 30, 301, -301})
    void issuedTokenWithPayerClockOffsetPasses(long payerBehindSeconds) {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .exchange(token(200, null, TOKEN_OK_BODY, NOW.minusSeconds(payerBehindSeconds)))
                .tokenResponse(okToken()).build();
        assertEquals("Client assertion accepted", assertOnly(check.evaluate(obs), Severity.PASS).title());
    }
    @Test void invalidClientWithPayerClockBeyondToleranceFails() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .exchange(token(401, null, "{\"error\":\"invalid_client\"}", NOW.minusSeconds(120)))
                .tokenResponse(tokenError("invalid_client", null)).build();
        assertTrue(assertOnly(check.evaluate(obs), Severity.FAIL).title().contains("payer clock"));
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
        assertTrue(assertOnly(check.evaluate(run(claims(CLIENT_ID, CLIENT_ID, TOKEN_URL, 300, null), null)), Severity.FAIL)
                .title().contains("jti is required"));
    }
    @Test void rejectedWithoutDescriptionFails() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .tokenResponse(tokenError("invalid_client", null)).build();
        assertOnly(check.evaluate(obs), Severity.FAIL);
    }
    @Test void tokenMetadataWithoutSuccessfulExchangeIsNotAccepted() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .exchange(token(500, null, TOKEN_OK_BODY, NOW)).tokenResponse(okToken()).build();
        assertTrue(check.evaluate(obs).isEmpty());
    }
    @Test void unrelatedFailureDoesNotClaimAssertionAccepted() {
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(healthyClaims())
                .tokenResponse(tokenError("invalid_scope", "unknown scope")).build();
        assertTrue(check.evaluate(obs).isEmpty());
    }

    // #234: the payer clock is blamed only for a rejection that points at the assertion, past tolerance.
    private static RunObservations rejected(int status, TokenResponseMetadata token, long payerBehindSeconds) {
        return RunObservations.builder(connection("2.2.1", false)).clientAssertion(
                        new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(300), NOW, "unique", "kid", CLIENT_ID))
                .exchange(token(status, null, "{}", NOW.minusSeconds(payerBehindSeconds)))
                .tokenResponse(token).build();
    }
    @Test void invalidScopeWithPayerClockOneSecondBehindHasNoFinding() {
        assertTrue(check.evaluate(rejected(400, tokenError("invalid_scope", "unknown scope"), 1)).isEmpty());
    }
    @Test void serverErrorWithPayerClockOneSecondBehindHasNoFinding() {
        assertTrue(check.evaluate(rejected(503, null, 1)).isEmpty());
        assertTrue(check.evaluate(rejected(503, tokenError("temporarily_unavailable", null), 1)).isEmpty());
    }
    @Test void invalidClientKeepsPayerDescriptionWithinTolerance() {
        Finding f = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", "unknown kid"), 1)), Severity.FAIL);
        assertTrue(f.title().contains("unknown kid"), f.title());
        assertFalse(f.title().contains("payer clock"), f.title());
    }
    @Test void invalidClientWithoutDescriptionWithinToleranceUsesGenericCause() {
        Finding f = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", null), 30)), Severity.FAIL);
        assertEquals("Client assertion rejected: The payer rejected the client assertion", f.title());
    }
    @Test void invalidClientBeyondToleranceBlamesPayerClockAndKeepsDescription() {
        Finding f = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", "assertion not accepted"), 120)), Severity.FAIL);
        assertTrue(f.title().contains("payer clock"), f.title());
        assertTrue(f.evidence().contains("payer error_description: assertion not accepted"), f.evidence());
    }
    @Test void offsetExactlyAtToleranceIsNotOverIt() {
        Finding at = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", null), 60)), Severity.FAIL);
        assertFalse(at.title().contains("payer clock"), at.title());
        Finding over = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", null), 61)), Severity.FAIL);
        assertTrue(over.title().contains("payer clock"), over.title());
    }
    @Test void payerClockAheadBeyondToleranceIsAlsoBlamed() {
        Finding f = assertOnly(check.evaluate(rejected(401, tokenError("invalid_client", null), -301)), Severity.FAIL);
        assertTrue(f.title().contains("payer clock"), f.title());
    }
    @ParameterizedTest @ValueSource(strings = {"exp is too far ahead", "IAT rejected", "nbf check failed", "assertion Expired"})
    void otherErrorNamingAssertionTimeBeyondToleranceBlamesPayerClock(String description) {
        Finding f = assertOnly(check.evaluate(rejected(400, tokenError("invalid_grant", description), 120)), Severity.FAIL);
        assertTrue(f.title().contains("payer clock"), f.title());
    }
    @Test void otherErrorCodeNamingExpBeyondToleranceBlamesPayerClock() {
        Finding f = assertOnly(check.evaluate(rejected(400, tokenError("exp", null), 120)), Severity.FAIL);
        assertTrue(f.title().contains("payer clock"), f.title());
    }
    @ParameterizedTest @ValueSource(strings = {"assertion rejected", "expiry", "token_expired", "exponent"})
    void otherErrorWithoutAssertionTimeWordHasNoFinding(String description) {
        assertTrue(check.evaluate(rejected(400, tokenError("invalid_grant", description), 120)).isEmpty());
    }
    @Test void otherErrorNamingExpWithinToleranceHasNoFinding() {
        assertTrue(check.evaluate(rejected(400, tokenError("invalid_grant", "exp is too far ahead"), 30)).isEmpty());
    }
    @Test void invalidClientBeyondToleranceWithExpWithinPayerWindowKeepsPayerCause() {
        // iat 120 s before the payer's Date, exp still inside the payer's 5-minute window: offset alone is not blame.
        var obs = RunObservations.builder(connection("2.2.1", false)).clientAssertion(
                        new JwtClaims(CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(100), NOW.minusSeconds(120), "unique", "kid", CLIENT_ID))
                .exchange(token(401, null, "{}", NOW)).tokenResponse(tokenError("invalid_client", "unknown kid")).build();
        Finding f = assertOnly(check.evaluate(obs), Severity.FAIL);
        assertEquals("Client assertion rejected: unknown kid", f.title());
    }
}
