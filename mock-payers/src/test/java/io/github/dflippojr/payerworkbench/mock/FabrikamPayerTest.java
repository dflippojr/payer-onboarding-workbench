package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FabrikamPayerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ORDER_SIGN_PATH = "/cds-services/order-sign-crd";

    @Test
    void discoveryDeclaresCrd201AndReferenceImplementationPrefetchKeys() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            JsonNode services = MAPPER.readTree(fixture.raw("GET", "/cds-services", null).body()).path("services");

            assertEquals(2, services.size());
            for (JsonNode service : services) {
                assertEquals("2.0.1", service.path("extension").path(MockPayer.IG_VERSION_EXTENSION).asText());
                assertTrue(service.path("prefetch").has("coverageBundle"));
                assertTrue(service.path("prefetch").has("deviceRequestBundle"));
                assertFalse(service.path("prefetch").has("coverage"));
                assertFalse(service.path("prefetch").has("patient"));
            }
        }
    }

    @Test
    void orderSignPutsCoverageInformationInCardSuggestions() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            CdsHookResponse response = fixture.orderSign(SyntheticData.standardOrders());

            assertTrue(response.rawJson().path("systemActions").isMissingNode());
            for (JsonNode card : response.rawJson().path("cards")) {
                JsonNode action = card.path("suggestions").path(0).path("actions").path(0);
                assertEquals("update", action.path("type").asText());
            }
            List<CoverageInformation> coverage = response.coverageInformation();
            assertEquals(List.of("conditional", "covered", "not-covered"),
                    coverage.stream().map(CoverageInformation::covered).toList());
            assertEquals(java.util.Arrays.asList("auth-needed", "no-auth", null),
                    coverage.stream().map(CoverageInformation::paNeeded).toList());
            assertEquals(List.of("clinical"), coverage.get(0).docNeeded());
            // The reference implementation's "identifier" instead of "coverage-assertion-id".
            assertEquals("FAB-DeviceRequest-synthetic-dr-1-E0250", coverage.get(0).coverageAssertionId());
            String extension = coverage.get(0).extension().toString();
            assertTrue(extension.contains("\"identifier\""), extension);
            assertFalse(extension.contains("coverage-assertion-id"), extension);
            assertEquals(FabrikamPayer.CARD_TYPE_SYSTEM, response.cards().get(0).source().topic().system());
        }
    }

    @Test
    void ecP384KeysWorkToo() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair ec = TestKeys.ecP384();
            fixture.jwks.publish("workbench-ec-key", ec);
            fixture.credentials.put("fabrikam-ec-key", TestKeys.privatePem(ec));

            ConnectionRecord record = withKey(fixture, "workbench-ec-key", "fabrikam-ec-key");
            assertEquals(3, fixture.client.callHook(record, "order-sign-crd", signRequest()).cards().size());
        }
    }

    @Test
    void refetchesTheJwksWhenTheClientRotatesKeys() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            fixture.orderSign(SyntheticData.standardOrders());
            int fetchesBefore = fixture.jwks.fetchCount();

            KeyPair rotated = TestKeys.rsa();
            fixture.jwks.publish("workbench-test-key-2", rotated);
            fixture.credentials.put("fabrikam-rotated-key", TestKeys.privatePem(rotated));
            ConnectionRecord record = withKey(fixture, "workbench-test-key-2", "fabrikam-rotated-key");

            assertEquals(3, fixture.client.callHook(record, "order-sign-crd", signRequest()).cards().size());
            assertEquals(fetchesBefore + 1, fixture.jwks.fetchCount());
        }
    }

    @Test
    void missingBearerGets401() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            HttpResponse<String> response = post(fixture, null);
            assertEquals(401, response.statusCode());
        }
    }

    @Test
    void replayedJtiIsRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            String token = jwt(key, JWSAlgorithm.RS384, PayerFixture.CLIENT_ID, audience(fixture), Instant.now().plusSeconds(120), "jti-1");

            assertEquals(200, post(fixture, token).statusCode());
            HttpResponse<String> replay = post(fixture, token);
            assertEquals(401, replay.statusCode());
            assertTrue(replay.body().contains("replay"), replay.body());
        }
    }

    @Test
    void audienceMustBeTheExactServiceUrl() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            String loopbackIp = "http://127.0.0.1:" + fixture.payer.port() + ORDER_SIGN_PATH;
            String discoveryUrl = fixture.payer.baseUrl() + "/cds-services";

            for (String aud : List.of(loopbackIp, discoveryUrl, fixture.payer.baseUrl())) {
                HttpResponse<String> response = post(fixture, jwt(key, JWSAlgorithm.RS384, PayerFixture.CLIENT_ID, aud,
                        Instant.now().plusSeconds(120), UUID.randomUUID().toString()));
                assertEquals(401, response.statusCode(), aud);
                assertTrue(response.body().contains("aud must be exactly"), response.body());
            }
        }
    }

    @Test
    void expiredJwtIsRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            HttpResponse<String> response = post(fixture, jwt(key, JWSAlgorithm.RS384, PayerFixture.CLIENT_ID,
                    audience(fixture), Instant.now().minus(Duration.ofMinutes(1)), UUID.randomUUID().toString()));

            assertEquals(401, response.statusCode());
            assertTrue(response.body().contains("expired"), response.body());
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {301, 3600, 31_536_000}) // just over five minutes, an hour, a year
    void assertionLifetimeLongerThanFiveMinutesIsRejectedAndNotCached(long lifetimeSeconds) throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            Instant now = Instant.now();
            HttpResponse<String> response = post(fixture, signed(key, assertionClaims(audience(fixture), now,
                    now.plusSeconds(lifetimeSeconds), UUID.randomUUID().toString())));

            assertEquals(401, response.statusCode(), response.body());
            assertTrue(response.body().contains("at most 5 minutes"), response.body());
            assertEquals(0, ((FabrikamPayer) fixture.payer).replayCacheSize());
        }
    }

    @Test
    void assertionWithFiveMinuteLifetimeIsAccepted() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            Instant now = Instant.now();
            HttpResponse<String> response = post(fixture, signed(key, assertionClaims(audience(fixture), now,
                    now.plusSeconds(300), UUID.randomUUID().toString())));

            assertEquals(200, response.statusCode(), response.body());
        }
    }

    @Test
    void assertionWithoutIatIsRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(PayerFixture.CLIENT_ID)
                    .audience(audience(fixture)).expirationTime(Date.from(Instant.now().plusSeconds(120)))
                    .jwtID(UUID.randomUUID().toString()).build();
            HttpResponse<String> response = post(fixture, signed(key, claims));

            assertEquals(401, response.statusCode(), response.body());
            assertTrue(response.body().contains("no iat"), response.body());
            assertEquals(0, ((FabrikamPayer) fixture.payer).replayCacheSize());
        }
    }

    /**
     * A future iat keeps exp - iat at five minutes while pushing the whole window far ahead of the payer's
     * clock, so the entry would outlive any bound on retention. The payer must refuse it and cache nothing.
     */
    @ParameterizedTest
    @ValueSource(longs = {3601, 86_400, 31_536_000}) // just over an hour, a day and a year ahead of the payer
    void assertionIssuedFarAheadOfThePayerClockIsRejectedAndNotCached(long aheadSeconds) throws Exception {
        Instant start = Instant.parse("2026-11-03T12:00:00Z");
        ManualClock clock = new ManualClock(start);
        try (PayerFixture fixture = PayerFixture.fabrikam(FabrikamPayer.builder().clock(clock))) {
            KeyPair key = publishKey(fixture);
            Instant issuedAt = start.plusSeconds(aheadSeconds);
            HttpResponse<String> response = post(fixture, signed(key, assertionClaims(audience(fixture), issuedAt,
                    issuedAt.plusSeconds(300), UUID.randomUUID().toString())));

            assertEquals(401, response.statusCode(), response.body());
            assertTrue(response.body().contains("ahead of the payer's clock"), response.body());
            assertEquals(0, ((FabrikamPayer) fixture.payer).replayCacheSize());
        }
    }

    /**
     * The matrix's clock/cds-hooks-jwt-payer-behind-1h row: the payer's clock is an hour behind the client's,
     * so an assertion issued now is an hour ahead of the payer. It is accepted, and its jti is kept until exp.
     */
    @Test
    void assertionIssuedAnHourAheadOfThePayerClockIsKeptUntilItsExp() throws Exception {
        Instant start = Instant.parse("2026-11-03T12:00:00Z");
        ManualClock clock = new ManualClock(start);
        try (PayerFixture fixture = PayerFixture.fabrikam(FabrikamPayer.builder().clock(clock))) {
            KeyPair key = publishKey(fixture);
            FabrikamPayer payer = (FabrikamPayer) fixture.payer;
            Instant issuedAt = start.plusSeconds(3600);
            String ahead = signed(key, assertionClaims(audience(fixture), issuedAt, issuedAt.plusSeconds(300), "ahead-1"));

            assertEquals(200, post(fixture, ahead).statusCode());
            assertEquals(1, payer.replayCacheSize());

            clock.set(start.plusSeconds(3899));
            HttpResponse<String> reused = post(fixture, ahead);
            assertEquals(401, reused.statusCode());
            assertTrue(reused.body().contains("replay"), reused.body());
            assertEquals(1, payer.replayCacheSize(), "ahead-1 has not reached its exp yet and must stay cached");

            clock.set(start.plusSeconds(3900));
            assertEquals(200, post(fixture, signed(key, assertionClaims(audience(fixture), clock.instant(),
                    clock.instant().plusSeconds(300), "ahead-2"))).statusCode());
            assertEquals(1, payer.replayCacheSize(), "ahead-1 reached its exp at +3900s and must be gone");
        }
    }

    @Test
    void expiredJtisAreEvictedFromTheReplayCache() throws Exception {
        Instant start = Instant.parse("2026-11-03T12:00:00Z");
        ManualClock clock = new ManualClock(start);
        try (PayerFixture fixture = PayerFixture.fabrikam(FabrikamPayer.builder().clock(clock))) {
            KeyPair key = publishKey(fixture);
            FabrikamPayer payer = (FabrikamPayer) fixture.payer;
            String first = signed(key, assertionClaims(audience(fixture), start, start.plusSeconds(300), "evict-1"));

            assertEquals(200, post(fixture, first).statusCode());
            assertEquals(1, payer.replayCacheSize());

            clock.set(start.plusSeconds(299));
            assertEquals(200, post(fixture, signed(key, assertionClaims(audience(fixture), clock.instant(),
                    start.plusSeconds(599), "evict-2"))).statusCode());
            assertEquals(2, payer.replayCacheSize());
            HttpResponse<String> reused = post(fixture, first);
            assertEquals(401, reused.statusCode());
            assertTrue(reused.body().contains("replay"), reused.body());

            clock.set(start.plusSeconds(301));
            assertEquals(200, post(fixture, signed(key, assertionClaims(audience(fixture), clock.instant(),
                    start.plusSeconds(601), "evict-3"))).statusCode());
            assertEquals(2, payer.replayCacheSize(), "evict-1 passed its exp at +300s and must be gone");
        }
    }

    @Test
    void unknownIssuerIsRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair key = publishKey(fixture);
            HttpResponse<String> response = post(fixture, jwt(key, JWSAlgorithm.RS384, "someone-else",
                    audience(fixture), Instant.now().plusSeconds(120), UUID.randomUUID().toString()));

            assertEquals(401, response.statusCode());
            assertTrue(response.body().contains("Unknown iss"), response.body());
        }
    }

    @Test
    void signatureFromAnotherKeyIsRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            KeyPair impostor = TestKeys.rsa(); // signs with the published kid but is not the published key
            HttpResponse<String> response = post(fixture, jwt(impostor, JWSAlgorithm.RS384, PayerFixture.CLIENT_ID,
                    audience(fixture), Instant.now().plusSeconds(120), UUID.randomUUID().toString()));

            assertEquals(401, response.statusCode());
            assertTrue(response.body().contains("signature"), response.body());
        }
    }

    @Test
    void symmetricAlgorithmsAreRejected() throws Exception {
        try (PayerFixture fixture = PayerFixture.fabrikam()) {
            byte[] secret = new byte[32];
            new SecureRandom().nextBytes(secret);
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(PayerFixture.KEY_ID).build(),
                    claims(PayerFixture.CLIENT_ID, audience(fixture), Instant.now().plusSeconds(120), "hs-jti"));
            jwt.sign(new MACSigner(secret));

            HttpResponse<String> response = post(fixture, jwt.serialize());
            assertEquals(401, response.statusCode());
            assertTrue(response.body().contains("HS256"), response.body());
        }
    }

    @Test
    void unreachableJwksIsReportedAsAnAuthFailure() throws Exception {
        TestKeys.JwksServer gone = new TestKeys.JwksServer();
        URI goneUrl = gone.url();
        gone.close();
        try (PayerFixture fixture = PayerFixture.fabrikam(FabrikamPayer.builder().client("orphan-client", goneUrl))) {
            ConnectionRecord record = ConnectionRecord.builder()
                    .payerId("fabrikam-synthetic").environment(Environment.SANDBOX).baseUrl(fixture.payer.baseUrl())
                    .authType(AuthType.CDS_HOOKS_JWT).clientId("orphan-client").keyId(PayerFixture.KEY_ID)
                    .credentialRef("fabrikam-signing-key").build();

            RouterException e = assertThrows(RouterException.class,
                    () -> fixture.client.callHook(record, "order-sign-crd", signRequest()));
            assertTrue(e.getMessage().contains("HTTP 401"), e.getMessage());
            assertTrue(e.getMessage().contains("Could not fetch JWKS"), e.getMessage());
        }
    }

    // ---- helpers ----

    /** Publishes a fresh key under the fixture's kid, replacing the one the SDK uses, and returns it. */
    private static KeyPair publishKey(PayerFixture fixture) {
        KeyPair key = TestKeys.rsa();
        fixture.jwks.publish(PayerFixture.KEY_ID, key);
        return key;
    }

    private static String audience(PayerFixture fixture) {
        return fixture.payer.baseUrl() + ORDER_SIGN_PATH;
    }

    private static String jwt(KeyPair key, JWSAlgorithm algorithm, String issuer, String audience, Instant expiry,
                              String jti) throws Exception {
        JWSSigner signer = new RSASSASigner(key.getPrivate());
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT)
                .keyID(PayerFixture.KEY_ID).build(), claims(issuer, audience, expiry, jti));
        jwt.sign(signer);
        return jwt.serialize();
    }

    /** The claims of a client assertion with an explicit iat and exp, as a client signs them. */
    private static JWTClaimsSet assertionClaims(String audience, Instant issuedAt, Instant expiry, String jti) {
        return new JWTClaimsSet.Builder()
                .issuer(PayerFixture.CLIENT_ID)
                .audience(audience)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiry))
                .jwtID(jti)
                .build();
    }

    /** Signs the claims with the key published under the fixture's kid, as {@link #jwt} does. */
    private static String signed(KeyPair key, JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS384).type(JOSEObjectType.JWT)
                .keyID(PayerFixture.KEY_ID).build(), claims);
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }

    /** A payer clock the test moves by hand. */
    private static final class ManualClock extends Clock {
        private Instant now;

        ManualClock(Instant now) {
            this.now = now;
        }

        void set(Instant to) {
            now = to;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static JWTClaimsSet claims(String issuer, String audience, Instant expiry, String jti) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .issueTime(new Date())
                .expirationTime(Date.from(expiry))
                .jwtID(jti)
                .build();
    }

    private static HttpResponse<String> post(PayerFixture fixture, String bearer) throws Exception {
        String body = MAPPER.writeValueAsString(signRequest(fixture));
        return bearer == null
                ? fixture.raw("POST", ORDER_SIGN_PATH, body, "Content-Type", "application/json")
                : fixture.raw("POST", ORDER_SIGN_PATH, body, "Content-Type", "application/json",
                        "Authorization", "Bearer " + bearer);
    }

    private static CdsHookRequest signRequest(PayerFixture fixture) {
        return CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()),
                fixture.fullPrefetch(SyntheticData.standardOrders()));
    }

    private static CdsHookRequest signRequest() {
        return CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()), null);
    }

    private static ConnectionRecord withKey(PayerFixture fixture, String keyId, String credentialRef) {
        return ConnectionRecord.builder()
                .payerId(fixture.record.payerId())
                .environment(fixture.record.environment())
                .baseUrl(fixture.record.baseUrl())
                .authType(AuthType.CDS_HOOKS_JWT)
                .clientId(PayerFixture.CLIENT_ID)
                .keyId(keyId)
                .credentialRef(credentialRef)
                .build();
    }
}
