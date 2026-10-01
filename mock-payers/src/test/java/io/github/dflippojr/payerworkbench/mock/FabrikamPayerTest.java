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

import java.net.URI;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
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
            assertEquals(List.of("auth-needed", "no-auth", "no-auth"),
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
