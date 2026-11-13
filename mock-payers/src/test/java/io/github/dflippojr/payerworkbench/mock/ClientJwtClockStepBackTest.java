package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Each payer's limits on how far ahead of its clock an assertion may reach (Tailspin's exp cap, Fabrikam's iat bound)
 * are judged by the payer's clock as it reads now. The replay cache never judges a jti by an instant earlier than one
 * it already used, but after the clock steps back that later instant must not widen these limits.
 */
class ClientJwtClockStepBackTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CLIENT = "client";
    private static final String KID = "kid";
    private static final String HOOK_PATH = "/cds-services/order-sign-crd";

    private static KeyPair key;
    private static TestKeys.JwksServer jwks;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        key = TestKeys.rsa();
        jwks = new TestKeys.JwksServer().publish(KID, key);
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stop() {
        jwks.close();
        http.close();
    }

    @Test
    void tailspinCapsExpAgainstItsClockAfterTheClockStepsBack() throws Exception {
        TestKeys.MutableClock clock = wholeSecondClock();
        try (TailspinPayer payer = TailspinPayer.builder().clock(clock).client(CLIENT, jwks.url()).build().start(0)) {
            String audience = payer.publicBaseUrl() + TailspinPayer.TOKEN_PATH;
            Instant before = clock.instant();
            HttpResponse<String> first = tailspinCall(payer, sign(audience, before, before.plusSeconds(300)));
            assertEquals(200, first.statusCode(), first::body);

            clock.advance(Duration.ofHours(-1));
            // 61 minutes ahead of the clock as it reads now, though still within 5 minutes of the earlier reading.
            HttpResponse<String> ahead = tailspinCall(payer,
                    sign(audience, clock.instant(), before.plusSeconds(60)));
            assertRejected(ahead, "invalid_client",
                    "exp must be in the future and no more than 5 minutes ahead");
        }
    }

    @Test
    void fabrikamBoundsIatAgainstItsClockAfterTheClockStepsBack() throws Exception {
        TestKeys.MutableClock clock = wholeSecondClock();
        try (FabrikamPayer payer = FabrikamPayer.builder().clock(clock).client(CLIENT, jwks.url()).build().start(0)) {
            String audience = payer.publicBaseUrl() + HOOK_PATH;
            Instant before = clock.instant();
            HttpResponse<String> first = fabrikamCall(payer, sign(audience, before, before.plusSeconds(300)));
            assertEquals(200, first.statusCode(), first::body);

            clock.advance(Duration.ofHours(-2));
            // iat is 2 hours 30 seconds ahead of the clock as it reads now, though 30 seconds past the earlier reading.
            HttpResponse<String> ahead = fabrikamCall(payer,
                    sign(audience, before.plusSeconds(30), before.plusSeconds(90)));
            assertRejected(ahead, "unauthorized",
                    "JWT iat is ahead of the payer's clock by more than 1 hour, got 7230 seconds");
        }
    }

    /** A JWT carries whole seconds; starting on one keeps the expected offsets exact. */
    private static TestKeys.MutableClock wholeSecondClock() {
        TestKeys.MutableClock clock = new TestKeys.MutableClock();
        clock.advance(Duration.ofNanos(-clock.instant().getNano()));
        return clock;
    }

    private static void assertRejected(HttpResponse<String> response, String error, String description)
            throws Exception {
        assertEquals(401, response.statusCode(), response::body);
        JsonNode body = MAPPER.readTree(response.body());
        assertEquals(error, body.path("error").asText(), response::body);
        assertEquals(description, body.path("error_description").asText(), response::body);
    }

    private static String sign(String audience, Instant issued, Instant expires) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(CLIENT).subject(CLIENT).audience(audience)
                .issueTime(Date.from(issued)).expirationTime(Date.from(expires))
                .jwtID(UUID.randomUUID().toString()).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID(KID).build(), claims);
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }

    private static HttpResponse<String> fabrikamCall(FabrikamPayer payer, String token) throws Exception {
        String body = MAPPER.writeValueAsString(
                CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()), null));
        return http.send(HttpRequest.newBuilder(URI.create(payer.baseUrl() + HOOK_PATH))
                .header("Content-Type", "application/json").header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> tailspinCall(TailspinPayer payer, String assertion) throws Exception {
        String form = "grant_type=client_credentials&client_id=" + CLIENT + "&client_assertion_type="
                + URLEncoder.encode(TailspinPayer.ASSERTION_TYPE, StandardCharsets.UTF_8)
                + "&client_assertion=" + URLEncoder.encode(assertion, StandardCharsets.UTF_8);
        return http.send(HttpRequest.newBuilder(URI.create(payer.tokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
