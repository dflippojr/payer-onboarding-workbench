package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.core.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class TailspinPayerTest {
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private ConnectionRecord record(TailspinPayer payer) {
        return ConnectionRecord.builder().payerId("tailspin-synthetic").environment(Environment.SANDBOX)
                .baseUrl(payer.baseUrl()).authType(AuthType.OAUTH2_PRIVATE_KEY_JWT).tokenEndpoint(payer.tokenEndpoint())
                .clientId("client").keyId("kid").credentialRef("key").build();
    }
    private JWTClaimsSet.Builder claims(String audience) {
        return new JWTClaimsSet.Builder().issuer("client").subject("client").audience(audience)
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300))).jwtID(UUID.randomUUID().toString());
    }
    private String signed(KeyPair key, JWTClaimsSet claims, String kid, JWSAlgorithm alg) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(kid).build(), claims);
        jwt.sign(key.getPrivate() instanceof ECPrivateKey ec ? new ECDSASigner(ec) : new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }
    private HttpResponse<String> request(TailspinPayer payer, String method, String path, String form) throws Exception {
        try (HttpClient http = HttpClient.newHttpClient()) {
            return http.send(HttpRequest.newBuilder(URI.create(payer.baseUrl() + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .method(method, form == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(form))
                    .build(), HttpResponse.BodyHandlers.ofString());
        }
    }
    private HttpResponse<String> token(TailspinPayer payer, String assertion) throws Exception {
        return request(payer, "POST", TailspinPayer.TOKEN_PATH, "grant_type=client_credentials&client_id=client"
                + "&scope=system%2F*.read&client_assertion_type=" + URLEncoder.encode(TailspinPayer.ASSERTION_TYPE, StandardCharsets.UTF_8)
                + "&client_assertion=" + URLEncoder.encode(assertion, StandardCharsets.UTF_8));
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void acceptsRsaAndEcAndRejectsReplay(boolean ec) throws Exception {
        KeyPair key = ec ? TestKeys.ecP384() : TestKeys.rsa();
        try (TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish("kid", key);
             TailspinPayer payer = TailspinPayer.builder().client("client", jwks.url()).build().start(0)) {
            String jwt = new JwtSigner().clientAssertion(record(payer), key.getPrivate());
            HttpResponse<String> response = token(payer, jwt);
            assertEquals(200, response.statusCode(), response::body);
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("system/*.read", MAPPER.readTree(response.body()).path("scope").asText());
            assertEquals(401, token(payer, jwt).statusCode());
            assertTrue(token(payer, jwt).body().contains("replay"));
            var discovery = MAPPER.readTree(request(payer, "GET", "/cds-services", null).body());
            assertEquals("2.2.1", discovery.path("services").get(0).path("extension").path(MockPayer.IG_VERSION_EXTENSION).asText());
            assertTrue(discovery.path("services").get(0).path("prefetch").has("patient"));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"aud", "iss", "sub", "exp-missing", "exp-expired", "exp-long", "jti-missing", "kid-missing", "kid-unknown", "signature", "alg"})
    void rejectsEachInvalidAssertion(String cause) throws Exception {
        KeyPair key = TestKeys.rsa();
        try (TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish("kid", key);
             TailspinPayer payer = TailspinPayer.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC)).client("client", jwks.url()).build().start(0)) {
            JWTClaimsSet.Builder claims = claims(payer.tokenEndpoint());
            switch (cause) {
                case "aud" -> claims.audience(payer.tokenEndpoint() + "/");
                case "iss" -> claims.issuer("other");
                case "sub" -> claims.subject("other");
                case "exp-missing" -> claims.expirationTime(null);
                case "exp-expired" -> claims.expirationTime(Date.from(NOW));
                case "exp-long" -> claims.expirationTime(Date.from(NOW.plusSeconds(301)));
                case "jti-missing" -> claims.jwtID(null);
                default -> { }
            }
            String kid = cause.equals("kid-missing") ? null : cause.equals("kid-unknown") ? "unknown" : "kid";
            String jwt = signed(cause.equals("signature") ? TestKeys.rsa() : key, claims.build(), kid,
                    cause.equals("alg") ? JWSAlgorithm.RS256 : JWSAlgorithm.RS384);
            HttpResponse<String> response = token(payer, jwt);
            assertEquals(401, response.statusCode());
            assertEquals("invalid_client", MAPPER.readTree(response.body()).path("error").asText());
            assertTrue(response.body().contains(cause.split("-")[0]), response::body);
        }
    }
    @Test void wrongAudienceFaultRejectsAtTokenAndClears() throws Exception {
        KeyPair key = TestKeys.rsa();
        try (TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish("kid", key);
             TailspinPayer payer = TailspinPayer.builder().client("client", jwks.url()).build().start(0)) {
            String jwt = new JwtSigner().clientAssertion(record(payer), key.getPrivate());
            payer.faults().enable(Fault.WRONG_AUDIENCE_REJECT);
            var rejected = token(payer, jwt);
            assertTrue(rejected.body().contains(TailspinPayer.WRONG_AUDIENCE));
            assertTrue(rejected.body().contains(payer.tokenEndpoint()));
            assertEquals("wrong-audience-reject", rejected.headers().firstValue(MockPayer.FAULT_HEADER).orElseThrow());
            payer.faults().clear();
            assertEquals(200, token(payer, jwt).statusCode());
        }
    }
    @Test void rejectsMalformedTokenRequestsAndUnauthorizedHooks() throws Exception {
        try (TailspinPayer payer = TailspinPayer.builder().build().start(0)) {
            assertEquals(405, request(payer, "GET", TailspinPayer.TOKEN_PATH, null).statusCode());
            assertEquals(400, request(payer, "POST", TailspinPayer.TOKEN_PATH, "grant_type=password").statusCode());
            assertTrue(request(payer, "POST", TailspinPayer.TOKEN_PATH, "grant_type=client_credentials").body().contains("client_assertion_type"));
            assertTrue(request(payer, "POST", TailspinPayer.TOKEN_PATH, "grant_type=client_credentials&client_assertion_type=" + TailspinPayer.ASSERTION_TYPE).body().contains("client_assertion is required"));
            assertTrue(token(payer, "bad.jwt").body().contains("signed JWT"));
            assertEquals(401, request(payer, "POST", "/cds-services/order-sign", "{}").statusCode());
            assertEquals(404, request(payer, "GET", "/missing", null).statusCode());
        }
    }
    @Test void launcherRegistersClientAndSupportsTlsAndPublicUrl() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);
        try (TailspinPayer payer = TailspinPayer.launch(new String[]{"--tls", "--port", "0", "--client", "client=http://localhost:1/jwks", "--public-base-url", "https://crd.tailspin-health.example"}, out)) {
            assertTrue(payer.baseUrl().startsWith("https://"));
            assertEquals("https://crd.tailspin-health.example", payer.publicBaseUrl());
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("private_key_jwt"));
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("client id=client"));
        }
        assertThrows(IllegalArgumentException.class, () -> TailspinPayer.launch(new String[]{"--client", "bad"}, out));
    }
}
