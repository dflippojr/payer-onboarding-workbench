package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * One row per client-JWT rejection reason, for Fabrikam (CDS Hooks client JWT on each hook call) and Tailspin
 * (SMART private_key_jwt at the token endpoint). Each row pins the status, the error code, the exact
 * error_description, the WWW-Authenticate header and the fault tag a payer answers with today, so moving the checks
 * into one shared validator cannot change a single byte a client sees.
 */
class ClientJwtRejectionTableTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");
    private static final String CLIENT = "client";
    private static final String KID = "kid";
    private static final String HOOK_PATH = "/cds-services/order-sign-crd";
    private static final String TAILSPIN_EXP = "exp must be in the future and no more than 5 minutes ahead";

    /** A P-384 key published under this kid, so an RS384 JWT naming it cannot be checked. */
    private static final String EC_KID = "ec-kid";

    private static KeyPair key;
    private static TestKeys.JwksServer jwks;
    /** Serves a broken JWK Set: {@code /unavailable} answers 503, {@code /garbage} answers 200 with a non-JWKS body. */
    private static HttpServer brokenJwks;
    private static HttpClient http;

    @BeforeAll
    static void startJwks() throws Exception {
        key = TestKeys.rsa();
        jwks = new TestKeys.JwksServer().publish(KID, key).publish(EC_KID, TestKeys.ecP384());
        brokenJwks = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        brokenJwks.createContext("/unavailable", exchange -> {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        brokenJwks.createContext("/garbage", exchange -> {
            byte[] body = "not a jwks".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        brokenJwks.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stopJwks() {
        jwks.close();
        brokenJwks.stop(0);
        http.close();
    }

    /** What one row sends; every field defaults to a valid assertion for the payer. */
    static final class Spec {
        Consumer<JWTClaimsSet.Builder> claims = c -> { };
        String kid = KID;
        JWSAlgorithm alg = JWSAlgorithm.RS384;
        boolean foreignKey;
        /** Sent in place of a signed JWT; {@link #ABSENT} sends no token at all. */
        String raw;
        String clientId = CLIENT;
        Fault[] faults = {};
        /** Sends the same assertion twice and checks the second answer. */
        boolean replay;
        /** Registers the client with this path on the broken JWKS server instead of the healthy one. */
        String brokenJwksPath;

        static final String ABSENT = "\u0000absent";

        Spec claims(Consumer<JWTClaimsSet.Builder> mutation) { claims = mutation; return this; }
        Spec kid(String value) { kid = value; return this; }
        Spec alg(JWSAlgorithm value) { alg = value; return this; }
        Spec foreignKey() { foreignKey = true; return this; }
        Spec raw(String value) { raw = value; return this; }
        Spec clientId(String value) { clientId = value; return this; }
        Spec faults(Fault... value) { faults = value; return this; }
        Spec replay() { replay = true; return this; }
        Spec brokenJwks(String path) { brokenJwksPath = path; return this; }
    }

    /**
     * One rejection. {@code message} maps the payer's public base URL to the expected error_description; a null
     * {@code fault} means the response carries no fault tag.
     */
    record Row(String reason, Spec spec, Function<String, String> message, Fault fault) {
        @Override
        public String toString() {
            return reason;
        }
    }

    private static URI jwksUrl(Spec spec) {
        return spec.brokenJwksPath == null ? jwks.url()
                : URI.create("http://localhost:" + brokenJwks.getAddress().getPort() + spec.brokenJwksPath);
    }

    /** The RegisteredJwks rejections; each payer reports them through its own error factory. */
    private static List<Row> jwksRows() {
        return List.of(
                new Row("JWKS answers 503", send().brokenJwks("/unavailable"),
                        base -> "Could not fetch JWKS for iss 'client' from " + jwksUrl(send().brokenJwks("/unavailable"))
                                + ": HTTP 503", null),
                new Row("JWKS body is not a JWK Set", send().brokenJwks("/garbage"),
                        base -> "Could not fetch JWKS for iss 'client' from " + jwksUrl(send().brokenJwks("/garbage"))
                                + ": Invalid JSON object", null),
                row("signature cannot be checked with the kid's key", send().kid(EC_KID),
                        "JWT signature could not be checked with kid 'ec-kid': "
                                + "Invalid key: Must be an instance of interface java.security.interfaces.RSAPublicKey"));
    }

    private static Spec send() {
        return new Spec();
    }

    private static Row row(String reason, Spec spec, String message) {
        return new Row(reason, spec, base -> message, null);
    }

    static Stream<Row> fabrikamRows() {
        List<Row> rows = new ArrayList<>();
        rows.add(row("no bearer token", send().raw(Spec.ABSENT),
                "CDS Hooks client JWT required in Authorization: Bearer"));
        rows.add(row("not a JWT", send().raw("bad.jwt"), "Bearer token is not a signed JWT"));
        rows.add(row("alg RS256", send().alg(JWSAlgorithm.RS256), "JWT alg RS256 is not accepted; use RS384 or ES384"));
        rows.add(row("unregistered iss", send().claims(c -> c.issuer("other")),
                "Unknown iss 'other'; register the client with Fabrikam first"));
        rows.add(row("missing iss", send().claims(c -> c.issuer(null)),
                "Unknown iss 'null'; register the client with Fabrikam first"));
        rows.add(row("missing kid", send().kid(null), "JWT header has no kid"));
        rows.add(row("blank kid", send().kid(""), "No public key with kid '' in the JWKS for iss 'client'"));
        rows.add(row("unknown kid", send().kid("unknown"), "No public key with kid 'unknown' in the JWKS for iss 'client'"));
        rows.add(row("bad signature", send().foreignKey(), "JWT signature does not verify against kid 'kid'"));
        rows.add(new Row("wrong aud", send().claims(c -> c.audience("https://elsewhere.example")),
                base -> "aud must be exactly '" + base + HOOK_PATH + "', got [https://elsewhere.example]", null));
        rows.add(new Row("wrong aud before missing exp",
                send().claims(c -> c.audience("https://elsewhere.example").expirationTime(null)),
                base -> "aud must be exactly '" + base + HOOK_PATH + "', got [https://elsewhere.example]", null));
        rows.add(row("missing exp", send().claims(c -> c.expirationTime(null)), "JWT has no exp"));
        rows.add(row("missing iat", send().claims(c -> c.issueTime(null)), "JWT has no iat"));
        rows.add(row("expired", send().claims(c -> c.issueTime(Date.from(NOW.minusSeconds(60))).expirationTime(Date.from(NOW))),
                "JWT expired at 2026-10-01T12:00:00Z"));
        rows.add(row("lifetime over 5 minutes", send().claims(c -> c.expirationTime(Date.from(NOW.plusSeconds(301)))),
                "JWT lifetime (exp minus iat) must be positive and at most 5 minutes, got 301 seconds"));
        rows.add(row("negative lifetime",
                send().claims(c -> c.issueTime(Date.from(NOW.plusSeconds(10))).expirationTime(Date.from(NOW.plusSeconds(5)))),
                "JWT lifetime (exp minus iat) must be positive and at most 5 minutes, got -5 seconds"));
        rows.add(row("zero lifetime",
                send().claims(c -> c.issueTime(Date.from(NOW.plusSeconds(10))).expirationTime(Date.from(NOW.plusSeconds(10)))),
                "JWT lifetime (exp minus iat) must be positive and at most 5 minutes, got 0 seconds"));
        rows.add(row("iat over an hour ahead",
                send().claims(c -> c.issueTime(Date.from(NOW.plusSeconds(3601))).expirationTime(Date.from(NOW.plusSeconds(3700)))),
                "JWT iat is ahead of the payer's clock by more than 1 hour, got 3601 seconds"));
        rows.add(row("missing jti", send().claims(c -> c.jwtID(null)), "JWT has no jti"));
        rows.add(row("blank jti", send().claims(c -> c.jwtID("  ")), "JWT has no jti"));
        rows.add(row("replayed jti", send().claims(c -> c.jwtID("jti-1")).replay(),
                "jti 'jti-1' was already used (replay)"));
        rows.add(new Row("fault wrong-audience-reject", send().faults(Fault.WRONG_AUDIENCE_REJECT),
                base -> "aud must be exactly '" + FabrikamPayer.WRONG_AUDIENCE_BASE + HOOK_PATH + "', got ["
                        + base + HOOK_PATH + "]", Fault.WRONG_AUDIENCE_REJECT));
        rows.add(new Row("fault expired-token-401", send().faults(Fault.EXPIRED_TOKEN_401),
                base -> "JWT expired", Fault.EXPIRED_TOKEN_401));
        rows.add(row("fault expired-token-401 after missing iat",
                send().faults(Fault.EXPIRED_TOKEN_401).claims(c -> c.issueTime(null)), "JWT has no iat"));
        rows.addAll(jwksRows());
        return rows.stream();
    }

    static Stream<Row> tailspinRows() {
        List<Row> rows = new ArrayList<>();
        rows.add(row("no client_assertion", send().raw(Spec.ABSENT), "client_assertion is required"));
        rows.add(row("not a JWT", send().raw("bad.jwt"), "client_assertion must be a signed JWT"));
        rows.add(row("alg RS256", send().alg(JWSAlgorithm.RS256), "alg must be RS384 or ES384"));
        rows.add(row("unregistered iss", send().claims(c -> c.issuer("other")), "iss is not a registered client id"));
        rows.add(row("missing iss", send().claims(c -> c.issuer(null)), "iss is not a registered client id"));
        rows.add(row("sub differs", send().claims(c -> c.subject("other")), "iss and sub must equal the registered client id"));
        rows.add(row("client_id differs", send().clientId("other"), "iss and sub must equal the registered client id"));
        rows.add(row("sub differs before unknown kid", send().claims(c -> c.subject("other")).kid("unknown"),
                "iss and sub must equal the registered client id"));
        rows.add(row("missing kid", send().kid(null), "kid is required"));
        rows.add(row("blank kid", send().kid(" "), "kid is required"));
        rows.add(row("unknown kid", send().kid("unknown"), "No public key with kid 'unknown' in the JWKS for iss 'client'"));
        rows.add(row("bad signature", send().foreignKey(), "JWT signature does not verify against kid 'kid'"));
        rows.add(new Row("wrong aud", send().claims(c -> c.audience("https://elsewhere.example")),
                base -> "aud must be exactly '" + base + TailspinPayer.TOKEN_PATH + "', got [https://elsewhere.example]", null));
        rows.add(row("missing exp", send().claims(c -> c.expirationTime(null)), "exp is required"));
        rows.add(row("expired", send().claims(c -> c.expirationTime(Date.from(NOW))), TAILSPIN_EXP));
        rows.add(row("exp over 5 minutes ahead", send().claims(c -> c.expirationTime(Date.from(NOW.plusSeconds(301)))),
                TAILSPIN_EXP));
        rows.add(row("missing jti", send().claims(c -> c.jwtID(null)), "jti is required"));
        rows.add(row("blank jti", send().claims(c -> c.jwtID("  ")), "jti is required"));
        rows.add(row("replayed jti", send().claims(c -> c.jwtID("jti-1")).replay(), "jti was already used (replay)"));
        rows.add(new Row("fault wrong-audience-reject", send().faults(Fault.WRONG_AUDIENCE_REJECT),
                base -> "aud must be exactly '" + TailspinPayer.WRONG_AUDIENCE + "', got ["
                        + base + TailspinPayer.TOKEN_PATH + "]", Fault.WRONG_AUDIENCE_REJECT));
        rows.addAll(jwksRows());
        return rows.stream();
    }

    @ParameterizedTest(name = "fabrikam: {0}")
    @MethodSource("fabrikamRows")
    void fabrikamRejection(Row row) throws Exception {
        try (FabrikamPayer payer = FabrikamPayer.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .client(CLIENT, jwksUrl(row.spec)).build().start(0)) {
            for (Fault fault : row.spec.faults) {
                payer.faults().enable(fault);
            }
            String token = token(row.spec, payer.publicBaseUrl() + HOOK_PATH);
            HttpResponse<String> response = fabrikamCall(payer, token);
            if (row.spec.replay) {
                assertEquals(200, response.statusCode(), response::body);
                response = fabrikamCall(payer, token);
            }
            String description = row.message.apply(payer.publicBaseUrl());
            assertRejected(response, "unauthorized", description, row.fault);
            assertEquals(Optional.of("Bearer error=\"invalid_token\", error_description=\""
                            + description.replace("\\", "\\\\").replace("\"", "\\\"") + "\""),
                    response.headers().firstValue("WWW-Authenticate"));
        }
    }

    @ParameterizedTest(name = "tailspin: {0}")
    @MethodSource("tailspinRows")
    void tailspinRejection(Row row) throws Exception {
        try (TailspinPayer payer = TailspinPayer.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .client(CLIENT, jwksUrl(row.spec)).build().start(0)) {
            for (Fault fault : row.spec.faults) {
                payer.faults().enable(fault);
            }
            String token = token(row.spec, payer.publicBaseUrl() + TailspinPayer.TOKEN_PATH);
            HttpResponse<String> response = tailspinCall(payer, token, row.spec.clientId);
            if (row.spec.replay) {
                assertEquals(200, response.statusCode(), response::body);
                response = tailspinCall(payer, token, row.spec.clientId);
            }
            assertRejected(response, "invalid_client", row.message.apply(payer.publicBaseUrl()), row.fault);
            assertEquals(Optional.empty(), response.headers().firstValue("WWW-Authenticate"));
        }
    }

    private static void assertRejected(HttpResponse<String> response, String error, String description, Fault fault)
            throws Exception {
        assertEquals(401, response.statusCode(), response::body);
        JsonNode body = MAPPER.readTree(response.body());
        assertEquals(error, body.path("error").asText(), response::body);
        assertEquals(description, body.path("error_description").asText(), response::body);
        assertEquals(Optional.ofNullable(fault).map(Fault::id), response.headers().firstValue(MockPayer.FAULT_HEADER));
    }

    private static String token(Spec spec, String audience) throws Exception {
        if (spec.raw != null) {
            return spec.raw.equals(Spec.ABSENT) ? null : spec.raw;
        }
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(CLIENT).subject(CLIENT).audience(audience)
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))
                .jwtID(UUID.randomUUID().toString());
        spec.claims.accept(claims);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(spec.alg).keyID(spec.kid).build(), claims.build());
        jwt.sign(new RSASSASigner((spec.foreignKey ? TestKeys.rsa() : key).getPrivate()));
        return jwt.serialize();
    }

    private static HttpResponse<String> fabrikamCall(FabrikamPayer payer, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(payer.baseUrl() + HOOK_PATH))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        MAPPER.writeValueAsString(CdsHookRequest.of(
                                SyntheticData.orderSign(SyntheticData.standardOrders()), null))));
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> tailspinCall(TailspinPayer payer, String assertion, String clientId)
            throws Exception {
        String form = "grant_type=client_credentials&client_id=" + clientId + "&client_assertion_type="
                + URLEncoder.encode(TailspinPayer.ASSERTION_TYPE, StandardCharsets.UTF_8)
                + (assertion == null ? "" : "&client_assertion=" + URLEncoder.encode(assertion, StandardCharsets.UTF_8));
        return http.send(HttpRequest.newBuilder(URI.create(payer.tokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
