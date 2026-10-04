package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Hand-written {@link RunObservations} for a synthetic payer. {@link #healthy()}
 * returns a mutable run that passes every check; tests replace one part of it to
 * inject a fault. All hosts are under the reserved {@code .test} TLD.
 */
final class Fixtures {

    static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");
    static final String BASE_URL = "https://crd.synthetic-payer.test";
    static final String DISCOVERY_URL = BASE_URL + "/cds-services";
    static final String ORDER_SIGN_URL = DISCOVERY_URL + "/crd-order-sign";
    static final String TOKEN_URL = "https://auth.synthetic-payer.test/oauth2/token";
    static final String CLIENT_ID = "synthetic-client";

    /** A runtime-generated opaque access token value. */
    static final String ACCESS_TOKEN = "at" + UUID.randomUUID().toString().replace("-", "");

    static final String TOKEN_OK_BODY = "{\"access_token\":\"" + ACCESS_TOKEN
            + "\",\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"system/*.read\"}";

    private static final SecureRandom RANDOM = new SecureRandom();

    private Fixtures() {
    }

    static RedactedConnection connection(String igVersion, boolean mtls) {
        return new RedactedConnection("synthetic-payer", "Synthetic Health Plan", Environment.SANDBOX, BASE_URL,
                AuthType.OAUTH2_CLIENT_CREDENTIALS, TOKEN_URL, CLIENT_ID, "synthetic-kid", null, null,
                List.of("system/*.read"), true, mtls, igVersion, ConnectionStatus.ACTIVE);
    }

    static String resource(String name) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalArgumentException("missing fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A JWT with a random (fake) signature; the signature is returned via {@link #signatureOf}. */
    static String jwt(String aud, Instant iat, Instant exp) {
        String header = "{\"alg\":\"RS384\",\"typ\":\"JWT\",\"kid\":\"synthetic-kid\"}";
        String payload = "{\"iss\":\"" + CLIENT_ID + "\",\"sub\":\"" + CLIENT_ID + "\",\"aud\":\"" + aud
                + "\",\"jti\":\"" + UUID.randomUUID() + "\",\"iat\":" + iat.getEpochSecond()
                + ",\"exp\":" + exp.getEpochSecond() + "}";
        byte[] sig = new byte[64];
        RANDOM.nextBytes(sig);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + enc.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + enc.encodeToString(sig);
    }

    static String signatureOf(String jwt) {
        return jwt.substring(jwt.lastIndexOf('.') + 1);
    }

    static Map<String, List<String>> headers(String... nameValues) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        for (int i = 0; i < nameValues.length; i += 2) {
            h.put(nameValues[i], List.of(nameValues[i + 1]));
        }
        return h;
    }

    static String httpDate(Instant instant) {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(instant.atOffset(ZoneOffset.UTC));
    }

    static HttpExchange discovery(int status, String body) {
        return new HttpExchange("GET", DISCOVERY_URL, status, Duration.ofMillis(120), headers("Accept", "application/json"),
                null, headers("Content-Type", "application/json", "Date", httpDate(NOW)), body, null);
    }

    static HttpExchange unreachable(String method, String url, String error) {
        return new HttpExchange(method, url, HttpExchange.NO_RESPONSE, Duration.ofMillis(40), Map.of(), null,
                Map.of(), null, error);
    }

    static String assertionBody(String jwt) {
        return "grant_type=client_credentials&scope=system%2F*.read"
                + "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                + "&client_assertion=" + jwt;
    }

    static HttpExchange token(int status, String requestBody, String responseBody, Instant serverDate) {
        return new HttpExchange("POST", TOKEN_URL, status, Duration.ofMillis(200),
                headers("Content-Type", "application/x-www-form-urlencoded"), requestBody,
                headers("Content-Type", "application/json", "Date", httpDate(serverDate)), responseBody, null);
    }

    static HttpExchange hook(int status, String body, long latencyMillis) {
        return new HttpExchange("POST", ORDER_SIGN_URL, status, Duration.ofMillis(latencyMillis),
                headers("Authorization", "Bearer " + ACCESS_TOKEN, "Content-Type", "application/json"),
                "{\"hook\":\"order-sign\",\"hookInstance\":\"" + UUID.randomUUID() + "\"}",
                headers("Content-Type", "application/json", "Date", httpDate(NOW)), body, null);
    }

    static TokenResponseMetadata okToken() {
        return new TokenResponseMetadata(true, "Bearer", 300L, List.of("system/*.read"), null, null);
    }

    static TokenResponseMetadata tokenError(String error, String description) {
        return new TokenResponseMetadata(false, null, null, List.of(), error, description);
    }

    static HookResponse orderSign(HttpExchange exchange) {
        return new HookResponse("crd-order-sign", "order-sign", "sample-order-sign-1", exchange);
    }

    /** A hook call that carried a CDS Hooks client JWT with this {@code aud}. */
    static HookResponse orderSign(HttpExchange exchange, String aud) {
        return new HookResponse("crd-order-sign", "order-sign", "sample-order-sign-1", exchange,
                new JwtClaims(CLIENT_ID, List.of(aud), NOW.plusSeconds(300), NOW, UUID.randomUUID().toString(),
                        "synthetic-kid"));
    }

    static Run healthy() {
        return new Run();
    }

    /** Asserts exactly one finding and returns it. */
    static Finding assertOnly(List<Finding> findings) {
        assertEquals(1, findings.size(), () -> "expected one finding but got " + findings);
        return findings.get(0);
    }

    static Finding assertOnly(List<Finding> findings, Severity severity) {
        Finding f = assertOnly(findings);
        assertEquals(severity, f.severity(), () -> "unexpected severity: " + f);
        return f;
    }

    /** A healthy run whose parts tests may replace before {@link #build()}. */
    static final class Run {
        RedactedConnection connection = connection("2.0.1", false);
        HttpExchange discovery = discovery(200, resource("discovery-healthy.json"));
        HttpExchange token = token(200, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))), TOKEN_OK_BODY, NOW);
        TokenResponseMetadata tokenResponse = okToken();
        List<HookResponse> hooks = new ArrayList<>(List.of(orderSign(hook(200, resource("order-sign-healthy.json"), 800))));
        List<HttpExchange> extraExchanges = new ArrayList<>();

        Run hookBody(String body) {
            hooks = new ArrayList<>(List.of(orderSign(hook(200, body, 800))));
            return this;
        }

        RunObservations build() {
            RunObservations.Builder b = RunObservations.builder(connection);
            if (discovery != null) {
                b.exchange(discovery).discovery(discovery);
            }
            if (token != null) {
                b.exchange(token);
            }
            b.tokenResponse(tokenResponse);
            for (HookResponse h : hooks) {
                b.exchange(h.exchange()).hookResponse(h);
            }
            extraExchanges.forEach(b::exchange);
            return b.build();
        }
    }
}
