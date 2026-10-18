package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What each {@link PayerBehaviour} field changes on the wire, checked against a running Northwind payer. */
class PayerBehaviourTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void standardBehaviourIsTheDefaultAndChangesNothing() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            assertSame(PayerBehaviour.STANDARD, fixture.payer.behaviour());
            HttpResponse<String> token = token(fixture);
            JsonNode body = MAPPER.readTree(token.body());
            assertEquals("Bearer", body.path("token_type").asText());
            assertTrue(body.path("expires_in").isNumber());
            assertEquals("application/json", token.headers().firstValue("Content-Type").orElseThrow());
            assertEquals(43, body.path("access_token").asText().length(), "32 random bytes, base64url");
        }
    }

    @Test
    void tokenResponseFieldsFollowTheBehaviour() throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withTokenType("bearer").withExpiresInAsString(true)
                .withExtraTokenFields(true).withTokenContentType("application/json;charset=UTF-8");
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            HttpResponse<String> token = token(fixture);
            JsonNode body = MAPPER.readTree(token.body());

            assertEquals(200, token.statusCode());
            assertEquals("bearer", body.path("token_type").asText());
            assertTrue(body.path("expires_in").isTextual());
            assertEquals("300", body.path("expires_in").asText());
            assertEquals("example_value", body.path("example_parameter").asText());
            assertEquals("application/json;charset=UTF-8", token.headers().firstValue("Content-Type").orElseThrow());
            assertEquals("no-store", token.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size(), "the token still works");
        }
    }

    @Test
    void tokenErrorWith200IssuesNoToken() throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withTokenErrorWith200(true);
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            HttpResponse<String> token = token(fixture);
            JsonNode body = MAPPER.readTree(token.body());

            assertEquals(200, token.statusCode());
            assertEquals("invalid_client", body.path("error").asText());
            assertFalse(body.has("access_token"));
        }
    }

    @ParameterizedTest
    @EnumSource(value = PayerBehaviour.AccessToken.class, names = {"JWT_RS256", "JWT_ES256", "JWT_OTHER_AUDIENCE"})
    void jwtAccessTokensAreSignedRfc9068TokensTheHookAccepts(PayerBehaviour.AccessToken format) throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withAccessToken(format);
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            SignedJWT jwt = SignedJWT.parse(MAPPER.readTree(token(fixture).body()).path("access_token").asText());

            assertEquals(format == PayerBehaviour.AccessToken.JWT_ES256 ? JWSAlgorithm.ES256 : JWSAlgorithm.RS256,
                    jwt.getHeader().getAlgorithm());
            assertEquals("at+jwt", jwt.getHeader().getType().getType());
            assertEquals(List.of(format == PayerBehaviour.AccessToken.JWT_OTHER_AUDIENCE
                    ? AccessTokens.OTHER_AUDIENCE : fixture.payer.publicBaseUrl()), jwt.getJWTClaimsSet().getAudience());
            assertEquals(PayerFixture.CLIENT_ID, jwt.getJWTClaimsSet().getSubject());
            assertEquals(300, Duration.between(jwt.getJWTClaimsSet().getIssueTime().toInstant(),
                    jwt.getJWTClaimsSet().getExpirationTime().toInstant()).toSeconds());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size());
        }
    }

    @Test
    void veryLongTokensAreAcceptedOnHookCalls() throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withAccessToken(PayerBehaviour.AccessToken.VERY_LONG);
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            String token = MAPPER.readTree(token(fixture).body()).path("access_token").asText();

            assertEquals(PayerBehaviour.VERY_LONG_TOKEN_LENGTH, token.length());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size());
        }
    }

    @Test
    void ignoredHookAuthenticationAcceptsAnUnauthenticatedHookCall() throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withHookAuthentication(PayerBehaviour.HookAuthentication.IGNORED);
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            CdsHookResponse response = new CdsHooksClient(fixture.credentials).callHook(unauthenticated(fixture),
                    "order-sign", CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()), Map.of()));

            assertEquals(3, response.cards().size());
        }
    }

    @Test
    void discoveryShapesFollowTheBehaviour() throws Exception {
        assertEquals(0, discovery(PayerBehaviour.Discovery.EMPTY).path("services").size());

        JsonNode noPrefetch = discovery(PayerBehaviour.Discovery.NO_PREFETCH).path("services");
        assertEquals(2, noPrefetch.size());
        noPrefetch.forEach(service -> assertFalse(service.has("prefetch"), service.toString()));

        List<String> hooks = new ArrayList<>();
        discovery(PayerBehaviour.Discovery.EXTRA_UNKNOWN_SERVICES).path("services")
                .forEach(service -> hooks.add(service.path("hook").asText()));
        assertEquals(List.of("patient-view", "order-sign", "order-select", "com.example.payer-risk-score"), hooks);
    }

    @ParameterizedTest
    @ValueSource(ints = {307, 308})
    void aSameHostRedirectPointsAtAnEndpointThatAnswers(int status) throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withRedirect(
                PayerBehaviour.Redirect.sameHost("/cds-services", status));
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            HttpResponse<String> redirected = fixture.raw("GET", "/cds-services", null);
            assertEquals(status, redirected.statusCode());
            assertEquals("/moved/cds-services", redirected.headers().firstValue("Location").orElseThrow());

            try (HttpClient following = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()) {
                HttpResponse<String> followed = following.send(HttpRequest.newBuilder(
                        URI.create(fixture.payer.baseUrl() + "/cds-services")).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(200, followed.statusCode());
                assertEquals(2, MAPPER.readTree(followed.body()).path("services").size());
            }
        }
    }

    @Test
    void aRedirectNeedsA3xxStatus() {
        assertThrows(IllegalArgumentException.class, () -> new PayerBehaviour.Redirect("/cds-services", 200, "/x"));
        assertThrows(IllegalArgumentException.class, () -> new PayerBehaviour.Redirect("/cds-services", 400, "/x"));
    }

    @ParameterizedTest
    @ValueSource(longs = {-3600, -300, 300, 3600})
    void aClockOffsetMovesThePayersDateHeaderAndItsClock(long seconds) throws Exception {
        PayerBehaviour behaviour = PayerBehaviour.STANDARD.withClockOffset(Duration.ofSeconds(seconds));
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().behaviour(behaviour))) {
            for (int call = 0; call < 2; call++) {   // a second call reuses the relayed keep-alive connection
                Instant before = Instant.now();
                HttpResponse<String> response = fixture.raw("GET", "/cds-services", null);
                Instant date = ZonedDateTime.parse(response.headers().firstValue("Date").orElseThrow(),
                        DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();

                assertEquals(200, response.statusCode());
                long measured = Duration.between(before, date).toSeconds();
                assertTrue(Math.abs(measured - seconds) <= 2, "Date moved by " + measured + " s, wanted " + seconds);
                assertEquals(2, MAPPER.readTree(response.body()).path("services").size(), "the body is intact");
            }
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size(), "POSTs pass through");
        }
    }

    @Test
    void aClockOffsetNeedsPlainHttp() {
        NorthwindPayer payer = NorthwindPayer.builder().client("c", "s")
                .behaviour(PayerBehaviour.STANDARD.withClockOffset(Duration.ofMinutes(5))).build();
        payer.tls(new TestTls());
        assertThrows(IllegalStateException.class, () -> payer.start(0));
    }

    @Test
    void theRelayLeavesHeadsWithoutAReadableDateAlone() throws Exception {
        try (DateShiftingRelay relay = new DateShiftingRelay(0, 1, Duration.ofHours(1))) {
            String noDate = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            String badDate = "HTTP/1.1 200 OK\r\nDate: yesterday\r\n\r\n";
            assertEquals(noDate, relay.shift(noDate));
            assertEquals(badDate, relay.shift(badDate));
            assertEquals("HTTP/1.1 200 OK\r\nDate: Sat, 03 Oct 2026 01:00:00 GMT\r\n\r\n",
                    relay.shift("HTTP/1.1 200 OK\r\nDate: Sat, 3 Oct 2026 00:00:00 GMT\r\n\r\n"));
            assertEquals("HTTP/1.1 200 OK\r\ndate:  Sat, 03 Oct 2026 01:00:00 GMT \r\n\r\n",
                    relay.shift("HTTP/1.1 200 OK\r\ndate:  Sat, 03 Oct 2026 00:00:00 GMT \r\n\r\n"));
        }
    }

    private static HttpResponse<String> token(PayerFixture fixture) throws Exception {
        String secret = fixture.credentials.resolve("northwind-client-secret").orElseThrow();
        String basic = Base64.getEncoder().encodeToString((PayerFixture.CLIENT_ID + ":" + secret)
                .getBytes(StandardCharsets.UTF_8));
        return fixture.raw("POST", NorthwindPayer.TOKEN_PATH, "grant_type=client_credentials",
                "Authorization", "Basic " + basic, "Content-Type", "application/x-www-form-urlencoded");
    }

    private static JsonNode discovery(PayerBehaviour.Discovery shape) throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder()
                .behaviour(PayerBehaviour.STANDARD.withDiscovery(shape)))) {
            return MAPPER.readTree(fixture.raw("GET", "/cds-services", null).body());
        }
    }

    private static ConnectionRecord unauthenticated(PayerFixture fixture) {
        return ConnectionRecord.builder().payerId("northwind-synthetic").displayName(NorthwindPayer.DISPLAY_NAME)
                .environment(Environment.SANDBOX).baseUrl(fixture.payer.baseUrl()).authType(AuthType.NONE)
                .igVersion(NorthwindPayer.IG_VERSION).build();
    }
}
