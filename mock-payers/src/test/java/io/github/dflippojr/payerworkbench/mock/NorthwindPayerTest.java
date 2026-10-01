package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.SystemAction;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NorthwindPayerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void discoveryDeclaresCrd221AndStandardPrefetchKeys() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            HttpResponse<String> response = fixture.raw("GET", "/cds-services", null);

            assertEquals(200, response.statusCode());
            for (JsonNode service : MAPPER.readTree(response.body()).path("services")) {
                assertEquals("2.2.1", service.path("extension").path(MockPayer.IG_VERSION_EXTENSION).asText());
                assertEquals(List.of("patient", "encounter", "coverage"), fieldNames(service.path("prefetch")));
            }
        }
    }

    @Test
    void orderSignPutsCoverageInformationInSystemActionsKeyedByCode() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            CdsHookResponse response = fixture.orderSign(SyntheticData.standardOrders());

            assertEquals(3, response.systemActions().size());
            for (SystemAction action : response.systemActions()) {
                assertEquals("update", action.type());
                assertEquals("DeviceRequest", action.resource().path("resourceType").asText());
            }
            response.rawJson().path("cards").forEach(card -> assertTrue(card.path("suggestions").isMissingNode()));

            List<CoverageInformation> coverage = response.coverageInformation();
            assertOutcome(coverage.get(0), "covered", "auth-needed", List.of());
            assertOutcome(coverage.get(1), "covered", "no-auth", List.of());
            assertOutcome(coverage.get(2), "conditional", "no-auth", List.of("clinical"));
            assertEquals("NW-DeviceRequest-synthetic-dr-1-E0250", coverage.get(0).coverageAssertionId());
            assertTrue(coverage.get(0).extension().toString().contains("coverage-assertion-id"));
            assertEquals("warning", response.cards().get(0).indicator());
            assertEquals("coverage-info", response.cards().get(0).source().topic().code());
        }
    }

    @Test
    void outcomesAreDeterministic() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            JsonNode first = fixture.orderSign(SyntheticData.standardOrders()).rawJson().path("systemActions");
            JsonNode second = fixture.orderSign(SyntheticData.standardOrders()).rawJson().path("systemActions");
            assertEquals(first, second);
        }
    }

    @Test
    void hookWithoutBearerTokenGets401() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            HttpResponse<String> response = fixture.raw("POST", "/cds-services/order-sign", hookBody(),
                    "Content-Type", "application/json");

            assertEquals(401, response.statusCode());
            assertTrue(response.headers().firstValue("WWW-Authenticate").orElse("").startsWith("Bearer"));
        }
    }

    @Test
    void unknownBearerTokenGets401InvalidToken() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            HttpResponse<String> response = fixture.raw("POST", "/cds-services/order-sign", hookBody(),
                    "Content-Type", "application/json", "Authorization", "Bearer not-a-real-token");

            assertEquals(401, response.statusCode());
            assertEquals("invalid_token", MAPPER.readTree(response.body()).path("error").asText());
        }
    }

    @Test
    void wrongClientSecretFailsAtTheTokenEndpoint() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            fixture.credentials.put("northwind-client-secret", "wrong-" + System.nanoTime());

            RouterException e = assertThrows(RouterException.class,
                    () -> fixture.orderSign(SyntheticData.standardOrders()));
            assertTrue(e.getMessage().contains("status=401"), e.getMessage());
            assertTrue(e.getMessage().contains("invalid_client"), e.getMessage());
        }
    }

    @Test
    void tokenEndpointOnlyAcceptsClientCredentials() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            HttpResponse<String> response = fixture.raw("POST", NorthwindPayer.TOKEN_PATH, "grant_type=password",
                    "Content-Type", "application/x-www-form-urlencoded", "Authorization", basic(fixture));

            assertEquals(400, response.statusCode());
            assertEquals("unsupported_grant_type", MAPPER.readTree(response.body()).path("error").asText());
        }
    }

    @Test
    void tokensExpireAndTheClientRecoversByFetchingANewOne() throws Exception {
        TestKeys.MutableClock clock = new TestKeys.MutableClock();
        try (PayerFixture fixture = PayerFixture.northwind(NorthwindPayer.builder().clock(clock))) {
            HttpResponse<String> tokenResponse = fixture.raw("POST", NorthwindPayer.TOKEN_PATH,
                    "grant_type=client_credentials",
                    "Content-Type", "application/x-www-form-urlencoded", "Authorization", basic(fixture));
            JsonNode token = MAPPER.readTree(tokenResponse.body());
            assertEquals(NorthwindPayer.DEFAULT_TOKEN_LIFETIME.toSeconds(), token.path("expires_in").asLong());
            String bearer = "Bearer " + token.path("access_token").asText();

            assertEquals(200, fixture.raw("POST", "/cds-services/order-sign", hookBody(),
                    "Content-Type", "application/json", "Authorization", bearer).statusCode());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size()); // SDK caches its token

            clock.advance(NorthwindPayer.DEFAULT_TOKEN_LIFETIME.plus(Duration.ofSeconds(1)));

            HttpResponse<String> expired = fixture.raw("POST", "/cds-services/order-sign", hookBody(),
                    "Content-Type", "application/json", "Authorization", bearer);
            assertEquals(401, expired.statusCode());
            assertTrue(expired.body().contains("expired"), expired.body());
            // The SDK's cached token is now expired too; it gets a 401, drops it and retries with a new one.
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size());
        }
    }

    private static void assertOutcome(CoverageInformation info, String covered, String paNeeded, List<String> docNeeded) {
        assertEquals(covered, info.covered());
        assertEquals(paNeeded, info.paNeeded());
        assertEquals(docNeeded, info.docNeeded());
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static String hookBody() throws Exception {
        return MAPPER.writeValueAsString(CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()),
                PayerFixture.northwindPrefetch()));
    }

    private static String basic(PayerFixture fixture) {
        String secret = fixture.credentials.resolve("northwind-client-secret").orElseThrow();
        String pair = URLEncoder.encode(PayerFixture.CLIENT_ID, StandardCharsets.UTF_8) + ":"
                + URLEncoder.encode(secret, StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }
}
