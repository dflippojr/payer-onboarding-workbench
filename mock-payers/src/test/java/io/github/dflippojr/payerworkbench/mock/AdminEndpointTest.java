package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdminEndpointTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void listsEveryFaultSwitchedOff(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            JsonNode state = MAPPER.readTree(fixture.raw("GET", "/admin/faults", null).body());

            assertEquals(fixture.payer.displayName(), state.path("payer").asText());
            assertEquals(Fault.values().length, state.path("faults").size());
            state.path("faults").forEach(f -> assertFalse(f.path("enabled").asBoolean(), f.toString()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void enablesAndDisablesAFault(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            assertEquals(200, fixture.raw("POST", "/admin/faults/discovery-500", null).statusCode());

            HttpResponse<String> discovery = fixture.raw("GET", "/cds-services", null);
            assertEquals(500, discovery.statusCode());
            assertEquals("discovery-500", discovery.headers().firstValue(MockPayer.FAULT_HEADER).orElse(null));
            assertTrue(fixture.payer.faults().isEnabled(Fault.DISCOVERY_500));

            assertEquals(200, fixture.raw("DELETE", "/admin/faults/discovery-500", null).statusCode());
            HttpResponse<String> recovered = fixture.raw("GET", "/cds-services", null);
            assertEquals(200, recovered.statusCode());
            assertTrue(recovered.headers().firstValue(MockPayer.FAULT_HEADER).isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void setsTheSlowResponseDelay(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            JsonNode state = MAPPER.readTree(fixture.raw("POST", "/admin/faults/slow-response?delayMs=50", null).body());

            JsonNode slow = state.path("faults").get(0);
            assertEquals("slow-response", slow.path("id").asText());
            assertTrue(slow.path("enabled").asBoolean());
            assertEquals(50, slow.path("delayMs").asLong());
            assertEquals(Duration.ofMillis(50), fixture.payer.faults().slowResponseDelay());
            assertEquals("slow-response", fixture.raw("GET", "/cds-services", null)
                    .headers().firstValue(MockPayer.FAULT_HEADER).orElse(null));

            assertEquals(400, fixture.raw("POST", "/admin/faults/slow-response?delayMs=-5", null).statusCode());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void clearsAllFaultsAndStaysReachableUnderTlsRequired(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            fixture.payer.faults().enable(Fault.TLS_REQUIRED).enable(Fault.MALFORMED_CARD);
            assertEquals(426, fixture.raw("GET", "/cds-services", null).statusCode());

            assertEquals(200, fixture.raw("DELETE", "/admin/faults", null).statusCode());

            assertTrue(fixture.payer.faults().enabled().isEmpty());
            assertEquals(200, fixture.raw("GET", "/cds-services", null).statusCode());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void rejectsUnknownFaultsAndMethods(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            assertEquals(404, fixture.raw("POST", "/admin/faults/meteor-strike", null).statusCode());
            assertEquals(405, fixture.raw("GET", "/admin/faults/discovery-500", null).statusCode());
            assertEquals(405, fixture.raw("POST", "/admin/faults", null).statusCode());
        }
    }
}
