package io.github.dflippojr.payerworkbench.mock;

import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** fhir-crd-router's client SDK, pointed at each payer through a ConnectionRecord, with every fault off. */
class ClientSdkHappyPathTest {

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void faultsAreOffByDefault(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            assertTrue(fixture.payer.faults().enabled().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void discoversOrderSignAndOrderSelect(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            List<CdsServiceDescriptor> services = fixture.client.discoverServices(fixture.record);

            Map<String, String> hookById = services.stream()
                    .collect(Collectors.toMap(CdsServiceDescriptor::id, CdsServiceDescriptor::hook));
            assertEquals(Map.of(fixture.orderSignId, "order-sign", fixture.orderSelectId, "order-select"), hookById);
            services.forEach(s -> assertTrue(s.prefetch().containsKey(fixture.coveragePrefetchKey), s.prefetch().toString()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void orderSignAuthenticatesAndReturnsParseableCoverageInformation(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            CdsHookResponse response = fixture.orderSign(SyntheticData.standardOrders());

            assertEquals(3, response.cards().size());
            for (Card card : response.cards()) {
                assertNotNull(card.summary());
                assertNotNull(card.indicator());
                assertEquals(fixture.payer.displayName(), card.source().label());
            }
            List<CoverageInformation> coverage = response.coverageInformation();
            assertEquals(List.of("DeviceRequest/synthetic-dr-1", "DeviceRequest/synthetic-dr-2", "DeviceRequest/synthetic-dr-3"),
                    coverage.stream().map(CoverageInformation::resourceReference).toList());
            coverage.forEach(c -> {
                assertEquals("Coverage/" + SyntheticData.COVERAGE_ID, c.coverage());
                assertNotNull(c.coverageAssertionId());
                assertNotNull(c.date());
            });
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void orderSelectReturnsGuidanceCardsOnly(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            CdsHookResponse response = fixture.orderSelect(SyntheticData.standardOrders());

            assertEquals(3, response.cards().size());
            assertTrue(response.systemActions().isEmpty());
            assertTrue(response.coverageInformation().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void repeatedCallsSucceed(String payerName) throws Exception {
        // Northwind reuses its cached token; Fabrikam needs a fresh jti every time.
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            for (int i = 0; i < 3; i++) {
                assertFalse(fixture.orderSign(SyntheticData.standardOrders()).cards().isEmpty());
            }
        }
    }
}
