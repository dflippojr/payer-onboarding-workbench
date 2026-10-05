package io.github.dflippojr.payerworkbench.mock;

import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdPrefetch;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Each fault, on each payer, as fhir-crd-router's client SDK experiences it. */
class FaultInjectionTest {

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void slowResponseDelaysHookCallsBeyondAClientDeadline(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            Duration delay = Duration.ofMillis(2_000);
            fixture.payer.faults().slowResponse(delay);

            // Discovery (and, for Northwind, the token request inside the hook call) stays fast.
            long start = System.nanoTime();
            assertFalse(fixture.client.discoverServices(fixture.record).isEmpty());
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(delay) < 0, "discovery was delayed");

            CompletableFuture<CdsHookResponse> call =
                    CompletableFuture.supplyAsync(() -> fixture.orderSign(SyntheticData.standardOrders()));
            assertThrows(TimeoutException.class, () -> call.get(150, TimeUnit.MILLISECONDS));
            call.cancel(true);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void expiredToken401RejectsHookCalls(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            fixture.payer.faults().enable(Fault.EXPIRED_TOKEN_401);

            RouterException e = assertThrows(RouterException.class,
                    () -> fixture.orderSign(SyntheticData.standardOrders()));
            assertTrue(e.getMessage().contains("HTTP 401"), e.getMessage());
            assertTrue(e.getMessage().contains("expired"), e.getMessage());

            fixture.payer.faults().disable(Fault.EXPIRED_TOKEN_401);
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void wrongAudienceRejectsHookCalls(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            fixture.payer.faults().enable(Fault.WRONG_AUDIENCE_REJECT);

            RouterException e = assertThrows(RouterException.class,
                    () -> fixture.orderSign(SyntheticData.standardOrders()));
            assertTrue(e.getMessage().contains("HTTP 401"), e.getMessage());
            assertTrue(e.getMessage().contains("aud"), e.getMessage());
            assertTrue(e.getMessage().contains(".example"), "names the audience it expected: " + e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void malformedCardOmitsSummaryAndIndicator(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            fixture.payer.faults().enable(Fault.MALFORMED_CARD);

            CdsHookResponse response = fixture.orderSign(SyntheticData.standardOrders());

            assertFalse(response.cards().isEmpty());
            for (Card card : response.cards()) {
                assertNull(card.summary(), "summary");
                assertNull(card.indicator(), "indicator");
                assertFalse(response.rawJson().path("cards").get(0).has("summary"));
            }
            assertEquals(3, response.coverageInformation().size(), "coverage information is still delivered");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void discovery500FailsDiscoveryButNotHooks(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            fixture.payer.faults().enable(Fault.DISCOVERY_500);

            RouterException e = assertThrows(RouterException.class, () -> fixture.client.discoverServices(fixture.record));
            assertTrue(e.getMessage().contains("HTTP 500"), e.getMessage());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void prefetchMissing400NamesTheMissingKey(String payerName) throws Exception {
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            // Only the patient: what a client that ignored the payer's discovery prefetch might send.
            Map<String, Object> thinPrefetch = CrdPrefetch.builder().patient(SyntheticData.patient()).build();
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders(), thinPrefetch).cards().size(),
                    "missing prefetch is tolerated while the fault is off");

            fixture.payer.faults().enable(Fault.PREFETCH_MISSING_400);

            RouterException e = assertThrows(RouterException.class,
                    () -> fixture.orderSign(SyntheticData.standardOrders(), thinPrefetch));
            assertTrue(e.getMessage().contains("HTTP 400"), e.getMessage());
            assertTrue(e.getMessage().contains(fixture.coveragePrefetchKey), e.getMessage());
            assertEquals(3, fixture.orderSign(SyntheticData.standardOrders()).cards().size(),
                    "complete prefetch still passes");
        }
    }

}
