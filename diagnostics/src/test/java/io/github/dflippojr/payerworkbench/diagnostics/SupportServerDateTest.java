package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dflippojr.payerworkbench.core.HttpExchange;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** {@link Support#serverDate}: the payer's clock from its Date header, in each form RFC 9110 requires. */
class SupportServerDateTest {

    private static HttpExchange withDate(String date) {
        return new HttpExchange("POST", Fixtures.ORDER_SIGN_URL, 200, Duration.ofMillis(10), Map.of(), "{}",
                Fixtures.headers("Date", date), "{}", null);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Thu, 01 Oct 2026 12:00:00 GMT", "Thursday, 01-Oct-26 12:00:00 GMT",
        "Thu Oct  1 12:00:00 2026"})
    void everyFormGivesTheSameInstant(String date) {
        assertEquals(Optional.of(Fixtures.NOW), Support.serverDate(withDate(date)), date);
    }

    @Test
    void rfc850TwoDigitYearUsesTheFiftyYearRule() {
        // The example in RFC 9110 section 5.6.7: 1994, not 2094.
        assertEquals(Optional.of(Instant.parse("1994-11-06T08:49:37Z")),
                Support.serverDate(withDate("Sunday, 06-Nov-94 08:49:37 GMT")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Thu, 01 Oct 2026 12:00:00 PST", "Friday, 01-Oct-26 12:00:00 GMT",
        "Thu Oct 32 12:00:00 2026"})
    void unreadableDateGivesNoPayerClock(String date) {
        assertEquals(Optional.empty(), Support.serverDate(withDate(date)), date);
    }
}
