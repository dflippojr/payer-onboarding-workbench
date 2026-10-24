package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** {@link HttpDate}: the three RFC 9110 forms, and the two-digit year window that RFC 850 needs. */
class HttpDateTest {

    private static final Instant NOW = Fixtures.NOW;

    @ParameterizedTest
    @ValueSource(strings = {"Thu, 01 Oct 2026 12:00:30 GMT", "Thursday, 01-Oct-26 12:00:30 GMT",
        "Thu Oct  1 12:00:30 2026", " Thu, 01 Oct 2026 12:00:30 GMT "})
    void everyFormNamesTheSameInstant(String value) {
        assertEquals(Optional.of(Instant.parse("2026-10-01T12:00:30Z")), HttpDate.parse(value, NOW), value);
    }

    @Test
    void rfc9110ExampleIsReadAsNineteenNinetyFour() {
        assertEquals(Optional.of(Instant.parse("1994-11-06T08:49:37Z")),
                HttpDate.parse("Sunday, 06-Nov-94 08:49:37 GMT", NOW));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1977-10-01T12:00:00Z", "2026-10-01T12:00:00Z", "2075-10-01T12:00:00Z",
        "2076-10-01T12:00:00Z"})
    void twoDigitYearWithinFiftyYearsEitherSideIsReadAsWritten(String when) {
        Instant expected = Instant.parse(when);
        assertEquals(Optional.of(expected), HttpDate.parse(rfc850(expected), NOW), when);
    }

    @Test
    void twoDigitYearMoreThanFiftyYearsAheadFallsBackACentury() {
        // 2077 is 51 years after 2026, so "77" names 1977. Saturday is 1977's weekday, so the day name agrees.
        assertEquals(Optional.of(Instant.parse("1977-10-01T12:00:00Z")),
                HttpDate.parse("Saturday, 01-Oct-77 12:00:00 GMT", NOW));
    }

    @Test
    void yearThatIsPastTheFiftyYearEdgeInItsLaterMonthsTakesThePreviousCentury() {
        // 31 Dec 2076 is after 1 Oct 2076, the most 50 years after NOW, so the year is 1976. Friday is 1976's weekday.
        assertEquals(Optional.of(Instant.parse("1976-12-31T12:00:00Z")),
                HttpDate.parse("Friday, 31-Dec-76 12:00:00 GMT", NOW));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Friday, 29-Feb-25 12:00:00 GMT", "Fri, 29 Feb 2025 12:00:00 GMT",
        "Fri Feb 29 12:00:00 2025"})
    void dayThatDoesNotExistIsMalformedNotRounded(String value) {
        assertEquals(Optional.empty(), HttpDate.parse(value, NOW), value);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not a date", "Thu, 01 Oct 2026 12:00:30 PST", "Thu Oct 1 12:00:30",
        "Thu Oct 32 12:00:30 2026", "Fri Oct  1 12:00:30 2026", "Friday, 01-Oct-26 12:00:30 GMT",
        "Thursday, 01-Oct-26 12:00:30", "Thursday, 32-Oct-26 12:00:30 GMT"})
    void unreadableValueNamesNoInstant(String value) {
        assertEquals(Optional.empty(), HttpDate.parse(value, NOW), value);
    }

    /** {@code instant} written in the RFC 850 form, the way a payer would send it. */
    private static String rfc850(Instant instant) {
        return DateTimeFormatter.ofPattern("EEEE, dd-MMM-uu HH:mm:ss 'GMT'", Locale.US)
                .format(instant.atOffset(ZoneOffset.UTC));
    }
}
