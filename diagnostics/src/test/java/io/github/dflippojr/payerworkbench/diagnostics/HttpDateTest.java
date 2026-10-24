package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.LocalDateTime;
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

    @Test
    void leapDayOfACenturyYearIsReadInTheCenturyThatHasOne() {
        // With NOW in 2050 the 50-year edge is in 2100, which has no 29 February, so "00" is 2000, a leap year.
        assertEquals(Optional.of(Instant.parse("2000-02-29T12:00:00Z")),
                HttpDate.parse("Tuesday, 29-Feb-00 12:00:00 GMT", Instant.parse("2050-01-01T12:00:00Z")));
    }

    @Test
    void rfc850ReadsEveryDayAroundTheFiftyYearEdgeAsTheRfcDoes() {
        // A timestamp up to NOW plus 50 years is read as written; one later than that is read a century back.
        LocalDateTime edge = LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).plusYears(50);
        for (LocalDateTime day = edge.minusDays(400); day.isBefore(edge.plusDays(400)); day = day.plusDays(1)) {
            Instant named = day.isAfter(edge)
                    ? day.minusYears(100).toInstant(ZoneOffset.UTC)
                    : day.toInstant(ZoneOffset.UTC);
            assertEquals(Optional.of(named), HttpDate.parse(rfc850(named), NOW), named.toString());
        }
    }

    @Test
    void leapDayWithNoLeapYearInTheWindowIsMalformed() {
        // With NOW in 2150 the window ends in 2200, and neither 2200 nor 2100 is a leap year, so no year fits.
        assertEquals(Optional.empty(),
                HttpDate.parse("Tuesday, 29-Feb-00 12:00:00 GMT", Instant.parse("2150-01-01T12:00:00Z")));
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
