package io.github.dflippojr.payerworkbench.diagnostics;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.ResolverStyle;
import java.time.format.TextStyle;
import java.time.temporal.ChronoField;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The three HTTP-date forms RFC 9110 section 5.6.7 requires a recipient to accept: IMF-fixdate, the obsolete
 * RFC 850 form with a two-digit year, and asctime. A value in any of them names the same instant.
 */
final class HttpDate {

    /**
     * Strict resolution throughout: a date that does not exist, such as 29 February 2025, is malformed rather
     * than rounded to a neighbouring day.
     */
    private static final DateTimeFormatter IMF_FIXDATE = DateTimeFormatter.RFC_1123_DATE_TIME
            .withResolverStyle(ResolverStyle.STRICT);

    private static final DateTimeFormatter ASCTIME = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("EEE MMM ")
            .optionalStart().appendLiteral(' ').optionalEnd()
            .appendValue(ChronoField.DAY_OF_MONTH)
            .appendPattern(" HH:mm:ss ")
            .appendValue(ChronoField.YEAR, 4)
            .toFormatter(Locale.US)
            .withResolverStyle(ResolverStyle.STRICT);

    private HttpDate() {
    }

    /**
     * The instant {@code value} names in any of the three forms, or empty if it is none of them. {@code now} is
     * the recipient's current time, against which RFC 850's two-digit year is read.
     */
    static Optional<Instant> parse(String value, Instant now) {
        String text = value.strip();
        return attempt(() -> ZonedDateTime.parse(text, IMF_FIXDATE).toInstant())
                .or(() -> attempt(() -> rfc850(text, now)))
                .or(() -> attempt(() -> LocalDateTime.parse(text, ASCTIME).toInstant(ZoneOffset.UTC)));
    }

    /**
     * The RFC 850 form, "Thursday, 01-Oct-26 12:00:30 GMT". RFC 9110 reads the two-digit year as the most recent
     * year whose timestamp is at most 50 years after {@code now}. The year is first taken from the window that
     * starts 49 years before {@code now}, which can still be 50 years ahead; if the timestamp is then past now
     * plus 50 years, the year falls back a century. The day name must agree with the date that results.
     */
    private static Instant rfc850(String text, Instant now) {
        String[] dayAndDate = text.split(", ", 2);
        if (dayAndDate.length != 2) {
            throw new DateTimeException("an RFC 850 date starts with a day name and a comma");
        }
        LocalDateTime date = LocalDateTime.parse(dayAndDate[1], rfc850Date(now));
        if (date.isAfter(LocalDateTime.ofInstant(now, ZoneOffset.UTC).plusYears(50))) {
            date = date.minusYears(100);
        }
        if (!date.getDayOfWeek().getDisplayName(TextStyle.FULL, Locale.US).equalsIgnoreCase(dayAndDate[0])) {
            throw new DateTimeException("the day name does not match the date");
        }
        return date.toInstant(ZoneOffset.UTC);
    }

    /**
     * The RFC 850 date and time without its day name, whose two-digit year is read from the window that starts 49
     * years before {@code now}. English month names, whatever the JVM's locale, as the RFC requires.
     */
    private static DateTimeFormatter rfc850Date(Instant now) {
        int firstYear = now.atOffset(ZoneOffset.UTC).getYear() - 49;
        return new DateTimeFormatterBuilder()
                .parseCaseInsensitive()
                .appendPattern("dd-MMM-")
                .appendValueReduced(ChronoField.YEAR, 2, 2, LocalDate.of(firstYear, 1, 1))
                .appendPattern(" HH:mm:ss 'GMT'")
                .toFormatter(Locale.US)
                .withResolverStyle(ResolverStyle.STRICT);
    }

    private static Optional<Instant> attempt(Supplier<Instant> parser) {
        try {
            return Optional.of(parser.get());
        } catch (DateTimeException e) {
            return Optional.empty();
        }
    }
}
