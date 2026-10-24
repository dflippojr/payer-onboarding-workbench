package io.github.dflippojr.payerworkbench.diagnostics;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The three HTTP-date forms RFC 9110 section 5.6.7 requires a recipient to accept: IMF-fixdate, the obsolete
 * RFC 850 form with a two-digit year, and asctime. A value in any of them names the same instant.
 */
final class HttpDate {

    private static final DateTimeFormatter ASCTIME = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("EEE MMM ")
            .optionalStart().appendLiteral(' ').optionalEnd()
            .appendValue(ChronoField.DAY_OF_MONTH)
            .appendPattern(" HH:mm:ss ")
            .appendValue(ChronoField.YEAR, 4)
            .toFormatter(Locale.US);

    private HttpDate() {
    }

    /**
     * The instant {@code value} names in any of the three forms, or empty if it is none of them. {@code now} is
     * the recipient's current time: RFC 9110 reads a two-digit year as the most recent year, within 50 years
     * either side of now, that has those two digits.
     */
    static Optional<Instant> parse(String value, Instant now) {
        String text = value.strip();
        return attempt(() -> ZonedDateTime.parse(text, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant())
                .or(() -> attempt(() -> LocalDateTime.parse(text, rfc850(now)).toInstant(ZoneOffset.UTC)))
                .or(() -> attempt(() -> LocalDateTime.parse(text, ASCTIME).toInstant(ZoneOffset.UTC)));
    }

    /**
     * The RFC 850 form, with its two-digit year read from the window that starts 49 years before {@code now}, so
     * a year up to 50 years ahead is taken as is and a year 51 or more years ahead falls back a century. Day and
     * month names are English whatever the JVM's locale, as the RFC requires.
     */
    private static DateTimeFormatter rfc850(Instant now) {
        int firstYear = now.atOffset(ZoneOffset.UTC).getYear() - 49;
        return new DateTimeFormatterBuilder()
                .parseCaseInsensitive()
                .appendPattern("EEEE, dd-MMM-")
                .appendValueReduced(ChronoField.YEAR, 2, 2, LocalDate.of(firstYear, 1, 1))
                .appendPattern(" HH:mm:ss 'GMT'")
                .toFormatter(Locale.US);
    }

    private static Optional<Instant> attempt(Supplier<Instant> parser) {
        try {
            return Optional.of(parser.get());
        } catch (DateTimeException e) {
            return Optional.empty();
        }
    }
}
