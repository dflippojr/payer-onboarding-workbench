package io.github.dflippojr.payerworkbench.diagnostics;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.Year;
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

    /**
     * The RFC 850 date and time without its day name. The two-digit year is read as 20yy. Whether 29 February
     * exists depends only on the two digits, except for 00, and 2000 is a leap year, so this parse rejects exactly
     * the dates that no century can hold. The century is chosen afterwards, and {@link #rfc850} checks it.
     */
    private static final DateTimeFormatter RFC_850_DATE = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("dd-MMM-")
            .appendValueReduced(ChronoField.YEAR, 2, 2, 2000)
            .appendPattern(" HH:mm:ss 'GMT'")
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
     * year with those digits whose timestamp is at most 50 years after {@code now}. That year is the latest one
     * at or before the cutoff year, or the one a century earlier if the timestamp is past the cutoff. The day name
     * must agree with the date that results.
     */
    private static Instant rfc850(String text, Instant now) {
        String[] dayAndDate = text.split(", ", 2);
        if (dayAndDate.length != 2) {
            throw new DateTimeException("an RFC 850 date starts with a day name and a comma");
        }
        LocalDateTime written = LocalDateTime.parse(dayAndDate[1], RFC_850_DATE);
        LocalDateTime cutoff = LocalDateTime.ofInstant(now, ZoneOffset.UTC).plusYears(50);
        int latest = cutoff.getYear() - Math.floorMod(cutoff.getYear() - written.getYear(), 100);
        LocalDateTime date = inYear(written, latest)
                .filter(candidate -> !candidate.isAfter(cutoff))
                .or(() -> inYear(written, latest - 100))
                .orElseThrow(() -> new DateTimeException("the date does not exist in any year it could name"));
        if (!date.getDayOfWeek().getDisplayName(TextStyle.FULL, Locale.US).equalsIgnoreCase(dayAndDate[0])) {
            throw new DateTimeException("the day name does not match the date");
        }
        return date.toInstant(ZoneOffset.UTC);
    }

    /** {@code written} in {@code year}, or empty if it is 29 February and {@code year} is a common year. */
    private static Optional<LocalDateTime> inYear(LocalDateTime written, int year) {
        boolean leapDayOfCommonYear = written.getMonthValue() == 2 && written.getDayOfMonth() == 29
                && !Year.isLeap(year);
        return leapDayOfCommonYear ? Optional.empty() : Optional.of(written.withYear(year));
    }

    private static Optional<Instant> attempt(Supplier<Instant> parser) {
        try {
            return Optional.of(parser.get());
        } catch (DateTimeException e) {
            return Optional.empty();
        }
    }
}
