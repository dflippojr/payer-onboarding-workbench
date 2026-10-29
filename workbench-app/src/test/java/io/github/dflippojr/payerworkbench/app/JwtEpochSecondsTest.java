package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The recorded {@code JwtClaims} read {@code iat} and {@code exp} as NumericDate seconds. A value an
 * {@link Instant} cannot hold is absent, not a {@code DateTimeException} that stops the run (#266).
 */
class JwtEpochSecondsTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private Instant read(String value) throws Exception {
        JsonNode claims = mapper.readTree("{\"iat\":" + value + "}");
        return OnboardingRunner.epochSeconds(claims, "iat");
    }

    @Test
    void readsSecondsInsideTheInstantRange() throws Exception {
        assertEquals(Instant.ofEpochSecond(1_700_000_000L), read("1700000000"));
        assertEquals(Instant.ofEpochSecond(Instant.MAX.getEpochSecond()), read(String.valueOf(Instant.MAX.getEpochSecond())));
        assertEquals(Instant.ofEpochSecond(Instant.MIN.getEpochSecond()), read(String.valueOf(Instant.MIN.getEpochSecond())));
    }

    @Test
    void secondsBeyondTheInstantRangeAreAbsent() throws Exception {
        for (String value : new String[] {"1000000000000000000", "-1000000000000000000", "1e18",
                String.valueOf(Instant.MAX.getEpochSecond() + 1), String.valueOf(Instant.MIN.getEpochSecond() - 1),
                String.valueOf(Long.MAX_VALUE), "123456789012345678901234567890"}) {
            assertNull(read(value), value);
        }
    }

    @Test
    void missingOrNonNumericIsAbsent() throws Exception {
        assertNull(OnboardingRunner.epochSeconds(mapper.readTree("{}"), "iat"));
        assertNull(read("\"1700000000\""));
        assertNull(read("true"));
        assertNull(read("null"));
    }
}
