package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.util.Random;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@link ExpiresIn} reads {@code expires_in} as the router SDK does after fhir-crd-router#105 (#177): a
 * positive whole JSON number, or a string that trims to one, and nothing else.
 */
class ExpiresInTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    /** {@code expires_in} as JSON text, and the seconds it gives; an empty column means not usable. */
    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', nullValues = "", value = {
            "300                    | 300",
            "300.0                  | 300",
            "3e2                    | 300",
            "9223372036854775807    | 9223372036854775807",
            "\"300\"                | 300",
            "\"3600 \"              | 3600",
            "\" 300\"               | 300",
            "\"+300\"               | 300",
            "\"99999999999999\"     | 99999999999999",
            "1.5                    |",
            "0                      |",
            "-300                   |",
            "9223372036854775808    |",
            "1e300                  |",
            "\"abc\"                |",
            "\"\"                   |",
            "\"5 minutes\"          |",
            "\"1.5\"                |",
            "\"1e3\"                |",
            "\"0\"                  |",
            "\"-1\"                 |",
            "\"99999999999999999999\" |",
            "true                   |",
            "false                  |",
            "{}                     |",
            "{\"seconds\":300}      |",
            "[300]                  |",
            "[]                     |",
            "null                   |"})
    void readsOnlyAPositiveWholeNumberOrNumericString(String json, Long expected) throws Exception {
        assertEquals(expected, ExpiresIn.seconds(JSON.readTree(json)));
    }

    @Test
    void missingIsNotUsable() {
        assertNull(ExpiresIn.seconds(null));
        assertNull(ExpiresIn.seconds(NODES.missingNode()));
    }

    @Test
    void everyNumberNodeTypeIsReadByValue() {
        assertEquals(300L, ExpiresIn.seconds(NODES.numberNode((short) 300)));
        assertEquals(300L, ExpiresIn.seconds(NODES.numberNode(300)));
        assertEquals(300L, ExpiresIn.seconds(NODES.numberNode(300L)));
        assertEquals(300L, ExpiresIn.seconds(NODES.numberNode(300f)));
        assertEquals(300L, ExpiresIn.seconds(NODES.numberNode(BigInteger.valueOf(300))));
        assertNull(ExpiresIn.seconds(NODES.numberNode(0.5d)));
        assertNull(ExpiresIn.seconds(NODES.numberNode(Double.NaN)), "not JSON, but a node can hold it");
        assertNull(ExpiresIn.seconds(NODES.numberNode(BigInteger.ONE.shiftLeft(64))));
    }

    /**
     * Property check over generated strings, against an oracle written from the spec rather than from
     * {@link Long#parseLong}: after trimming, an optional sign and ASCII digits whose value is in
     * {@code 1..Long.MAX_VALUE}. The alphabet favours near misses (signs, dots, exponents, spaces).
     */
    @Test
    void aStringIsUsableExactlyWhenItTrimsToAPositiveInteger() {
        Pattern integer = Pattern.compile("[+-]?[0-9]+");
        BigInteger max = BigInteger.valueOf(Long.MAX_VALUE);
        String alphabet = "0123456789000+-.eE x\t";
        Random random = new Random(177);
        for (int i = 0; i < 20_000; i++) {
            StringBuilder s = new StringBuilder();
            for (int n = random.nextInt(22); n > 0; n--) {
                s.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String text = s.toString();
            String trimmed = text.trim();
            Long expected = null;
            if (integer.matcher(trimmed).matches()) {
                BigInteger value = new BigInteger(trimmed);
                expected = value.signum() > 0 && value.compareTo(max) <= 0 ? value.longValueExact() : null;
            }
            assertEquals(expected, ExpiresIn.seconds(NODES.textNode(text)), () -> "\"" + text + "\"");
        }
    }
}
