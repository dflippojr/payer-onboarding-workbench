package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The structural path of {@link Redactor#redact(String)} (#377 stage 1); {@link RedactorTreeTest} has
 * {@link Redactor#redactTree(Object)}. Every secret here is synthetic.
 */
class RedactorStructuralTest {

    private static final String SECRET = "FAKE-SECRET-377-NOT-REAL";

    @Test
    void keepsTheWhitespaceMemberOrderAndNumberTextOfJsonAndMasksItsSecrets() {
        String in = "  {\n  \"b\" : 1.50e+3,\r\n\t\"a\": [ -0.0 , 100000000000000000000000, true,null ],\n"
                + "  \"password\" :  \"" + SECRET + "\" ,\"z\":{ }\n}\n";
        String out = "  {\n  \"b\" : 1.50e+3,\r\n\t\"a\": [ -0.0 , 100000000000000000000000, true,null ],\n"
                + "  \"password\" :  \"[REDACTED]\" ,\"z\":{ }\n}\n";
        assertEquals(out, Redactor.redact(in));
    }

    @Test
    void writesStringsAndNamesWithTheEscapeSpellingsJacksonWrites() {
        // A letter, a slash and a quote spelled as escapes, an escaped control character and a non-ASCII letter.
        assertEquals("{\"kty\":\"A/\\\"\\n\\u0001é\"}",
                Redactor.redact("{\"k\\u0074y\":\"\\u0041\\/\\u0022\\u000a\\u0001\\u00e9\"}"));
        // The decoded name is the one compared: a secret name spelled with escapes is masked, and written plainly.
        assertEquals("{\"client_secret\":\"[REDACTED]\"}", Redactor.redact("{\"client\\u005fsecret\":\"" + SECRET + "\"}"));
    }

    @Test
    void masksASecretMembersValueOfAnyTypeAndKeepsAnAuthorizationScheme() {
        assertEquals("{\"secret\":\"[REDACTED]\",\"apiKey\":\"[REDACTED]\",\"password\":null,\"private_key\":\"[REDACTED]\","
                        + "\"Authorization\":\"Bearer [REDACTED]\",\"Cookie\":\"[REDACTED]\",\"assertion\":\"[REDACTED]\"}",
                Redactor.redact("{\"secret\":12,\"apiKey\":[\"" + SECRET + "\"],\"password\":null,\"private_key\":{\"d\":\""
                        + SECRET + "\"},\"Authorization\":\"Bearer " + SECRET + "\",\"Cookie\":\"s=" + SECRET
                        + "\",\"assertion\":true}"));
    }

    @Test
    void masksTheValuesOfAJwksPrivateMembersOnlyInAnObjectWithKty() {
        assertEquals("{\"kty\":\"RSA\",\"n\":\"N1\",\"d\":\"[REDACTED]\",\"p\":\"[REDACTED]\",\"oth\":\"[REDACTED]\",\"k\":null}",
                Redactor.redact("{\"kty\":\"RSA\",\"n\":\"N1\",\"d\":\"" + SECRET + "\",\"p\":5,\"oth\":[{\"r\":\"" + SECRET
                        + "\"}],\"k\":null}"));
        String sibling = "{\"jwk\":{\"kty\":\"oct\"},\"data\":{\"d\":\"2026-11-18\",\"k\":[1,2]}}";
        assertEquals(sibling, Redactor.redact(sibling));
    }

    @Test
    void readsJsonInAStringOnTheTreeAndRedactsOtherStringsAsText() {
        assertEquals("{\"body\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\", \\\"n\\\": 1e5}\",\"m\":\"sent Bearer [REDACTED]\"}",
                Redactor.redact("{\"body\":\"{\\u0022access_token\\u0022:\\\"" + SECRET + "\\\", \\\"n\\\": 1e5}\","
                        + "\"m\":\"sent Bearer\\t" + SECRET + "\"}"));
        // A JSON string on its own is read too.
        assertEquals("  \"Bearer [REDACTED]\"", Redactor.redact("  \"Bearer " + SECRET + "\""));
        // So is a member name.
        assertEquals("{\"Bearer [REDACTED]\":1}", Redactor.redact("{\"Bearer " + SECRET + "\":1}"));
    }

    @Test
    void readsJsonNestedInStringsPastTheLevelBoundWithTheTextEngine() {
        String text = "{\"password\":\"" + SECRET + "\",\"n\":1}";
        for (int level = 0; level <= JsonRedaction.MAX_LEVELS + 2; level++) {
            String out = Redactor.redact(text);
            assertFalse(out.contains(SECRET), level + ": " + out);
            assertTrue(out.contains(Redactor.MASK), level + ": " + out);
            text = "{\"body\":" + quoted(text) + "}";
        }
    }

    @Test
    void masksJsonWhoseNamesRepeatWhole() {
        assertEquals(Redactor.MASK, Redactor.redact("{\"a\":1,\"a\":\"" + SECRET + "\"}"));
        // Repeated once decoded.
        assertEquals(Redactor.MASK, Redactor.redact("{\"a\":1,\"\\u0061\":\"" + SECRET + "\"}"));
        // Only the string that holds such JSON is masked.
        assertEquals("{\"body\":\"[REDACTED]\",\"n\":1}",
                Redactor.redact("{\"body\":\"{\\\"a\\\":1,\\\"a\\\":2}\",\"n\":1}"));
        // Two names the redaction makes one would read back as repeated names.
        assertEquals(Redactor.MASK, Redactor.redact("{\"Bearer abc123def456\":1,\"Bearer xyz789uvw012\":2}"));
    }

    @Test
    void masksJsonNestedDeeperThanTheBoundWhole() {
        String atBound = "[".repeat(JsonRedaction.MAX_DEPTH) + "\"Bearer " + SECRET + "\"" + "]".repeat(JsonRedaction.MAX_DEPTH);
        String out = Redactor.redact(atBound);
        assertEquals("[".repeat(JsonRedaction.MAX_DEPTH) + "\"Bearer [REDACTED]\"" + "]".repeat(JsonRedaction.MAX_DEPTH), out);
        String past = "[" + atBound + "]";
        assertEquals(Redactor.MASK, Redactor.redact(past));
        // Also when the text would not have parsed further on: past the bound nothing more is read.
        assertEquals(Redactor.MASK, Redactor.redact("[".repeat(JsonRedaction.MAX_DEPTH + 1) + SECRET));
    }

    @Test
    void masksTheOutermostTextWhenAStringOpensAPrivateKeyBlockItDoesNotClose() {
        String header = "-----BEGIN PRIVATE KEY-----";
        String footer = "-----END PRIVATE KEY-----";
        for (String in : List.of(
                "{\"a\":\"" + header + "\",\"b\":\"" + SECRET + "\\n" + footer + "\"}",
                "{\"kty\":\"RSA\",\"d\":\"" + header + "\",\"note\":\"" + SECRET + "\"}",
                "{\"body\":" + quoted("{\"a\":\"" + header + "\"}") + ",\"b\":\"" + SECRET + "\"}",
                "{\"" + header + "\":1,\"b\":\"" + SECRET + "\"}",
                "[\"" + header.replace("PRIVATE KEY", "PGP PRIVATE KEY BLOCK") + "\",\"" + SECRET + "\"]")) {
            assertEquals(Redactor.MASK, Redactor.redact(in), in);
        }
        // A block a string closes is masked in that string, and the rest is kept.
        assertEquals("{\"a\":\"" + header + "\\n[REDACTED]\\n" + footer + "\",\"n\":1}",
                Redactor.redact("{\"a\":\"" + header + "\\n" + SECRET + "\\n" + footer + "\",\"n\":1}"));
        // Text that is not JSON goes to the text engine, which masks the block to the end of the text.
        String notJson = "{\"a\":\"" + header + "\"} and then " + SECRET;
        assertFalse(Redactor.redact(notJson).contains(SECRET));
    }

    /** JSON whose one string opens a key block, its first character written as an escape, one or two levels down. */
    private static List<String> nestedOpenKeys() {
        String inner = "{\"k\":\"\\u002d----BEGIN PRIVATE KEY-----\"}";
        return List.of(inner, "{\"x\":" + quoted(inner) + "}");
    }

    @Test
    void masksTheOutermostTextWhenASecretMembersValueOpensAKeyBlockItDoesNotClose() {
        String rest = SECRET + "\n-----END PRIVATE KEY-----";
        for (String nested : nestedOpenKeys()) {
            String in = "{\"password\":" + quoted(nested) + ",\"note\":" + quoted(rest).replace("\n", "\\n") + "}";
            assertEquals(Redactor.MASK, Redactor.redact(in), in);
            java.util.Map<String, Object> tree = new java.util.LinkedHashMap<>();
            tree.put("password", nested);
            tree.put("note", rest);
            assertEquals(Redactor.MASK, Redactor.redactTree(tree), in);
        }
    }

    @Test
    void masksTheOutermostTextWhenAJwkPrivateMembersValueOpensAKeyBlockItDoesNotClose() {
        String rest = SECRET + "\n-----END PRIVATE KEY-----";
        for (String nested : nestedOpenKeys()) {
            String in = "{\"kty\":\"RSA\",\"d\":" + quoted(nested) + ",\"note\":" + quoted(rest).replace("\n", "\\n") + "}";
            assertEquals(Redactor.MASK, Redactor.redact(in), in);
            java.util.Map<String, Object> tree = new java.util.LinkedHashMap<>();
            tree.put("kty", "RSA");
            tree.put("d", nested);
            tree.put("note", rest);
            assertEquals(Redactor.MASK, Redactor.redactTree(tree), in);
        }
    }

    @Test
    void readsTextThatIsNotOneJsonValueWithTheTextEngine() {
        for (String text : List.of("{\"a\":1} trailing", "[1,]", "{'a':1}", "// note\n{}", "{\"a\":\"tab\there\"}", "42",
                "true", "plain prose", "   ")) {
            assertEquals(text, Redactor.redact(text), text);
        }
        assertEquals("{\"password\":\"[REDACTED]\"} trailing", Redactor.redact("{\"password\":\"" + SECRET + "\"} trailing"));
    }

    @Test
    void readsTextLongerThanTheBoundWithTheTextEngine() {
        String longText = "{\"password\":\"" + SECRET + "\",\"pad\":\"" + "x".repeat(JsonRedaction.MAX_CHARS) + "\"}";
        assertFalse(JsonRedaction.mayBeJson(longText));
        assertFalse(Redactor.redact(longText).contains(SECRET));
    }

    @Test
    void readsAStringAsTheTextSpellsItTooUntilTheTextEnginesReadersGo() {
        // The secret name's closing quote is a quote only two levels down (\\u005cu0022); decoded once, the value reads
        // as prose, but the text engine's reading of the string as spelled masks it, as it did before the structural path.
        String in = "{\"note\":\"{\\\"password\\u005cu0022:\\\"" + SECRET + "\\\"}\"}";
        String out = Redactor.redact(in);
        assertFalse(out.contains(SECRET), out);
        assertTrue(out.startsWith("{\"note\":\""), out);
    }

    @Test
    void findsAnUnclosedPrivateKeyAmongManyLabelsInLinearTime() {
        // Many closed blocks, each with its own label, then one header left open.
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < 16_000; i++) {
            String label = "X" + Integer.toString(i, 26).toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]", "")
                    + " PRIVATE KEY";
            text.append("-----BEGIN ").append(label).append("-----\\nm\\n-----END ").append(label).append("-----\\n");
        }
        String closed = "{\"k\":\"" + text + "\"}";
        String open = "{\"k\":\"" + text + "-----BEGIN LAST PRIVATE KEY-----\",\"n\":\"" + SECRET + "\"}";
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            assertTrue(Redactor.redact(closed).startsWith("{\"k\":\"-----BEGIN"));
            assertEquals(Redactor.MASK, Redactor.redact(open));
        });
    }

    private static String quoted(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
