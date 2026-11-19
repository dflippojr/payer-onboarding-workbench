package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * The structural path of {@link Redactor#redact(String)} and the snapshot-first {@link Redactor#redactTree(Object)}
 * (#377 stage 1). Every secret here is synthetic.
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

    // ---- redactTree: copied into plain data once, then redacted ----

    /** A number whose text a caller controls. */
    static final class EchoNumber extends Number {
        private static final long serialVersionUID = 1L;

        @Override
        public int intValue() {
            return 0;
        }

        @Override
        public long longValue() {
            return 0;
        }

        @Override
        public float floatValue() {
            return 0;
        }

        @Override
        public double doubleValue() {
            return 0;
        }

        @Override
        public String toString() {
            return "Bearer " + SECRET;
        }
    }

    /** A {@link BigDecimal} whose text a caller controls. */
    static final class EchoDecimal extends BigDecimal {
        private static final long serialVersionUID = 1L;

        EchoDecimal() {
            super(1);
        }

        @Override
        public String toString() {
            return "Bearer " + SECRET;
        }
    }

    record Jwk(String kty, String n, String d) {
    }

    record Throwing(String name) {
        @Override
        public String name() {
            throw new IllegalStateException("accessor saw " + SECRET);
        }
    }

    enum Labelled {
        ONE {
            @Override
            public String toString() {
                return "Bearer " + SECRET;
            }
        }
    }

    @Test
    void turnsCallerNumbersIntoRedactedText() {
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(Map.of("n", new EchoNumber(), "d", new EchoDecimal()));
        assertEquals("Bearer [REDACTED]", out.get("n"));
        assertEquals("Bearer [REDACTED]", out.get("d"));
        // JDK scalars stay as they are.
        Map<String, Object> scalars = new LinkedHashMap<>();
        scalars.put("i", 7);
        scalars.put("d", new BigDecimal("1.50"));
        scalars.put("at", Instant.EPOCH);
        scalars.put("took", Duration.ofSeconds(3));
        scalars.put("c", 'x');
        assertEquals(scalars, Redactor.redactTree(scalars));
    }

    @Test
    void readsARecordWithAKtyComponentAsAJwk() {
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(Map.of("key", new Jwk("RSA", "N1", SECRET)));
        assertEquals(Map.of("kty", "RSA", "n", "N1", "d", Redactor.MASK), out.get("key"));
    }

    @Test
    void masksTheWholeTreeWhenCopyingItFails() {
        Object throwingToString = new Object() {
            @Override
            public String toString() {
                throw new IllegalStateException("toString saw " + SECRET);
            }
        };
        List<Object> holdsItself = new ArrayList<>();
        holdsItself.add(holdsItself);
        for (Object value : List.of(Map.of("x", throwingToString), Map.of("x", new Throwing("n")), holdsItself)) {
            assertEquals(Redactor.MASK, Redactor.redactTree(value));
        }
        // A step's details that cannot be copied keep only the mask.
        StepResult step = new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok", Map.of("x", throwingToString));
        assertEquals(Map.of("details", Redactor.MASK), step.details());
    }

    @Test
    void runsEachCallerMethodOnceAndKeepsNoCallerObject() {
        AtomicInteger entrySets = new AtomicInteger();
        Map<String, Object> counting = new AbstractMap<>() {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                entrySets.incrementAndGet();
                return Map.<String, Object>of("kty", "oct", "k", SECRET).entrySet();
            }
        };
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(counting);
        assertEquals(1, entrySets.get());
        assertEquals(Map.of("kty", "oct", "k", Redactor.MASK), out);
        // An enum is its name, never its own text; so is an enum key.
        assertEquals(Map.of("ONE", "ONE"), Redactor.redactTree(Map.of(Labelled.ONE, Labelled.ONE)));
    }

    @Test
    void copiesACallerObjectThatAppearsTwiceOnce() {
        AtomicInteger entrySets = new AtomicInteger();
        Map<String, Object> shared = new AbstractMap<>() {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                entrySets.incrementAndGet();
                return Map.<String, Object>of("access_token", SECRET).entrySet();
            }
        };
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("a", shared);
        tree.put("b", List.of(shared, shared));
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);
        assertEquals(1, entrySets.get());
        assertEquals(Map.of("access_token", Redactor.MASK), out.get("a"));
        assertEquals(List.of(Map.of("access_token", Redactor.MASK), Map.of("access_token", Redactor.MASK)), out.get("b"));
    }

    @Test
    void masksATreeWhoseSharedValuesExpandPastTheBoundQuickly() {
        // 40 levels of a list holding the level below twice: 2^40 leaves read as a tree, 41 objects to copy.
        AtomicInteger entrySets = new AtomicInteger();
        Object level = new AbstractMap<String, Object>() {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                entrySets.incrementAndGet();
                return Map.<String, Object>of("m", "Bearer " + SECRET).entrySet();
            }
        };
        for (int i = 0; i < 40; i++) {
            level = List.of(level, level);
        }
        Object tree = level;
        Object out = org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5),
                () -> Redactor.redactTree(tree));
        assertEquals(Redactor.MASK, out);
        assertEquals(1, entrySets.get());
        // Below the bound, sharing is kept as values: 2^10 leaves.
        Object small = "Bearer " + SECRET;
        for (int i = 0; i < 10; i++) {
            small = List.of(small, small);
        }
        assertFalse(String.valueOf(Redactor.redactTree(small)).contains(SECRET));
    }

    @Test
    void keepsNoPrivateMemberOfARecordUsedAsBothAKeyAndAValue() {
        Jwk jwk = new Jwk("RSA", "N1", SECRET);
        Map<String, Object> masked = Map.of("kty", "RSA", "n", "N1", "d", Redactor.MASK);
        // A key is copied as any value is, redacted by the same rules, then keyed by its text.
        String keyText = "{kty=RSA, n=N1, d=" + Redactor.MASK + "}";
        Map<Object, Object> keyFirst = new LinkedHashMap<>();
        keyFirst.put(jwk, "k");
        keyFirst.put("v", jwk);
        Map<Object, Object> valueFirst = new LinkedHashMap<>();
        valueFirst.put("v", jwk);
        valueFirst.put(jwk, "k");
        for (Map<Object, Object> tree : List.of(keyFirst, valueFirst)) {
            Object out = Redactor.redactTree(tree);
            assertFalse(String.valueOf(out).contains(SECRET), String.valueOf(out));
            assertEquals(Map.of(keyText, "k", "v", masked), out);
        }
    }

    @Test
    void masksARootOrAKeyPastTheSizeBound() {
        // A string of MAX_WEIGHT characters weighs one more than the bound.
        String big = "x".repeat((int) PlainData.MAX_WEIGHT);
        Object bigText = new Object() {
            @Override
            public String toString() {
                return big;
            }
        };
        assertEquals(Redactor.MASK, Redactor.redactTree(big));
        assertEquals(Redactor.MASK, Redactor.redactTree(bigText));
        assertEquals(Redactor.MASK, Redactor.redactTree(Map.of(bigText, "v")));
    }

    @Test
    void masksEachFieldValueOnTheTreeAsTheJsonPathDoes() {
        // One masking rule for a field's value, whichever path reads it and whatever type the caller gave it.
        List<String> names = new ArrayList<>();
        names.addAll(Redactor.SECRET_FIELDS);
        for (String name : Redactor.SENSITIVE_HEADERS) {
            names.add(name);
            names.add(name.toUpperCase(java.util.Locale.ROOT));
        }
        List<String> texts = List.of("v1", "v1 v2", "Bearer v1", "basic v1 v2", "x-y v1", " v1 ", "");
        List<java.util.function.Function<String, Object>> types = List.of(t -> t, StringBuilder::new,
                t -> new Object() {
                    @Override
                    public String toString() {
                        return t;
                    }
                });
        List<String> wrong = new ArrayList<>();
        for (String name : names) {
            for (String text : texts) {
                String expected = Redactor.redact("{" + quoted(name) + ":" + quoted(text) + "}");
                for (java.util.function.Function<String, Object> type : types) {
                    Object out = ((Map<?, ?>) Redactor.redactTree(Map.of(name, type.apply(text)))).get(name);
                    if (!expected.equals("{" + quoted(name) + ":" + quoted(String.valueOf(out)) + "}")) {
                        wrong.add(name + " " + type.apply(text).getClass().getSimpleName() + " " + quoted(text) + " => " + out
                                + " / " + expected);
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
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
