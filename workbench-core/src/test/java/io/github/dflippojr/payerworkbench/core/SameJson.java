package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The output contract of {@link Redactor#redact(String)} since its structural path (#377): text that is one JSON value
 * comes back with canonical escape spellings, so an expectation holds when the output is the expected text or the same
 * JSON. Same JSON means the same names in the same order and the same values, and a string that holds one JSON value
 * holds the same JSON, at any depth, with the same whitespace around the value.
 */
final class SameJson {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private SameJson() {
    }

    /** Asserts that {@code input} redacts to {@code expected}: the same text, or the same JSON. */
    static void assertRedactsTo(String expected, String input) {
        assertRedactsTo(expected, input, "");
    }

    /** {@link #assertRedactsTo(String, String)} with {@code message} in the failure. */
    static void assertRedactsTo(String expected, String input, String message) {
        String out = Redactor.redact(input);
        assertTrue(same(expected, out), () -> message + " " + input + "\n expected: " + expected + "\n but was:  " + out);
    }

    /** Asserts that the Redactor keeps {@code text}: the same text, or the same JSON. */
    static void assertKept(String text) {
        assertRedactsTo(text, text, "kept");
    }

    /** {@link #assertKept(String)} with {@code message} in the failure. */
    static void assertKept(String text, String message) {
        assertRedactsTo(text, text, message);
    }

    /** Whether {@code a} and {@code b} are the same text or the same JSON. */
    static boolean same(String a, String b) {
        return a == null ? b == null : b != null && (a.equals(b) || sameJson(a, b));
    }

    /** Whether {@code a} and {@code b} are each one JSON value, the same one, with the same whitespace around it. */
    static boolean sameJson(String a, String b) {
        JsonNode x = tree(a);
        JsonNode y = tree(b);
        return x != null && y != null && same(x, y)
                && a.length() - a.stripLeading().length() == b.length() - b.stripLeading().length()
                && a.length() - a.stripTrailing().length() == b.length() - b.stripTrailing().length();
    }

    /** {@code text} as one JSON value, or {@code null} if it is not one. */
    static JsonNode tree(String text) {
        if (text.isBlank()) {
            return null;
        }
        try {
            return JSON.readTree(text);
        } catch (RuntimeException notJson) {
            return null;
        }
    }

    private static boolean same(JsonNode x, JsonNode y) {
        if (x.isString() && y.isString()) {
            String s = x.asString();
            String t = y.asString();
            return s.equals(t) || sameJson(s, t);
        }
        if (x.isObject() && y.isObject()) {
            if (x.size() != y.size()) {
                return false;
            }
            Iterator<Map.Entry<String, JsonNode>> xs = x.properties().iterator();
            Iterator<Map.Entry<String, JsonNode>> ys = y.properties().iterator();
            while (xs.hasNext()) {
                Map.Entry<String, JsonNode> m = xs.next();
                Map.Entry<String, JsonNode> n = ys.next();
                if (!m.getKey().equals(n.getKey()) || !same(m.getValue(), n.getValue())) {
                    return false;
                }
            }
            return true;
        }
        if (x.isArray() && y.isArray()) {
            if (x.size() != y.size()) {
                return false;
            }
            for (int i = 0; i < x.size(); i++) {
                if (!same(x.get(i), y.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return x.equals(y);
    }
}
