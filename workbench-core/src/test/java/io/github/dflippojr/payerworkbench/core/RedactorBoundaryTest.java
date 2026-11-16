package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * The edges of the object walk and the outermost fail-closed boundary (#360, owner amendment of 2026-11-16 after security
 * round 5 on #361): a private member is found by its key's text whatever type holds the key; a map's own JWK context is
 * worked out before its keys are redacted and applies to them; and every public entry point turns anything thrown into a
 * masked placeholder, with no message and no cause. Each case checks that no character of the dummy secret is left in
 * what comes out, and that nothing is thrown.
 */
class RedactorBoundaryTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A dummy secret whose letters appear nowhere else in the texts checked below, nor in the mask. */
    private static final String SECRET = "JGVWXZJGVWXZ";

    private static final List<String> MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth");

    /** Each member's JWK, stringified 0 to 17 times, with a label naming the member and the depth only. */
    private static Map<String, String> jwkTexts() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String m : MEMBERS) {
            String text = "{\"kty\":\"oct\",\"" + m + "\":\"" + SECRET + "\"}";
            for (int depth = 0; depth <= Redactor.NESTED_LEVELS + 1; depth++) {
                out.put("member " + m + " depth " + depth, text);
                text = "{\"body\":" + JSON.writeValueAsString(text) + "}";
            }
        }
        return out;
    }

    /** Whether any character of the secret is in what {@code kept} shows, or in its JSON form. */
    private static boolean leaks(Object kept) {
        String text = String.valueOf(kept);
        if (kept instanceof Map<?, ?> || kept instanceof List<?>) {
            try {
                text += JSON.writeValueAsString(kept);
            } catch (RuntimeException e) {
                // A key JSON cannot write: its string form above is what is checked.
            }
        }
        String shown = text;
        return SECRET.chars().anyMatch(c -> shown.indexOf(c) >= 0);
    }

    /** The places a map can sit: the top, in a list in a map, and nested in a step's details. */
    private static Map<String, Function<Object, Object>> places() {
        Map<String, Function<Object, Object>> out = new LinkedHashMap<>();
        out.put("top", Redactor::redactTree);
        out.put("nested", o -> Redactor.redactTree(Map.of("a", List.of(o))));
        out.put("step details", o -> new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok",
                Map.of("nested", List.of(o))).details());
        return out;
    }

    /** Cases checked and those that left a character of the secret or threw, labelled by member and form only. */
    private static final class Misses {
        private final List<String> labels = new ArrayList<>();
        private int total;

        void check(String label, Supplier<Object> run) {
            total++;
            try {
                if (leaks(run.get())) {
                    labels.add(label + ": a character of the secret is left");
                }
            } catch (Throwable e) {
                List<String> messages = new ArrayList<>();
                for (Throwable t = e; t != null; t = t.getCause()) {
                    messages.add(String.valueOf(t.getMessage()));
                }
                labels.add(label + ": threw " + e.getClass().getSimpleName()
                        + (leaks(messages) ? ", with a character of the secret in its messages" : ""));
            }
        }

        void checkInPlaces(String label, Object value) {
            places().forEach((place, put) -> check(label + ", " + place, () -> put.apply(value)));
        }

        void assertNone() {
            assertTrue(total > 0);
            assertTrue(labels.isEmpty(), () -> labels.size() + " of " + total + " cases leaked or threw, first: "
                    + labels.subList(0, Math.min(5, labels.size())));
        }
    }

    private static Map<Object, Object> mapOf(Object... keysAndValues) {
        Map<Object, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            m.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return m;
    }

    // ---- class 1: a key of any kept type names a private member by its text ----

    @Test
    void findsAPrivateMemberByTheTextOfAKeyOfAnyTypeItKeeps() {
        Misses misses = new Misses();
        for (String m : MEMBERS) {
            if (m.length() != 1) {
                continue; // Only a one-letter member can be a character key; the others are covered as text below.
            }
            Character key = m.charAt(0);
            for (Object value : List.of(SECRET, List.of(SECRET), Map.of("v", SECRET))) {
                String form = value instanceof String ? "string" : value instanceof List ? "list" : "map";
                misses.checkInPlaces("member " + m + ", character key, " + form + " value",
                        mapOf("kty", "oct", key, value));
                misses.checkInPlaces("member " + m + ", character key, text-bearing kty, " + form + " value",
                        mapOf(new StringBuilder("kty"), "oct", key, value));
            }
        }
        for (String m : MEMBERS) {
            misses.checkInPlaces("member " + m + ", text-bearing key", mapOf("kty", "oct", new StringBuilder(m), SECRET));
        }
        misses.assertNone();
        // A key that is not a private member keeps its value.
        assertEquals(Map.of("kty", "oct", 'n', "N1"), Redactor.redactTree(mapOf("kty", "oct", 'n', "N1")));
    }

    // ---- class 2: object keys read with their own map's JWK context ----

    @Test
    void readsEveryKeyOfAMapWithThatMapsOwnJwkContext() {
        Misses misses = new Misses();
        for (String m : MEMBERS) {
            List<String> fragments = List.of("{\"" + m + "\":\"" + SECRET + "\"}", "\"" + m + "\":\"" + SECRET + "\"",
                    m + "=" + SECRET, "{\"body\":" + JSON.writeValueAsString("{\"" + m + "\":\"" + SECRET + "\"}") + "}");
            for (int f = 0; f < fragments.size(); f++) {
                String fragment = fragments.get(f);
                for (Object marker : List.of("kty", new StringBuilder("kty"))) {
                    String label = "member " + m + ", fragment form " + f + ", " + marker.getClass().getSimpleName() + " marker";
                    misses.checkInPlaces(label + ", text-bearing key, marker first",
                            mapOf(marker, "oct", new StringBuilder(fragment), 1));
                    misses.checkInPlaces(label + ", text-bearing key, marker last",
                            mapOf(new StringBuilder(fragment), 1, marker, "oct"));
                    misses.checkInPlaces(label + ", string key", mapOf(marker, "oct", fragment, 1));
                }
            }
        }
        misses.assertNone();
        // A plain member name is kept in a JWK, and outside one any key keeps its redacted text.
        assertEquals(Map.of("kty", "oct", "n", "N1", "x5t#S256", "T"),
                Redactor.redactTree(mapOf(new StringBuilder("kty"), "oct", new StringBuilder("n"), "N1", "x5t#S256", "T")));
        assertEquals(Map.of("d=1", 1), Redactor.redactTree(mapOf(new StringBuilder("d=1"), 1)));
    }

    // ---- class 3: header maps and lists that throw ----

    /** A header map whose every read throws, quoting what it holds in the message and the cause. */
    static final class ThrowingMap extends AbstractMap<String, List<String>> {
        private final String text;

        ThrowingMap(String text) {
            this.text = text;
        }

        @Override
        public Set<Entry<String, List<String>>> entrySet() {
            throw new IllegalStateException("cannot read " + text, new IllegalArgumentException(text));
        }

        @Override
        public boolean isEmpty() {
            throw new IllegalStateException("cannot read " + text, new IllegalArgumentException(text));
        }

        @Override
        public int size() {
            throw new IllegalStateException("cannot read " + text, new IllegalArgumentException(text));
        }
    }

    /** A header value list whose every read throws, quoting what it holds. */
    static final class ThrowingList extends AbstractList<String> {
        private final String text;

        ThrowingList(String text) {
            this.text = text;
        }

        @Override
        public String get(int index) {
            throw new AssertionError("cannot read " + text);
        }

        @Override
        public int size() {
            throw new AssertionError("cannot read " + text);
        }
    }

    @Test
    void masksAHeaderMapOrListThatThrowsAndLetsNoExceptionOrItsMessageOut() {
        Misses misses = new Misses();
        jwkTexts().forEach((label, jwk) -> {
            Map<String, Map<String, List<String>>> headers = new LinkedHashMap<>();
            headers.put("throwing map", new ThrowingMap(jwk));
            headers.put("throwing list", Map.of("Echo", new ThrowingList(jwk)));
            headers.forEach((form, h) -> {
                misses.check(label + ", " + form + ", redactHeaders", () -> Redactor.redactHeaders(h));
                misses.check(label + ", " + form + ", exchange request headers", () -> new HttpExchange("POST",
                        "https://payer.example/x", 200, Duration.ZERO, h, null, null, null, null));
                misses.check(label + ", " + form + ", exchange response headers", () -> new HttpExchange("POST",
                        "https://payer.example/x", 200, Duration.ZERO, null, null, h, null, null));
                misses.checkInPlaces(label + ", " + form + ", in a tree", mapOf("requestHeaders", h));
            });
        });
        misses.assertNone();
        // Ordinary headers are unchanged.
        assertEquals(Map.of("Content-Type", List.of("application/json")),
                Redactor.redactHeaders(Map.of("Content-Type", List.of("application/json"))));
    }
}
