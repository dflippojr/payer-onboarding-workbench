package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalField;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * How {@link Redactor#redactTree(Object)} walks objects (#360, owner decision of 2026-11-16 after security round 4 on
 * #361): only strings, maps, lists and an explicit set of exact JDK scalar classes are walked or kept; every other object
 * becomes text inside the fail-closed boundary, and that text goes through {@link Redactor#redact(String)} with the
 * enclosing JWK context carried in. Each grid puts a JWK private member, stringified 0 to 17 times, into one class of
 * object and checks that no character of the dummy secret is left anywhere in the output, and that nothing is thrown.
 */
class RedactorTraversalTest {

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

    /** Whether any character of the secret is in what {@code kept} shows. */
    private static boolean leaks(Object kept) {
        String text = String.valueOf(kept);
        return SECRET.chars().anyMatch(c -> text.indexOf(c) >= 0);
    }

    /** The places a value can sit in a tree: as a value, as a key, in a list, and in a step's details. */
    private static Map<String, Function<Object, Object>> places() {
        Map<String, Function<Object, Object>> out = new LinkedHashMap<>();
        out.put("value", o -> Redactor.redactTree(mapOf("v", o)));
        out.put("key", o -> Redactor.redactTree(mapOf(o, 1)));
        out.put("list item", o -> Redactor.redactTree(List.of(o)));
        out.put("top", Redactor::redactTree);
        out.put("step details value", o -> new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok",
                Map.of("nested", List.of(mapOf("v", o)))).details());
        out.put("step details key", o -> new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok",
                Map.of("nested", mapOf(o, 1))).details());
        return out;
    }

    private static Map<Object, Object> mapOf(Object k, Object v) {
        Map<Object, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    /** Cases checked and those that left a character of the secret or threw, labelled by member and depth only. */
    private static final class Misses {
        private final List<String> labels = new ArrayList<>();
        private int total;

        /** Runs every case in every place. */
        void check(Map<String, Object> cases) {
            for (Map.Entry<String, Object> c : cases.entrySet()) {
                for (Map.Entry<String, Function<Object, Object>> place : places().entrySet()) {
                    total++;
                    String label = c.getKey() + ", " + place.getKey();
                    try {
                        if (leaks(place.getValue().apply(c.getValue()))) {
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
            }
        }

        /** Fails with how many of the cases missed, and the first few labels. */
        void assertNone() {
            assertTrue(total > 0);
            assertTrue(labels.isEmpty(), () -> labels.size() + " of " + total + " cases leaked or threw, first: "
                    + labels.subList(0, Math.min(5, labels.size())));
        }
    }

    // ---- class 1: text-bearing subtypes of scalar types ----

    /** A number that holds text. */
    static final class TextNumber extends Number {
        private final transient String text;

        TextNumber(String text) {
            this.text = text;
        }

        @Override
        public int intValue() {
            return 1;
        }

        @Override
        public long longValue() {
            return 1;
        }

        @Override
        public float floatValue() {
            return 1;
        }

        @Override
        public double doubleValue() {
            return 1;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    /** A subclass of a JDK number class that is not final. */
    static final class TextDecimal extends BigDecimal {
        private final transient String text;

        TextDecimal(String text) {
            super(1);
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }

        @Override
        public boolean equals(Object o) {
            return this == o;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(this);
        }
    }

    /** A temporal value that holds text. */
    record TextTemporal(String text) implements TemporalAccessor {
        @Override
        public boolean isSupported(TemporalField field) {
            return false;
        }

        @Override
        public long getLong(TemporalField field) {
            return 0;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    /** An enum whose constant holds text. */
    enum TextEnum {
        ONE;

        private String text;

        @Override
        public String toString() {
            return text;
        }
    }

    @Test
    void turnsTextBearingSubtypesOfNumberTemporalAndEnumValuesIntoRedactedTextAsKeysAndValues() {
        Misses misses = new Misses();
        for (Map.Entry<String, String> jwk : jwkTexts().entrySet()) {
            Map<String, Object> cases = new LinkedHashMap<>();
            cases.put(jwk.getKey() + ", number", new TextNumber(jwk.getValue()));
            cases.put(jwk.getKey() + ", JDK number subclass", new TextDecimal(jwk.getValue()));
            cases.put(jwk.getKey() + ", temporal", new TextTemporal(jwk.getValue()));
            TextEnum.ONE.text = jwk.getValue();
            cases.put(jwk.getKey() + ", enum", TextEnum.ONE);
            misses.check(cases);
        }
        misses.assertNone();
    }

    // ---- class 2: conversions that throw ----

    /** An object whose string form throws, quoting what it holds in the message and in the cause. */
    record Throwing(String text, int kind) {
        @Override
        public String toString() {
            switch (kind) {
                case 0 -> throw new IllegalStateException("cannot show " + text, new IllegalArgumentException(text));
                case 1 -> throw new AssertionError("cannot show " + text);
                default -> {
                    return sneaky(new Exception("cannot show " + text));
                }
            }
        }

        @SuppressWarnings("unchecked")
        private static <T extends Throwable> String sneaky(Throwable t) throws T {
            throw (T) t;
        }
    }

    /** A record whose component is an object whose string form throws. */
    record Holder(Object body) {
    }

    /** A record whose accessor throws, quoting what it holds. */
    record FailingAccessor(String body) {
        @Override
        public String body() {
            throw new IllegalStateException("cannot read " + body);
        }
    }

    @Test
    void masksAConversionThatThrowsAndLetsNoExceptionOrItsMessageOut() {
        Misses misses = new Misses();
        for (Map.Entry<String, String> jwk : jwkTexts().entrySet()) {
            Map<String, Object> cases = new LinkedHashMap<>();
            for (int kind = 0; kind < 3; kind++) {
                cases.put(jwk.getKey() + ", throwing kind " + kind, new Throwing(jwk.getValue(), kind));
                cases.put(jwk.getKey() + ", record component throwing kind " + kind,
                        new Holder(new Throwing(jwk.getValue(), kind)));
            }
            cases.put(jwk.getKey() + ", record accessor throwing", new FailingAccessor(jwk.getValue()));
            misses.check(cases);
        }
        misses.assertNone();
        // A map or list that holds itself is masked where it comes round again, rather than throwing or walking on.
        Map<Object, Object> cycle = new LinkedHashMap<>();
        cycle.put("self", cycle);
        cycle.put("again", List.of(cycle, cycle));
        Object out = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> Redactor.redactTree(cycle));
        assertEquals(Map.of("self", Redactor.MASK, "again", List.of(Redactor.MASK, Redactor.MASK)), out);
        // So is anything past the levels walked.
        Object deep = "end";
        for (int i = 0; i <= Redactor.TREE_LEVELS; i++) {
            deep = List.of(deep);
        }
        Object walked = Redactor.redactTree(deep);
        for (int i = 0; i < Redactor.TREE_LEVELS; i++) {
            walked = ((List<?>) walked).getFirst();
        }
        assertEquals(Redactor.MASK, walked);
    }

    // ---- class 3: records and objects that carry JWK context ----

    /** A record shaped like a JWK, with every private member as a component. */
    record JwkRecord(String kty, String d, String p, String q, String dp, String dq, String qi, String k, Object oth) {
    }

    /** A record with no {@code kty} of its own, for a JWK map to enclose. */
    record Member(String d, String p, String q, String dp, String dq, String qi, String k, Object oth) {
    }

    /** A plain object with a {@code kty} field. */
    static final class JwkObject {
        private final String kty = "oct";
        private final String member;
        private final String value;

        JwkObject(String member, String value) {
            this.member = member;
            this.value = value;
        }

        @Override
        public String toString() {
            return "JwkObject " + member + "=" + value + " (" + kty.length() + ")";
        }
    }

    private static Object[] onlyMember(String member) {
        Object[] values = new Object[MEMBERS.size()];
        values[MEMBERS.indexOf(member)] = member.equals("oth") ? List.of(SECRET) : SECRET;
        return values;
    }

    @Test
    void masksARecordOrObjectThatCarriesJwkContextLikeAJwkMap() {
        Map<String, Object> cases = new LinkedHashMap<>();
        for (String m : MEMBERS) {
            Object[] v = onlyMember(m);
            cases.put("member " + m + ", record with kty", new JwkRecord("oct", (String) v[0], (String) v[1],
                    (String) v[2], (String) v[3], (String) v[4], (String) v[5], (String) v[6], v[7]));
            Member member = new Member((String) v[0], (String) v[1], (String) v[2], (String) v[3], (String) v[4],
                    (String) v[5], (String) v[6], v[7]);
            cases.put("member " + m + ", record in a JWK map", mapOf("kty", member));
            Map<Object, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "oct");
            jwk.put("x", List.of(member));
            cases.put("member " + m + ", record in a list in a JWK map", jwk);
            cases.put("member " + m + ", object with a kty field", new JwkObject(m, SECRET));
            cases.put("member " + m + ", record with kty in a record", new Holder(new JwkRecord("oct", (String) v[0],
                    (String) v[1], (String) v[2], (String) v[3], (String) v[4], (String) v[5], (String) v[6], v[7])));
        }
        Misses misses = new Misses();
        misses.check(cases);
        misses.assertNone();
    }

    // ---- what is kept ----

    @Test
    void keepsStringsMapsListsAndExactJdkScalarsAndTurnsEveryOtherObjectIntoRedactedText() {
        Map<Object, Object> tree = new LinkedHashMap<>();
        tree.put("int", 3);
        tree.put("long", 4L);
        tree.put("double", 1.5);
        tree.put("big", new BigInteger("123456789012345678901234567890"));
        tree.put("decimal", new BigDecimal("1.25"));
        tree.put("flag", true);
        tree.put("letter", 'x');
        tree.put("at", Instant.EPOCH);
        tree.put("day", LocalDate.of(2026, 11, 16));
        tree.put("took", Duration.ofSeconds(3));
        tree.put(7, "seven");
        tree.put("list", List.of("a", 1));
        tree.put("map", Map.of("b", 2));
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);
        assertEquals(tree, out);
        assertSame(Instant.EPOCH, out.get("at"));
        // Every other object is its redacted string form: an enum by its name, a record by its record form.
        assertEquals(Map.of("FAIL", "ok"), Redactor.redactTree(Map.of(Severity.FAIL, "ok")));
        assertEquals("Holder[body=plain]", Redactor.redactTree(new Holder("plain")));
        // A JDK number subclass is not its JDK class: it becomes text.
        assertEquals("plain", Redactor.redactTree(new TextDecimal("plain")));
        // A text-bearing key that is exactly kty still makes its map a JWK.
        Map<Object, Object> jwk = new LinkedHashMap<>();
        jwk.put(new StringBuilder("kty"), "oct");
        jwk.put(new StringBuilder("d"), SECRET);
        assertEquals(Map.of("kty", "oct", "d", Redactor.MASK), Redactor.redactTree(jwk));
    }
}
