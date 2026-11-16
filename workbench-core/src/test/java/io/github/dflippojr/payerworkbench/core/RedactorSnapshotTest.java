package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * Snapshot first (#360, owner amendment of 2026-11-16 after security round 6 on #361): every public entry point copies
 * caller input once into plain JDK data before anything else, runs each caller method at most once while copying, and
 * keeps and calls no caller object afterwards. Each case checks that no character of the dummy secret is left in
 * anything the result shows, and that nothing is thrown, then or later.
 */
class RedactorSnapshotTest {

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

    private static boolean leaks(Object shown) {
        String text = String.valueOf(shown);
        return SECRET.chars().anyMatch(c -> text.indexOf(c) >= 0);
    }

    /** Cases checked and those that left a character of the secret or threw, labelled by member, depth and form only. */
    private static final class Misses {
        private final List<String> labels = new ArrayList<>();
        private int total;

        void check(String label, Supplier<Object> run) {
            total++;
            try {
                Object out = run.get();
                if (out != null) {
                    labels.add(label + ": " + out);
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

        void assertNone() {
            assertTrue(total > 0);
            assertTrue(labels.isEmpty(), () -> labels.size() + " of " + total + " cases missed, first: "
                    + labels.subList(0, Math.min(5, labels.size())));
        }
    }

    // ---- class 1: header lists whose own behaviour is trusted or kept ----

    /** A stream that ignores its mapping and gives back {@code result}, a caller list. */
    @SuppressWarnings("unchecked")
    private static Stream<String> streamGiving(List<String> result) {
        return (Stream<String>) Proxy.newProxyInstance(RedactorSnapshotTest.class.getClassLoader(),
                new Class<?>[] {Stream.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "map", "filter", "sequential", "parallel", "unordered", "onClose" -> proxy;
                    case "toList", "collect" -> result;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    /**
     * A header value list that streams as {@code streamed}. Once {@code throwsLater}, its first read works and every read
     * after it throws, quoting what it holds.
     */
    static final class CallerList extends AbstractList<String> {
        private final List<String> items;
        private final List<String> streamed;
        private final boolean throwsLater;
        private boolean read;

        CallerList(List<String> items, List<String> streamed, boolean throwsLater) {
            this.items = items;
            this.streamed = streamed;
            this.throwsLater = throwsLater;
        }

        private void touch() {
            if (throwsLater && read) {
                throw new IllegalStateException("cannot read " + items, new IllegalArgumentException(items.toString()));
            }
            read = true;
        }

        @Override
        public String get(int index) {
            touch();
            return items.get(index);
        }

        @Override
        public int size() {
            touch();
            return items.size();
        }

        @Override
        public Iterator<String> iterator() {
            touch();
            return new ArrayList<>(items).iterator();
        }

        @Override
        public Stream<String> stream() {
            touch();
            return streamGiving(streamed == null ? this : streamed);
        }

        @Override
        public String toString() {
            touch();
            return items.toString();
        }

        @Override
        public int hashCode() {
            touch();
            return items.hashCode();
        }

        @Override
        public boolean equals(Object o) {
            touch();
            return o == this;
        }
    }

    /** Whether every list in {@code headers} is a JDK list that cannot be changed and is none of {@code callers}. */
    private static String notJdkData(Map<String, List<String>> headers, Collection<Object> callers) {
        for (List<String> list : headers.values()) {
            if (!list.getClass().getName().startsWith("java.util.") || callers.stream().anyMatch(c -> c == list)) {
                return "a caller list is kept";
            }
            try {
                list.add("x");
                return "a kept list can be changed";
            } catch (UnsupportedOperationException expected) {
                // A JDK unmodifiable list.
            }
        }
        return null;
    }

    /** What every observable method of the exchange shows, or why it failed the check. */
    private static String exchangeMiss(HttpExchange exchange, Collection<Object> callers) {
        String kept = notJdkData(exchange.requestHeaders(), callers);
        kept = kept != null ? kept : notJdkData(exchange.responseHeaders(), callers);
        if (kept != null) {
            return kept;
        }
        List<Object> shown = List.of(exchange.toString(), exchange.hashCode(), exchange.equals(exchange),
                exchange.method(), exchange.url(), exchange.requestHeaders(), exchange.responseHeaders(),
                String.valueOf(exchange.requestBody()), String.valueOf(exchange.responseBody()),
                exchange.responded());
        return leaks(shown) ? "a character of the secret is left" : null;
    }

    @Test
    void copiesEveryHeaderListItselfIntoANewJdkListAndKeepsNoCallerListAfterwards() {
        Misses misses = new Misses();
        jwkTexts().forEach((label, jwk) -> {
            List<String> raw = new ArrayList<>(List.of(jwk + " tail"));
            Map<String, Supplier<CallerList>> forms = new LinkedHashMap<>();
            forms.put("streams as itself", () -> new CallerList(raw, null, false));
            forms.put("streams as another caller list", () -> new CallerList(raw, new ArrayList<>(raw), false));
            forms.put("streams as itself, then throws", () -> new CallerList(raw, null, true));
            forms.forEach((form, list) -> {
                misses.check(label + ", " + form + ", redactHeaders", () -> {
                    CallerList values = list.get();
                    Map<String, List<String>> out = Redactor.redactHeaders(Map.of("Echo", values));
                    String kept = notJdkData(out, List.of(values, values.streamed == null ? values : values.streamed));
                    return kept != null ? kept : leaks(out) ? "a character of the secret is left" : null;
                });
                misses.check(label + ", " + form + ", exchange", () -> {
                    CallerList request = list.get();
                    CallerList response = list.get();
                    HttpExchange exchange = new HttpExchange("POST", "https://payer.example/x", 200, Duration.ZERO,
                            Map.of("Echo", request), null, Map.of("Echo", response), null, null);
                    List<Object> callers = new ArrayList<>(List.of(request, response));
                    if (request.streamed != null) {
                        callers.add(request.streamed);
                        callers.add(response.streamed);
                    }
                    return exchangeMiss(exchange, callers);
                });
                misses.check(label + ", " + form + ", step details", () -> {
                    StepResult step = new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok",
                            Map.of("nested", List.of(Map.of("headers", Map.of("Echo", list.get())))));
                    return leaks(step.details()) || leaks(step.details().hashCode()) ? "a character of the secret is left"
                            : null;
                });
            });
        });
        misses.assertNone();
    }

    // ---- general: each caller method runs at most once, inside the entry point, and none afterwards ----

    /** Counts the calls made to each method of the caller objects in one case. */
    static final class Calls {
        private final Map<String, Integer> counts = new LinkedHashMap<>();

        void hit(String method) {
            counts.merge(method, 1, Integer::sum);
        }

        Map<String, Integer> snapshot() {
            return Map.copyOf(counts);
        }
    }

    /** A caller object that holds text and counts its calls. */
    static final class CountingText {
        private final Calls calls;
        private final String id;
        private final String text;

        CountingText(Calls calls, String id, String text) {
            this.calls = calls;
            this.id = id;
            this.text = text;
        }

        @Override
        public String toString() {
            calls.hit(id + ".toString");
            return text;
        }

        @Override
        public int hashCode() {
            calls.hit(id + ".hashCode");
            return 1;
        }

        @Override
        public boolean equals(Object o) {
            calls.hit(id + ".equals");
            return o == this;
        }
    }

    /** A caller map that counts every call; it holds its entries in a list, so building it calls nothing on them. */
    static final class CountingMap extends AbstractMap<Object, Object> {
        private final Calls calls;
        private final String id;
        private final List<Entry<Object, Object>> entries = new ArrayList<>();

        CountingMap(Calls calls, String id, Object... keysAndValues) {
            this.calls = calls;
            this.id = id;
            for (int i = 0; i < keysAndValues.length; i += 2) {
                entries.add(new SimpleImmutableEntry<>(keysAndValues[i], keysAndValues[i + 1]));
            }
        }

        @Override
        public Set<Entry<Object, Object>> entrySet() {
            calls.hit(id + ".entrySet");
            Set<Entry<Object, Object>> set = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
            set.addAll(entries);
            return set;
        }

        @Override
        public int size() {
            calls.hit(id + ".size");
            return entries.size();
        }

        @Override
        public boolean isEmpty() {
            calls.hit(id + ".isEmpty");
            return entries.isEmpty();
        }

        @Override
        public Object get(Object key) {
            calls.hit(id + ".get");
            return null;
        }

        @Override
        public String toString() {
            calls.hit(id + ".toString");
            return id;
        }

        @Override
        public int hashCode() {
            calls.hit(id + ".hashCode");
            return 1;
        }

        @Override
        public boolean equals(Object o) {
            calls.hit(id + ".equals");
            return o == this;
        }
    }

    /** A caller list that counts every call. */
    static final class CountingList extends AbstractList<Object> {
        private final Calls calls;
        private final String id;
        private final List<Object> items;

        CountingList(Calls calls, String id, Object... items) {
            this.calls = calls;
            this.id = id;
            this.items = new ArrayList<>(List.of(items));
        }

        @Override
        public Object get(int index) {
            calls.hit(id + ".get");
            return items.get(index);
        }

        @Override
        public int size() {
            calls.hit(id + ".size");
            return items.size();
        }

        @Override
        public Iterator<Object> iterator() {
            calls.hit(id + ".iterator");
            return new ArrayList<>(items).iterator();
        }

        @Override
        public Stream<Object> stream() {
            calls.hit(id + ".stream");
            return new ArrayList<>(items).stream();
        }

        @Override
        public java.util.Spliterator<Object> spliterator() {
            calls.hit(id + ".spliterator");
            return new ArrayList<>(items).spliterator();
        }

        @Override
        public String toString() {
            calls.hit(id + ".toString");
            return id;
        }

        @Override
        public int hashCode() {
            calls.hit(id + ".hashCode");
            return 1;
        }

        @Override
        public boolean equals(Object o) {
            calls.hit(id + ".equals");
            return o == this;
        }
    }

    /** Every object reachable in {@code out}, by identity. */
    private static Set<Object> reachable(Object out) {
        Set<Object> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        List<Object> todo = new ArrayList<>();
        todo.add(out);
        while (!todo.isEmpty()) {
            Object o = todo.removeLast();
            if (o == null || !seen.add(o)) {
                continue;
            }
            if (o instanceof Map<?, ?> m && m.getClass().getName().startsWith("java.util.")) {
                m.forEach((k, v) -> {
                    todo.add(k);
                    todo.add(v);
                });
            } else if (o instanceof List<?> l && l.getClass().getName().startsWith("java.util.")) {
                todo.addAll(l);
            }
        }
        return seen;
    }

    /**
     * Runs one entry point on fresh caller objects and fails the case if a caller method ran more than once, ran after
     * the entry point returned (while every method of the result is used), or a caller object is kept in the result.
     */
    private static String generalMiss(java.util.function.Function<Calls, Object[]> make,
                                      java.util.function.Function<Object[], Object> entry) {
        Calls calls = new Calls();
        Object[] callers = make.apply(calls);
        Object result = entry.apply(callers);
        Map<String, Integer> during = calls.snapshot();
        List<String> twice = during.entrySet().stream().filter(e -> e.getValue() > 1).map(Map.Entry::getKey).toList();
        if (!twice.isEmpty()) {
            return "ran more than once: " + twice;
        }
        Set<Object> kept = reachable(result instanceof HttpExchange e ? List.of(e.requestHeaders(), e.responseHeaders())
                : result instanceof StepResult s ? s.details() : result);
        for (Object c : callers) {
            if (kept.contains(c)) {
                return "kept a caller object";
            }
        }
        for (Object o : kept) {
            if (o != null && !o.getClass().getName().startsWith("java.")) {
                return "kept a " + o.getClass().getSimpleName();
            }
        }
        // Every method of the result is used; a step's own text (its timestamp) is not part of what is checked.
        String all = String.valueOf(result) + result.hashCode() + result.equals(result);
        Object visible = result instanceof StepResult s ? s.details() : result;
        String shown = String.valueOf(visible) + JSON.writeValueAsString(
                result instanceof StepResult s ? s.details() : result instanceof HttpExchange e ? e.requestHeaders() : result)
                + (result instanceof StepResult ? "" : all);
        if (!calls.snapshot().equals(during)) {
            return "a caller method ran after the entry point returned";
        }
        return leaks(shown) ? "a character of the secret is left" : null;
    }

    @Test
    void runsEachCallerMethodAtMostOnceInsideTheEntryPointAndKeepsNoCallerObject() {
        Misses misses = new Misses();
        jwkTexts().forEach((label, jwk) -> {
            java.util.function.Function<Calls, Object[]> tree = calls -> {
                CountingText key = new CountingText(calls, "key", "note");
                CountingText value = new CountingText(calls, "value", jwk);
                // The same caller objects sit in more than one place: each is still read once.
                CountingList list = new CountingList(calls, "list", value, "x", value);
                CountingMap inner = new CountingMap(calls, "inner", "v", new CountingText(calls, "deep", jwk));
                CountingMap map = new CountingMap(calls, "map", key, list, "inner", inner, "again", inner, "value", value);
                return new Object[] {map, key, value, list, inner};
            };
            java.util.function.Function<Calls, Object[]> headers = calls -> {
                CountingList values = new CountingList(calls, "values", jwk, "plain");
                CountingMap map = new CountingMap(calls, "headers", "Echo", values, "Echo-Again", values);
                return new Object[] {map, values};
            };
            misses.check(label + ", redactTree", () -> generalMiss(tree, c -> Redactor.redactTree(c[0])));
            misses.check(label + ", step details", () -> generalMiss(tree,
                    c -> new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok", Map.of("nested", c[0]))));
            misses.check(label + ", redactHeaders", () -> generalMiss(headers,
                    c -> Redactor.redactHeaders(castHeaders(c[0]))));
            misses.check(label + ", exchange", () -> generalMiss(headers, c -> new HttpExchange("POST",
                    "https://payer.example/x", 200, Duration.ZERO, castHeaders(c[0]), null, null, null, null)));
        });
        misses.assertNone();
        // Ordinary input is unchanged.
        assertEquals(Map.of("a", List.of("b", 1)), Redactor.redactTree(new LinkedHashMap<>(Map.of("a", List.of("b", 1)))));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<String>> castHeaders(Object map) {
        return (Map<String, List<String>>) map;
    }
}
