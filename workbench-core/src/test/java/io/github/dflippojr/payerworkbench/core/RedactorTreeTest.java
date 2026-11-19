package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * {@link Redactor#redactTree(Object)} since it takes only JSON-shaped plain data (#377, typed tree): a tree is redacted
 * exactly as the same tree written as JSON text is by {@link Redactor#redact(String)}, any other value masks the whole
 * tree without running its code, and reading stops at the size and depth bounds. Every secret here is synthetic.
 */
class RedactorTreeTest {

    private static final String SECRET = "FAKE-SECRET-377-TREE-NOT-REAL";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** The size bound, 16 Mi: one per value, container and name, and each string's and name's length as JSON spells it. */
    private static final long MAX_WEIGHT = 16L * 1024 * 1024;

    // ---- one rule: a tree as its JSON text ----

    /** Member names: every secret field and credential header, also in capitals, the JWK members and plain names. */
    private static List<String> names() {
        List<String> names = new ArrayList<>(Redactor.SECRET_FIELDS);
        for (String header : Redactor.SENSITIVE_HEADERS) {
            names.add(header);
            names.add(header.toUpperCase(Locale.ROOT));
        }
        names.addAll(Redactor.JWK_PRIVATE_MEMBERS);
        names.addAll(List.of("kty", "note", "url", ""));
        return names;
    }

    /** Values of every JSON shape, with strings a secret, a scheme, escapes, JSON or a key block might be in. */
    private static List<Object> values() {
        List<Object> texts = List.of("v1", "v1 v2", "Bearer v1", "basic v1 v2", "x-y v1", " v1 ", "",
                "Bearer " + SECRET, "Echo: token " + SECRET, "q\"b\\c\n\u0001\u007fé ",
                "{\"password\":\"" + SECRET + "\",\"n\":[1,\"Bearer " + SECRET + "\"]}", "[\"" + SECRET + "\"]",
                "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.SIG1");
        List<Object> values = new ArrayList<>(texts);
        values.addAll(List.of(7, 7L, (short) 7, (byte) 7, 1.5, 1.5f, new BigDecimal("1.50"),
                new BigInteger("100000000000000000000000"), true, false));
        values.add(null);
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", "N1");
        jwk.put("d", SECRET);
        jwk.put("oth", List.of(Map.of("r", SECRET)));
        values.add(jwk);
        values.add(Map.of("note", "Bearer " + SECRET));
        values.add(List.of("Bearer " + SECRET));
        List<Object> mixed = new ArrayList<>(List.of("Basic " + SECRET, 3, true, List.of(SECRET), Map.of("a", SECRET)));
        mixed.add(null);
        values.add(mixed);
        values.add(List.of());
        values.add(Map.of());
        return values;
    }

    @Test
    void redactsATreeAsTheJsonPathRedactsItsText() {
        List<String> wrong = new ArrayList<>();
        int checked = 0;
        for (String name : names()) {
            for (Object value : values()) {
                Map<String, Object> member = new LinkedHashMap<>();
                member.put(name, value);
                Map<String, Object> inJwk = new LinkedHashMap<>();
                inJwk.put("kty", "oct");
                inJwk.put(name.equals("kty") ? "k" : name, value);
                List<Object> item = new ArrayList<>();
                item.add(value);
                for (Object tree : List.of(member, inJwk, item, List.of(member), Map.of("outer", member))) {
                    checked += check(tree, wrong);
                }
            }
        }
        for (Object value : values()) {
            checked += check(value, wrong);
        }
        assertEquals(List.of(), wrong);
        assertTrue(checked > 10_000, "checked " + checked);
    }

    @Test
    void redactsEachCorpusEntryInATreeAsItsJsonText() throws IOException {
        JsonNode corpus;
        try (InputStream in = RedactorTreeTest.class.getResourceAsStream("/redaction-corpus.json")) {
            corpus = JSON.readTree(in);
        }
        List<String> wrong = new ArrayList<>();
        for (String section : List.of("text", "harmless")) {
            for (JsonNode entry : corpus.get(section)) {
                String input = entry.get("input").asString();
                check(Map.of("note", input), wrong);
                check(List.of(input), wrong);
                check(input, wrong);
                Object parsed = parsed(input);
                if (parsed instanceof Map<?, ?> || parsed instanceof List<?>) {
                    check(parsed, wrong);
                }
            }
        }
        for (JsonNode entry : corpus.get("headers")) {
            check(Map.of(entry.get("name").asString(), List.of(entry.get("value").asString())), wrong);
            check(Map.of(entry.get("name").asString(), entry.get("value").asString()), wrong);
        }
        assertEquals(List.of(), wrong);
    }

    /**
     * Checks {@code tree}, and the same tree as Jackson reads its JSON text into plain data, against its JSON text,
     * adding what differs to {@code wrong}; the number of trees checked.
     */
    private static int check(Object tree, List<String> wrong) {
        String text = JSON.writeValueAsString(tree);
        same(text, Redactor.redact(text), Redactor.redactTree(tree), "plain", wrong);
        Object read = JSON.readValue(text, Object.class);
        String readText = JSON.writeValueAsString(read);
        same(readText, Redactor.redact(readText), Redactor.redactTree(read), "read", wrong);
        return 2;
    }

    private static void same(String text, String expected, Object out, String form, List<String> wrong) {
        // Text the JSON path masks whole is the mask itself; any other redacted tree is compared as JSON text.
        String actual = Redactor.MASK.equals(expected) && Redactor.MASK.equals(out) ? Redactor.MASK
                : JSON.writeValueAsString(out);
        if (!expected.equals(actual)) {
            wrong.add(form + " " + text + "\n  text path: " + expected + "\n  tree path: " + actual);
        }
    }

    private static Object parsed(String text) {
        try {
            return JSON.readValue(text, Object.class);
        } catch (RuntimeException notJson) {
            return null;
        }
    }

    @Test
    void masksAJacksonTreeAndRedactsItOnceConvertedToPlainData() {
        JsonNode node = JSON.readTree("{\"a\":[1,2.5,true,null,\"Bearer " + SECRET + "\"],\"b\":{\"client_secret\":\""
                + SECRET + "\"}}");
        // A Jackson tree is not plain data: the whole tree is the mask, also inside plain data.
        assertEquals(Redactor.MASK, Redactor.redactTree(node));
        assertEquals(Redactor.MASK, Redactor.redactTree(Map.of("node", node)));
        assertEquals(Redactor.MASK, Redactor.redactTree(JsonNodeFactory.instance.pojoNode(new StringBuilder(SECRET))));
        // A caller converts it first.
        Map<String, Object> b = Map.of("client_secret", Redactor.MASK);
        List<Object> a = new ArrayList<>(List.of(1, 2.5, true));
        a.add(null);
        a.add("Bearer " + Redactor.MASK);
        Object out = Redactor.redactTree(JSON.convertValue(node, Object.class));
        assertEquals(Map.of("a", a, "b", b), out);
        assertTrue(out.getClass().getName().startsWith("java.util."), () -> "not plain data: " + out.getClass());
    }

    // ---- anything else is rejected and masked ----

    record Jwk(String kty, String n, String d, AtomicInteger reads) {
        @Override
        public String d() {
            reads.incrementAndGet();
            return d;
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

    /** A number whose text a caller controls, counting each time its code runs. */
    static final class CountingNumber extends Number {
        private static final long serialVersionUID = 1L;
        private final transient AtomicInteger calls;

        CountingNumber(AtomicInteger calls) {
            this.calls = calls;
        }

        @Override
        public int intValue() {
            calls.incrementAndGet();
            return 0;
        }

        @Override
        public long longValue() {
            calls.incrementAndGet();
            return 0;
        }

        @Override
        public float floatValue() {
            calls.incrementAndGet();
            return 0;
        }

        @Override
        public double doubleValue() {
            calls.incrementAndGet();
            return 0;
        }

        @Override
        public String toString() {
            calls.incrementAndGet();
            return "Bearer " + SECRET;
        }
    }

    /** A {@link BigDecimal} whose text a caller controls. */
    static final class EchoDecimal extends BigDecimal {
        private static final long serialVersionUID = 1L;
        private final transient AtomicInteger calls;

        EchoDecimal(AtomicInteger calls) {
            super(1);
            this.calls = calls;
        }

        @Override
        public String toString() {
            calls.incrementAndGet();
            return "Bearer " + SECRET;
        }
    }

    /** Each value that is not JSON-shaped, and a count of the times its own code ran (none for JDK values). */
    private static List<Object> notPlain(AtomicInteger calls) {
        Map<Object, Object> enumKey = new LinkedHashMap<>();
        enumKey.put(Labelled.ONE, 1L);
        Map<Object, Object> numberKey = new LinkedHashMap<>();
        numberKey.put(1, "v");
        return List.of(new Jwk("RSA", "N1", SECRET, calls), Labelled.ONE, new LinkedHashSet<>(List.of(SECRET)),
                new String[] {SECRET}, new Object[] {SECRET}, new int[] {1}, Optional.of(SECRET), Optional.empty(),
                new ArrayDeque<>(List.of(SECRET)), new StringBuilder(SECRET), Instant.EPOCH, Duration.ofSeconds(3), 'x',
                new AtomicLong(1), new CountingNumber(calls), new EchoDecimal(calls), enumKey, numberKey,
                new Object() {
                    @Override
                    public String toString() {
                        calls.incrementAndGet();
                        return SECRET;
                    }
                });
    }

    @Test
    void masksTheWholeTreeForAnyValueThatIsNotJsonShapedWithoutRunningItsCode() {
        AtomicInteger calls = new AtomicInteger();
        List<String> kept = new ArrayList<>();
        for (Object value : notPlain(calls)) {
            List<Object> inList = new ArrayList<>(List.of("ok"));
            inList.add(value);
            Map<String, Object> inMap = new LinkedHashMap<>();
            inMap.put("before", "ok");
            inMap.put("v", value);
            for (Object tree : List.of(value, inList, inMap, List.of(Map.of("deeper", inList)))) {
                Object out = Redactor.redactTree(tree);
                if (!Redactor.MASK.equals(out)) {
                    kept.add(value.getClass().getName() + " => " + out);
                }
            }
        }
        assertEquals(List.of(), kept);
        assertEquals(0, calls.get(), "caller code ran");
    }

    @Test
    void stepDetailsThatAreNotJsonShapedKeepOnlyTheMask() {
        AtomicInteger calls = new AtomicInteger();
        StepResult step = new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok",
                Map.of("connection", new Jwk("RSA", "N1", SECRET, calls)));
        assertEquals(Map.of("details", Redactor.MASK), step.details());
        assertEquals(0, calls.get());
        Map<String, Object> plain = new LinkedHashMap<>();
        plain.put("status", "passed");
        plain.put("counts", Map.of("FAIL", 1L));
        plain.put("connection", Map.of("authType", "NONE", "scopes", List.of()));
        assertEquals(plain, new StepResult("s", Instant.EPOCH, Duration.ZERO, true, "ok", plain).details());
    }

    /** A string node of a caller's own class, counting each time its code gives its text. */
    static final class CallerStringNode extends tools.jackson.databind.node.StringNode {
        private static final long serialVersionUID = 1L;
        private final transient AtomicInteger calls;

        CallerStringNode(AtomicInteger calls) {
            super("ok");
            this.calls = calls;
        }

        @Override
        public String stringValue() {
            calls.incrementAndGet();
            return "Bearer " + SECRET;
        }

        @Override
        public String asString() {
            calls.incrementAndGet();
            return "Bearer " + SECRET;
        }
    }

    @Test
    void masksATreeHoldingAValueOfACallerClassAnywhereWithoutRunningItsCode() {
        AtomicInteger calls = new AtomicInteger();
        tools.jackson.databind.node.ObjectNode standard = JsonNodeFactory.instance.objectNode();
        standard.put("note", "ok");
        standard.set("v", new CallerStringNode(calls));
        tools.jackson.databind.node.ArrayNode list = JsonNodeFactory.instance.arrayNode();
        list.add(new CallerStringNode(calls));
        for (Object tree : List.of(standard, list, Map.of("outer", standard), List.of(list))) {
            assertEquals(Redactor.MASK, Redactor.redactTree(tree), () -> String.valueOf(tree.getClass()));
        }
        assertEquals(0, calls.get(), "caller code ran");
    }

    // ---- what comes back ----

    @Test
    void returnsNewUnmodifiableDataThatKeepsOrderNumbersAndBooleans() {
        Map<String, Object> tree = new LinkedHashMap<>();
        BigDecimal decimal = new BigDecimal("1.50");
        Long count = 3_000_000_000L;
        tree.put("z", decimal);
        tree.put("a", count);
        tree.put("m", true);
        tree.put("n", null);
        tree.put("l", new ArrayList<>(List.of("Bearer " + SECRET)));
        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);
        assertEquals(List.of("z", "a", "m", "n", "l"), List.copyOf(out.keySet()));
        assertSame(decimal, out.get("z"));
        assertSame(count, out.get("a"));
        assertEquals(true, out.get("m"));
        assertTrue(out.containsKey("n"));
        assertEquals(List.of("Bearer " + Redactor.MASK), out.get("l"));
        assertThrows(UnsupportedOperationException.class, () -> ((Map<String, Object>) cast(out)).put("x", 1));
        assertThrows(UnsupportedOperationException.class, () -> ((List<Object>) cast(out.get("l"))).add("x"));
        assertEquals(null, Redactor.redactTree(null));
        assertEquals("Bearer " + Redactor.MASK, Redactor.redactTree("Bearer " + SECRET));
        assertSame(count, Redactor.redactTree(count));
    }

    @SuppressWarnings("unchecked")
    private static <T> T cast(Object value) {
        return (T) value;
    }

    @Test
    void readsEachCallerMapAndListOnce() {
        AtomicInteger entrySets = new AtomicInteger();
        AtomicInteger iterators = new AtomicInteger();
        Map<String, Object> counting = new AbstractMap<>() {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                entrySets.incrementAndGet();
                return Map.<String, Object>of("kty", "oct", "k", SECRET).entrySet();
            }
        };
        List<Object> list = new AbstractList<>() {
            @Override
            public Iterator<Object> iterator() {
                iterators.incrementAndGet();
                return List.<Object>of(counting).iterator();
            }

            @Override
            public Object get(int index) {
                return counting;
            }

            @Override
            public int size() {
                return 1;
            }
        };
        assertEquals(List.of(Map.of("kty", "oct", "k", Redactor.MASK)), Redactor.redactTree(list));
        assertEquals(1, entrySets.get());
        assertEquals(1, iterators.get());
    }

    @Test
    void masksAMapWhoseEntriesRepeatANameAsATextWithARepeatedName() {
        Map<String, Object> repeats = new AbstractMap<>() {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                return new AbstractSet<>() {
                    @Override
                    public Iterator<Map.Entry<String, Object>> iterator() {
                        return List.<Map.Entry<String, Object>>of(Map.entry("note", "a"), Map.entry("note", SECRET))
                                .iterator();
                    }

                    @Override
                    public int size() {
                        return 2;
                    }
                };
            }
        };
        assertEquals(Redactor.MASK, Redactor.redact("{\"note\":\"a\",\"note\":\"b\"}"));
        assertEquals(Redactor.MASK, Redactor.redactTree(repeats));
    }

    @Test
    void masksATreeNestedPastTheDepthBoundAsATextNestedSo() {
        Object deepest = "Bearer " + SECRET;
        Object tree = deepest;
        for (int depth = 1; depth <= JsonRedaction.MAX_DEPTH; depth++) {
            tree = List.of(tree);
        }
        assertNotEquals(Redactor.MASK, Redactor.redactTree(tree));
        assertNotEquals(Redactor.MASK, Redactor.redact(JSON.writeValueAsString(tree)));
        Object deeper = Map.of("k", tree);
        assertEquals(Redactor.MASK, Redactor.redactTree(deeper));
        assertEquals(Redactor.MASK, Redactor.redact(JSON.writeValueAsString(deeper)));
    }

    @Test
    void masksATreeWithAnUnclosedPrivateKeyBlockAsItsText() {
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("a", "-----BEGIN PRIVATE KEY-----\nFAKE");
        tree.put("b", "rest " + SECRET);
        assertEquals(Redactor.MASK, Redactor.redact(JSON.writeValueAsString(tree)));
        assertEquals(Redactor.MASK, Redactor.redactTree(tree));
    }

    // ---- the size bound ----

    @Test
    void masksAStringANameOrABigNumberPastTheSizeBound() {
        String big = "x".repeat((int) MAX_WEIGHT);
        assertEquals(Redactor.MASK, Redactor.redactTree(big));
        assertEquals(Redactor.MASK, Redactor.redactTree(Map.of(big, "v")));
        assertEquals(Redactor.MASK, Redactor.redactTree(List.of(BigInteger.ONE.shiftLeft(64 * 1024 * 1024))));
        // A string that only its escapes take past the bound.
        String controls = "\u0001".repeat((int) (MAX_WEIGHT / 4));
        assertEquals(Redactor.MASK, Redactor.redactTree(controls));
        assertNotEquals(Redactor.MASK, Redactor.redactTree("x".repeat((int) (MAX_WEIGHT / 4))));
    }

    @Test
    void masksATreeWhoseSharedValuesExpandPastTheBoundQuickly() {
        // 40 levels of a list holding the level below twice: 2^40 leaves read as a tree.
        Object level = "Bearer " + SECRET;
        for (int i = 0; i < 40; i++) {
            level = List.of(level, level);
        }
        Object tree = level;
        assertEquals(Redactor.MASK, assertTimeoutPreemptively(Duration.ofSeconds(5), () -> Redactor.redactTree(tree)));
        Object small = "Bearer " + SECRET;
        for (int i = 0; i < 10; i++) {
            small = List.of(small, small);
        }
        assertFalse(String.valueOf(Redactor.redactTree(small)).contains(SECRET));
    }

    enum Container { LIST, MAP, SET, ARRAY }

    enum Element { LARGE, ONE_CHARACTER }

    enum Identity { SHARED, DISTINCT }

    static Stream<Arguments> pastTheBound() {
        List<Arguments> cells = new ArrayList<>();
        for (Container container : Container.values()) {
            for (Element element : Element.values()) {
                for (Identity identity : Identity.values()) {
                    // An array holds its items already, so only a shared item keeps the test's own heap small.
                    if (!(container == Container.ARRAY && identity == Identity.DISTINCT)) {
                        cells.add(Arguments.of(container, element, identity));
                    }
                }
            }
        }
        return cells.stream();
    }

    /**
     * The most a tree may allocate on its thread: with large items it stops after a few, and with one-character items a
     * tree up to the bound allocates well under 128 bytes per unit of it.
     */
    private static long heap(Element element) {
        return element == Element.LARGE ? 64L * 1024 * 1024 : 128L * MAX_WEIGHT;
    }

    @ParameterizedTest(name = "{0} of {1} items, {2}")
    @MethodSource("pastTheBound")
    void masksAContainerPastTheBoundWithinAFixedHeapAndTime(Container container, Element element, Identity identity) {
        String text = element == Element.LARGE ? "x".repeat(1024 * 1024) : "x";
        // Far more items than the bound holds; a lazy container makes each only when it is read.
        long count = container == Container.ARRAY ? 64_000_000L : 100_000_000L;
        AtomicLong read = new AtomicLong();
        Supplier<Object> item = identity == Identity.SHARED ? () -> text : () -> new String(text);
        Object tree = switch (container) {
            case LIST -> new LazyList(count, read, item);
            case MAP -> new LazyMap(count, read, item);
            case SET -> new LazySet(count, read, item);
            case ARRAY -> {
                Object[] items = new Object[(int) count];
                java.util.Arrays.fill(items, text);
                yield items;
            }
        };
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long[] allocated = new long[1];
        Object out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            long before = threads.getCurrentThreadAllocatedBytes();
            Object masked = Redactor.redactTree(tree);
            allocated[0] = threads.getCurrentThreadAllocatedBytes() - before;
            return masked;
        });
        assertEquals(Redactor.MASK, out);
        assertTrue(allocated[0] < heap(element), () -> "allocated " + allocated[0] + " bytes");
        // Reading stops at the bound: no more items than the bound's worth (each weighs its text, quoted, and one),
        // plus the one that passes it. A set or an array is not read at all.
        long most = container == Container.LIST || container == Container.MAP
                ? MAX_WEIGHT / (text.length() + 3) + 1 : 0;
        assertTrue(read.get() <= most, () -> "read " + read.get() + " items, at most " + most);
    }

    /** {@code count} items, each made only when an iterator reaches it. */
    private static Iterator<Object> lazy(long count, AtomicLong read, Supplier<Object> item) {
        return new Iterator<>() {
            private long next;

            @Override
            public boolean hasNext() {
                return next < count;
            }

            @Override
            public Object next() {
                next++;
                read.incrementAndGet();
                return item.get();
            }
        };
    }

    static final class LazyList extends AbstractList<Object> {
        private final long count;
        private final AtomicLong read;
        private final Supplier<Object> item;

        LazyList(long count, AtomicLong read, Supplier<Object> item) {
            this.count = count;
            this.read = read;
            this.item = item;
        }

        @Override
        public Iterator<Object> iterator() {
            return lazy(count, read, item);
        }

        @Override
        public Object get(int index) {
            throw new UnsupportedOperationException("read through the iterator only");
        }

        @Override
        public int size() {
            return (int) Math.min(count, Integer.MAX_VALUE);
        }
    }

    static final class LazySet extends AbstractSet<Object> {
        private final long count;
        private final AtomicLong read;
        private final Supplier<Object> item;

        LazySet(long count, AtomicLong read, Supplier<Object> item) {
            this.count = count;
            this.read = read;
            this.item = item;
        }

        @Override
        public Iterator<Object> iterator() {
            return lazy(count, read, item);
        }

        @Override
        public int size() {
            return (int) Math.min(count, Integer.MAX_VALUE);
        }
    }

    /** {@code count} entries named 0, 1, 2 and on, each made only when an iterator reaches it. */
    static final class LazyMap extends AbstractMap<String, Object> {
        private final long count;
        private final AtomicLong read;
        private final Supplier<Object> item;

        LazyMap(long count, AtomicLong read, Supplier<Object> item) {
            this.count = count;
            this.read = read;
            this.item = item;
        }

        @Override
        public Set<Map.Entry<String, Object>> entrySet() {
            return new AbstractSet<>() {
                @Override
                public Iterator<Map.Entry<String, Object>> iterator() {
                    Iterator<Object> values = lazy(count, read, item);
                    return new Iterator<>() {
                        private long name;

                        @Override
                        public boolean hasNext() {
                            return values.hasNext();
                        }

                        @Override
                        public Map.Entry<String, Object> next() {
                            return new AbstractMap.SimpleImmutableEntry<>(Long.toString(name++), values.next());
                        }
                    };
                }

                @Override
                public int size() {
                    return (int) Math.min(count, Integer.MAX_VALUE);
                }
            };
        }
    }
}
