package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * {@link Redactor#redactTree(Object)}'s snapshot (#377 stage 1) over a grid of caller value type, the role the value
 * plays, how it is shared and its size. In every cell the redacted tree holds only plain data and no secret byte, each
 * caller method runs at most once, and a value past {@link PlainData#MAX_WEIGHT} masks the whole tree. Every secret here
 * is synthetic.
 */
class RedactorSnapshotGridTest {

    private static final String SECRET = "FAKE-SECRET-377-GRID-NOT-REAL";

    /** Enough characters that any value holding them passes the size bound. */
    private static final String PAD = "x".repeat((int) PlainData.MAX_WEIGHT);

    enum Type { STRING, TO_STRING, NUMBER, ENUM, RECORD, MAP, LIST, SET, ARRAY, OPTIONAL }

    enum Role { ROOT, MAP_VALUE, MAP_KEY, ELEMENT, COMPONENT, OPTIONAL_CONTENT }

    enum Sharing { ONCE, TWICE_IN_ITS_ROLE, ALSO_AS_KEY_AND_VALUE }

    enum Size { SMALL, PAST_THE_BOUND }

    /** A caller object, and how many times its own code ran ({@code null} when it has none to count). */
    record Made(Object value, AtomicInteger calls) {
    }

    record Holder(Object held) {
    }

    record GridJwk(String kty, String n, String d, AtomicInteger reads) {
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

    static Stream<Arguments> grid() {
        List<Arguments> cells = new ArrayList<>();
        for (Type type : Type.values()) {
            for (Role role : Role.values()) {
                for (Sharing sharing : Sharing.values()) {
                    for (Size size : Size.values()) {
                        // An enum is copied as its name, which cannot be made larger than the bound.
                        if (!(type == Type.ENUM && size == Size.PAST_THE_BOUND)) {
                            cells.add(Arguments.of(type, role, sharing, size));
                        }
                    }
                }
            }
        }
        return cells.stream();
    }

    @ParameterizedTest(name = "{0} as {1}, {2}, {3}")
    @MethodSource("grid")
    void copiesOnceRedactsAndBoundsEveryCell(Type type, Role role, Sharing sharing, Size size) {
        Made made = make(type, size);
        Object x = made.value();
        Object tree = switch (sharing) {
            case ONCE -> place(role, x);
            case TWICE_IN_ITS_ROLE -> List.of(place(role, x), place(role, x));
            case ALSO_AS_KEY_AND_VALUE -> List.of(place(role, x), identityMap(x, x));
        };

        Object out = Redactor.redactTree(tree);

        if (size == Size.PAST_THE_BOUND) {
            assertEquals(Redactor.MASK, out);
        } else {
            assertNotEquals(Redactor.MASK, out);
            assertPlain(out);
            assertFalse(String.valueOf(out).contains(SECRET), () -> String.valueOf(out));
        }
        if (made.calls() != null) {
            int calls = made.calls().get();
            assertTrue(size == Size.PAST_THE_BOUND ? calls <= 1 : calls == 1, "caller code ran " + calls + " times");
        }
    }

    enum Container { LIST, SET, MAP, ARRAY }

    enum Element { LARGE, ONE_CHARACTER }

    enum Identity { SHARED, DISTINCT }

    /** The most a copy may allocate on its thread, far above any copy within the bound and below copying past it. */
    private static final long HEAP = 512L * 1024 * 1024;

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

    @ParameterizedTest(name = "{0} of {1} items, {2}")
    @MethodSource("pastTheBound")
    void masksAContainerPastTheBoundWithinAFixedHeapAndTime(Container container, Element element, Identity identity) {
        String text = element == Element.LARGE ? "x".repeat(1024 * 1024) : "x";
        long weight = 1L + text.length();
        // Far more items than the bound holds; a lazy container makes each only when it is read.
        long count = container == Container.ARRAY ? 32_000_000L : container == Container.MAP ? 20_000_000L
                : 100_000_000L;
        AtomicLong read = new AtomicLong();
        Object tree = switch (container) {
            case LIST -> new LazyList(count, read, item(text, identity));
            case SET -> new LazySet(count, read, item(text, identity));
            case MAP -> new LazyMap(count, read, item(text, identity));
            case ARRAY -> {
                Object[] items = new Object[(int) count];
                java.util.Arrays.fill(items, text);
                yield items;
            }
        };
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long[] allocated = new long[1];
        Object out = assertTimeoutPreemptively(java.time.Duration.ofSeconds(20), () -> {
            long before = threads.getCurrentThreadAllocatedBytes();
            Object masked = Redactor.redactTree(tree);
            allocated[0] = threads.getCurrentThreadAllocatedBytes() - before;
            return masked;
        });
        assertEquals(Redactor.MASK, out);
        assertTrue(allocated[0] < HEAP, () -> "allocated " + allocated[0] + " bytes");
        if (container != Container.ARRAY) {
            // The copy stops reading at the bound: no more items than the bound's worth, plus the one that passes it.
            long most = PlainData.MAX_WEIGHT / (weight + (container == Container.MAP ? 1 : 0)) + 1;
            assertTrue(read.get() <= most, () -> "read " + read.get() + " items, at most " + most);
        }
    }

    /** Each item: the same text, or a new caller object whose text it is. */
    private static java.util.function.Supplier<Object> item(String text, Identity identity) {
        return identity == Identity.SHARED ? () -> text : () -> new Object() {
            @Override
            public String toString() {
                return text;
            }
        };
    }

    /** {@code count} items, each made only when an iterator reaches it. */
    private static Iterator<Object> lazy(long count, AtomicLong read, java.util.function.Supplier<Object> item) {
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

    static final class LazyList extends java.util.AbstractCollection<Object> {
        private final long count;
        private final AtomicLong read;
        private final java.util.function.Supplier<Object> item;

        LazyList(long count, AtomicLong read, java.util.function.Supplier<Object> item) {
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

    static final class LazySet extends AbstractSet<Object> {
        private final long count;
        private final AtomicLong read;
        private final java.util.function.Supplier<Object> item;

        LazySet(long count, AtomicLong read, java.util.function.Supplier<Object> item) {
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

    /** {@code count} entries keyed 0, 1, 2 and on, each made only when an iterator reaches it. */
    static final class LazyMap extends AbstractMap<Object, Object> {
        private final long count;
        private final AtomicLong read;
        private final java.util.function.Supplier<Object> item;

        LazyMap(long count, AtomicLong read, java.util.function.Supplier<Object> item) {
            this.count = count;
            this.read = read;
            this.item = item;
        }

        @Override
        public Set<Map.Entry<Object, Object>> entrySet() {
            return new AbstractSet<>() {
                @Override
                public Iterator<Map.Entry<Object, Object>> iterator() {
                    Iterator<Object> values = lazy(count, read, item);
                    return new Iterator<>() {
                        private long key;

                        @Override
                        public boolean hasNext() {
                            return values.hasNext();
                        }

                        @Override
                        public Map.Entry<Object, Object> next() {
                            return new AbstractMap.SimpleImmutableEntry<>(key++, values.next());
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

    /** A caller object of {@code type} that carries the secret; past the bound, it also carries {@link #PAD}. */
    private static Made make(Type type, Size size) {
        String text = "Bearer " + SECRET + (size == Size.PAST_THE_BOUND ? " " + PAD : "");
        AtomicInteger calls = new AtomicInteger();
        return switch (type) {
            case STRING -> new Made(text, null);
            case TO_STRING -> new Made(new Object() {
                @Override
                public String toString() {
                    calls.incrementAndGet();
                    return text;
                }
            }, calls);
            case NUMBER -> new Made(new CountingNumber(text, calls), calls);
            case ENUM -> new Made(Labelled.ONE, null);
            case RECORD -> new Made(new GridJwk("RSA", size == Size.PAST_THE_BOUND ? PAD : "N1", SECRET, calls), calls);
            case MAP -> new Made(new AbstractMap<String, Object>() {
                @Override
                public Set<Map.Entry<String, Object>> entrySet() {
                    calls.incrementAndGet();
                    Map<String, Object> entries = new LinkedHashMap<>();
                    entries.put("kty", "oct");
                    entries.put("k", SECRET);
                    entries.put("note", text);
                    return entries.entrySet();
                }
            }, calls);
            case LIST -> new Made(new AbstractList<Object>() {
                @Override
                public Iterator<Object> iterator() {
                    calls.incrementAndGet();
                    return List.<Object>of(text).iterator();
                }

                @Override
                public Object get(int index) {
                    return text;
                }

                @Override
                public int size() {
                    return 1;
                }
            }, calls);
            case SET -> new Made(new AbstractSet<Object>() {
                @Override
                public Iterator<Object> iterator() {
                    calls.incrementAndGet();
                    return List.<Object>of(text).iterator();
                }

                @Override
                public int size() {
                    return 1;
                }
            }, calls);
            case ARRAY -> new Made(new Object[] {text}, null);
            case OPTIONAL -> new Made(Optional.of(text), null);
        };
    }

    /** {@code x} in {@code role}; a key goes in an identity map, so placing it runs none of its code. */
    private static Object place(Role role, Object x) {
        return switch (role) {
            case ROOT -> x;
            case MAP_VALUE -> Map.of("v", x);
            case MAP_KEY -> identityMap(x, "v");
            case ELEMENT -> List.of(x);
            case COMPONENT -> new Holder(x);
            case OPTIONAL_CONTENT -> Optional.of(x);
        };
    }

    private static Map<Object, Object> identityMap(Object key, Object value) {
        Map<Object, Object> map = new IdentityHashMap<>();
        map.put(key, value);
        return map;
    }

    /** The redacted tree holds only strings, plain scalars, and maps keyed by text, lists, sets and optionals of them. */
    private static void assertPlain(Object value) {
        if (value == null || value instanceof String || PlainData.SCALARS.contains(value.getClass())) {
            return;
        }
        if (value instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                assertTrue(k instanceof String, () -> "a key that is not text: " + k.getClass());
                assertPlain(v);
            });
        } else if (value instanceof List<?> || value instanceof Set<?>) {
            ((Iterable<?>) value).forEach(RedactorSnapshotGridTest::assertPlain);
        } else if (value instanceof Optional<?> optional) {
            optional.ifPresent(RedactorSnapshotGridTest::assertPlain);
        } else {
            throw new AssertionError("a value that is not plain data: " + value.getClass());
        }
        assertTrue(value.getClass().getName().startsWith("java.util."), () -> "not a JDK class: " + value.getClass());
    }

    /** A number whose text a caller controls, counting each time it is read. */
    static final class CountingNumber extends Number {
        private static final long serialVersionUID = 1L;
        private final transient String text;
        private final transient AtomicInteger calls;

        CountingNumber(String text, AtomicInteger calls) {
            this.text = text;
            this.calls = calls;
        }

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
            calls.incrementAndGet();
            return text;
        }
    }
}
