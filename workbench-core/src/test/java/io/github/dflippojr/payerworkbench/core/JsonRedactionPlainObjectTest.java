package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * The maps {@link Redactor#redactTree(Object)} returns for objects (#402): built without hashing a name
 * ({@code JsonRedaction.PlainObject}), and handed out exactly as before, an unmodifiable view of an ordered map: the same
 * class, member order, lookups, equality, text and errors as {@link Collections#unmodifiableMap} of a
 * {@link LinkedHashMap}. Every value here is synthetic.
 */
class JsonRedactionPlainObjectTest {

    /** What the tree path returned for an object before #402. */
    private static Map<String, Object> before(Map<String, Object> tree) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(tree));
    }

    private static Map<String, Object> tree() {
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("zeta", "one");
        tree.put("", 2L);
        tree.put("alpha", null);
        tree.put("AaBB", true);
        tree.put("BBAa", List.of("x"));
        tree.put("nested", new LinkedHashMap<>(Map.of("inner", "v")));
        return tree;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> redacted(Object tree) {
        return (Map<String, Object>) Redactor.redactTree(tree);
    }

    @Test
    void keepsTheClassOrderAndLookupsOfAnUnmodifiableOrderedMap() {
        Map<String, Object> tree = tree();
        Map<String, Object> out = redacted(tree);
        Map<String, Object> was = before(tree);
        assertSame(was.getClass(), out.getClass());
        assertEquals(List.copyOf(tree.keySet()), List.copyOf(out.keySet()));
        assertEquals(new ArrayList<>(was.values()).subList(0, 5), new ArrayList<>(out.values()).subList(0, 5));
        assertSame(was.getClass(), out.get("nested").getClass());
        assertEquals(was, out);
        assertEquals(out, was);
        assertEquals(was.hashCode(), out.hashCode());
        assertEquals(was.toString(), out.toString());
        assertEquals(was.entrySet(), out.entrySet());
        assertEquals(6, out.size());
        assertFalse(out.isEmpty());
        for (String name : tree.keySet()) {
            assertTrue(out.containsKey(name), name);
            assertTrue(out.containsKey(new String(name.toCharArray())), name);
            assertEquals(tree.get(name) == null, out.get(name) == null, name);
        }
        assertTrue(out.containsKey("alpha"));
        assertNull(out.get("alpha"));
        assertEquals("fallback", out.getOrDefault("missing", "fallback"));
        assertNull(out.getOrDefault("alpha", "fallback"));
        for (Object miss : new Object[] {"missing", "Aa", "zet", "zetaa", null, 1, 'z', List.of("zeta")}) {
            assertFalse(out.containsKey(miss), String.valueOf(miss));
            assertNull(out.get(miss), String.valueOf(miss));
        }
        List<String> walked = new ArrayList<>();
        out.forEach((name, value) -> walked.add(name));
        assertEquals(List.copyOf(tree.keySet()), walked);
    }

    @Test
    void anEmptyObjectIsAnEmptyUnmodifiableOrderedMap() {
        Map<String, Object> out = redacted(new LinkedHashMap<>());
        Map<String, Object> was = before(new LinkedHashMap<>());
        assertSame(was.getClass(), out.getClass());
        assertTrue(out.isEmpty());
        assertEquals(was, out);
        assertEquals(Map.of(), out);
        assertEquals("{}", out.toString());
        assertFalse(out.containsKey(""));
        assertFalse(out.entrySet().iterator().hasNext());
        assertThrows(NoSuchElementException.class, () -> out.entrySet().iterator().next());
    }

    /** Every change throws, even one that would change nothing, as on the map returned before. */
    @Test
    void refusesEveryChangeEvenOneThatChangesNothing() {
        Map<String, Object> out = redacted(tree());
        Map<String, Object> empty = redacted(new LinkedHashMap<>());
        List<Consumer<Map<String, Object>>> changes = List.of(
                m -> m.put("zeta", "two"),
                m -> m.put("new", 1),
                m -> m.remove("zeta"),
                m -> m.remove("missing"),
                m -> m.clear(),
                m -> m.putAll(Map.of()),
                m -> m.putIfAbsent("zeta", "two"),
                m -> m.computeIfAbsent("zeta", k -> "two"),
                m -> m.computeIfPresent("missing", (k, v) -> v),
                m -> m.replaceAll((k, v) -> v),
                m -> m.keySet().remove("missing"),
                m -> m.values().clear(),
                m -> m.entrySet().clear(),
                m -> m.entrySet().iterator().remove(),
                m -> m.entrySet().iterator().next().setValue("two"));
        for (Map<String, Object> map : List.of(out, before(tree()))) {
            for (Consumer<Map<String, Object>> change : changes) {
                assertThrows(UnsupportedOperationException.class, () -> change.accept(map));
            }
        }
        for (Map<String, Object> map : List.of(empty, before(new LinkedHashMap<>()))) {
            assertThrows(UnsupportedOperationException.class, map::clear);
            assertThrows(UnsupportedOperationException.class, () -> map.remove("missing"));
            assertThrows(UnsupportedOperationException.class, () -> map.putAll(Map.of()));
        }
        assertEquals(tree().keySet(), out.keySet());
    }

    @Test
    void walksItsMembersInOrderAndThenStops() {
        Map<String, Object> out = redacted(tree());
        Iterator<Map.Entry<String, Object>> members = out.entrySet().iterator();
        for (String name : tree().keySet()) {
            assertTrue(members.hasNext());
            assertEquals(name, members.next().getKey());
        }
        assertFalse(members.hasNext());
        assertThrows(NoSuchElementException.class, members::next);
    }

    /** It survives Java serialization as the map returned before did, as an equal map in the same order. */
    @Test
    void serializesAsAnEqualMapInTheSameOrder() throws IOException, ClassNotFoundException {
        Map<String, Object> out = redacted(tree());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream stream = new ObjectOutputStream(bytes)) {
            stream.writeObject(out);
        }
        Object back;
        try (ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            back = stream.readObject();
        }
        assertEquals(out, back);
        assertEquals(List.copyOf(out.keySet()), List.copyOf(((Map<?, ?>) back).keySet()));
        assertTrue(((Map<?, ?>) back).containsKey("AaBB"));
    }

    /**
     * A name given twice is unreadable, as two names that redact to one are in {@code JsonRedaction.redact}, which
     * comes first on the path, so the map never pairs a value with the wrong name.
     */
    @Test
    void refusesANameGivenTwice() {
        JsonRedaction.PlainObject object = new JsonRedaction.PlainObject(2);
        object.append("name", 1);
        assertThrows(JsonRedaction.Unreadable.class, () -> object.append(new String("name".toCharArray()), 2));
        assertEquals(Map.of("name", 1), object);
    }
}
