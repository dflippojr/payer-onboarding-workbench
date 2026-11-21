package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.SwitchExpressionTree;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Types;
import org.junit.jupiter.api.Test;

/**
 * The member-name checks of {@link JsonRedaction} (#398): the check for a name that repeats in one object, in the text
 * reader and the tree reader, and the check for two names that redact to one. Each goes through
 * {@code JsonRedaction.Names}, an index whose cost per name is linear in the name's length and that takes no hash of a
 * name: a hashed index costs a log factor more on names chosen to collide.
 */
class JsonRedactionNamesTest {

    private static final String JSON_REDACTION = JsonRedaction.class.getName();
    private static final String NAMES = JSON_REDACTION + ".Names";
    private static final String PLAIN_OBJECT = JSON_REDACTION + ".PlainObject";

    /**
     * The name index takes no hash, and the name checks go through it. The log factor a hashed index costs on names
     * chosen to collide is small next to the linear work each name gets on this path (decoding, the key-block check,
     * redaction), so no timing can tell it from noise; the absence of hashing is checked in the code instead, as
     * {@code RedactorTest.indexesFooterLabelsWithoutHashing} checks the armor-label index. {@link #namesIndexViolations}
     * reads the code as the compiler does.
     */
    @Test
    void indexesMemberNamesWithoutHashing() throws IOException {
        List<String> found = namesIndexViolations(CompiledSource.read("JsonRedaction"));
        assertTrue(found.isEmpty(), () -> String.join("\n", found));
    }

    @Test
    void hashFreeGuardIgnoresCommentsAndLiterals() throws IOException {
        String named = "            // A HashSet, HashMap or Objects.hash here would hash the names.\n"
                + "            String hashing = \"new java.util.HashSet<String>().add(name.hashCode() + name)\";\n";
        String variant = CompiledSource.replaceOnce(CompiledSource.read("JsonRedaction"),
                "        boolean add(String name) {\n", "        boolean add(String name) {\n" + named);
        List<String> found = namesIndexViolations(variant);
        assertTrue(found.isEmpty(), () -> String.join("\n", found));
    }

    @Test
    void hashFreeGuardFailsWhenANameCheckStopsGoingThroughNames() throws IOException {
        String source = CompiledSource.read("JsonRedaction");
        // The text reader checks its names in a hash set, as before #398.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            Names names = object ? new Names() : null;\n",
                        "            java.util.Set<String> names = new java.util.HashSet<>();\n"),
                "in Reader.readContainer: constructs java.util.HashSet",
                "Reader.readContainer does not call JsonRedaction.Names.add");
        // The tree reader checks its names in a sorted set: no hash, but not linear in the names either.
        assertViolations(CompiledSource.replaceOnce(CompiledSource.replaceOnce(source,
                        "                Names names = new Names();\n",
                        "                java.util.Set<String> names = new java.util.TreeSet<>();\n"),
                        "        private String name(String name, Names names) {",
                        "        private String name(String name, java.util.Set<String> names) {"),
                "in TreeReader.read: constructs java.util.TreeSet", "TreeReader.name does not call JsonRedaction.Names.add");
        // The redacted names are collected by a factory instead.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            if (!names.add(redactedName)) {\n",
                        "            if (!names.add(redactedName) || java.util.Set.of(redactedName).isEmpty()) {\n"),
                "in JsonRedaction.redact(Node): makes a java.util.Set<java.lang.String>");
        // A name check hands its names to a helper of the class that indexes them in a hash set.
        assertViolations(CompiledSource.replaceOnce(CompiledSource.replaceOnce(source,
                        "            if (!names.add(redactedName)) {\n",
                        "            if (!names.add(redactedName) || !seenBefore(seen, redactedName)) {\n"),
                        "    /** {@code text} as Jackson's encoder spells a JSON string, quotes included. */\n",
                        "    private static final java.util.Set<String> seen = new java.util.HashSet<>();\n\n"
                                + "    private static boolean seenBefore(java.util.Set<String> seen, String name) {\n"
                                + "        java.util.Set<String> copy = new java.util.HashSet<>(seen);\n"
                                + "        return copy.add(name);\n    }\n\n"
                                + "    /** {@code text} as Jackson's encoder spells a JSON string, quotes included. */\n"),
                "in JsonRedaction.seenBefore: constructs java.util.HashSet",
                "in JsonRedaction.seenBefore: indexes with java.util.Set<java.lang.String>.add");
        // The index hands each name to a helper outside it that hashes it.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            int length = name.length();\n",
                        "            int length = name.length() + java.util.Objects.hash(name) * 0;\n"),
                "in Names: hashes with java.util.Objects.hash");
        // The index takes a hash code itself, or keeps its names in a hash map.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            int length = name.length();\n",
                        "            int length = name.length() + name.hashCode() * 0;\n"),
                "in Names: hashes with java.lang.String.hashCode");
        assertViolations(CompiledSource.replaceOnce(source,
                        "            int length = name.length();\n",
                        "            int length = new java.util.HashMap<String, Integer>().getOrDefault(name, name.length());\n"),
                "in Names: calls java.util.HashMap.<init>", "in Names: calls java.util.HashMap.getOrDefault");
        // A switch on a name hashes it with no call in the source.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            int length = name.length();\n",
                        "            int length = switch (name) { case \"kty\" -> 3; default -> name.length(); };\n"),
                "in Names: switches on a String");
        // The tree path builds the maps it returns in a hashed map again, as before #402.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            PlainObject out = new PlainObject(container.members().size());\n"
                                + "            container.members().forEach(member -> out.append(member.name(), plain(member.value())));\n",
                        "            java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();\n"
                                + "            container.members().forEach(member -> out.put(member.name(), plain(member.value())));\n"),
                "in JsonRedaction.plain: constructs java.util.LinkedHashMap",
                "in JsonRedaction.plain: indexes with java.util.Map<java.lang.String,java.lang.Object>.put");
        // Or hands the hash-free map to a factory that copies it into a hashed one.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            return Collections.unmodifiableMap(out);\n",
                        "            return java.util.Map.copyOf(out);\n"),
                "in JsonRedaction.plain: makes a java.util.Map<java.lang.String,java.lang.Object> with java.util.Map.copyOf");
        // The returned map hashes a name to look it up, or keeps a hashed map of its names beside the index.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            return key instanceof String name ? names.indexOf(name) : -1;\n",
                        "            return key instanceof String name ? names.indexOf(name) + name.hashCode() * 0 : -1;\n"),
                "in PlainObject: hashes with java.lang.String.hashCode");
        assertViolations(CompiledSource.replaceOnce(source,
                        "            return key instanceof String name ? names.indexOf(name) : -1;\n",
                        "            return key instanceof String name ? new java.util.HashMap<String, Integer>()"
                                + ".getOrDefault(name, names.indexOf(name)) : -1;\n"),
                "in PlainObject: calls java.util.HashMap.<init>", "in PlainObject: calls java.util.HashMap.getOrDefault");
        // A name check that drops the index altogether.
        assertViolations(CompiledSource.replaceOnce(source,
                        "            if (!names.add(redactedName)) {\n",
                        "            if (redactedName == null) {\n"),
                "JsonRedaction.redact(Node) does not call JsonRedaction.Names.add");
    }

    /** Asserts that {@link #namesIndexViolations} reports each of {@code expected} (as a substring) for {@code source}. */
    private static void assertViolations(String source, String... expected) {
        List<String> found = namesIndexViolations(source);
        for (String violation : expected) {
            assertTrue(found.stream().anyMatch(f -> f.contains(violation)),
                    () -> "missing \"" + violation + "\" in:\n" + String.join("\n", found));
        }
    }

    /** Names that the index must tell apart exactly: the empty name, prefixes, the extreme and the lone surrogate chars. */
    private static final List<String> EDGE_NAMES = List.of("", "\0", "\0\0", "a", "a\0", "ab", "abc", "abd", "b",
            "\uFFFF", "\uFFFF\uFFFF", "\uD800", "\uDC00", "\uD800\uDC00", "\uDBFF\uDFFF", "\u0001", "\u8000",
            "\u7FFF", "Aa", "BB", "AaAa", "AaBB", "BBAa", "BBBB");

    @Test
    void tellsEdgeNamesApart() {
        JsonRedaction.Names names = new JsonRedaction.Names();
        for (String name : EDGE_NAMES) {
            assertTrue(names.add(name), () -> "new: " + escaped(name));
        }
        for (String name : EDGE_NAMES) {
            assertFalse(names.add(name), () -> "again: " + escaped(name));
            assertFalse(names.add(new String(name.toCharArray())), () -> "equal copy: " + escaped(name));
        }
        // In reverse order the same: no name is taken for another whatever came first.
        JsonRedaction.Names reversed = new JsonRedaction.Names();
        for (int i = EDGE_NAMES.size() - 1; i >= 0; i--) {
            assertTrue(reversed.add(EDGE_NAMES.get(i)));
        }
        for (String name : EDGE_NAMES) {
            assertFalse(reversed.add(name));
        }
    }

    /**
     * The index agrees with a hash set on seeded sequences of names over a small alphabet that holds the empty name,
     * prefixes, names that differ only in their last character, and characters at both ends of the char range, so
     * names repeat, share long beginnings and end inside one another.
     */
    @Test
    void agreesWithAHashSet() {
        char[] alphabet = {'\0', '\u0001', 'a', 'b', 'A', 'B', '\u7FFF', '\u8000', '\uD800', '\uDC00', '\uFFFE', '\uFFFF'};
        Random random = new Random(398);
        for (int round = 0; round < 2_000; round++) {
            JsonRedaction.Names names = new JsonRedaction.Names();
            Set<String> oracle = new HashSet<>();
            int letters = 1 + random.nextInt(alphabet.length);
            int count = random.nextInt(60);
            int longest = random.nextInt(8);
            String shared = random.nextBoolean() ? "" : "p".repeat(random.nextInt(20));
            for (int i = 0; i < count; i++) {
                StringBuilder name = new StringBuilder(shared);
                for (int length = random.nextInt(longest + 1); length > 0; length--) {
                    name.append(alphabet[random.nextInt(letters)]);
                }
                String added = name.toString();
                int at = round;
                assertEquals(oracle.add(added), names.add(added), () -> "round " + at + ": " + escaped(added));
            }
        }
    }

    /**
     * The index finds each name at the place it was first added, and finds no name it was not given, as a list of the
     * distinct names does, on the edge names in both orders and on seeded sequences like those of
     * {@link #agreesWithAHashSet}; {@code JsonRedaction.PlainObject} looks its names up this way (#402).
     */
    @Test
    void findsNamesWhereAListOfThemDoes() {
        JsonRedaction.Names empty = new JsonRedaction.Names();
        assertEquals(-1, empty.indexOf(""));
        assertEquals(0, empty.size());
        for (List<String> order : List.of(EDGE_NAMES, EDGE_NAMES.reversed())) {
            JsonRedaction.Names names = new JsonRedaction.Names();
            List<String> oracle = new ArrayList<>();
            for (String name : order) {
                assertEquals(-1, names.indexOf(name), () -> "before: " + escaped(name));
                names.add(name);
                oracle.add(name);
                for (String probe : EDGE_NAMES) {
                    assertEquals(oracle.indexOf(probe), names.indexOf(new String(probe.toCharArray())),
                            () -> "probe " + escaped(probe) + " after " + escaped(name));
                }
            }
            for (int i = 0; i < oracle.size(); i++) {
                assertEquals(oracle.get(i), names.name(i));
            }
        }
        char[] alphabet = {'\0', '\u0001', 'a', 'b', 'A', 'B', '\u7FFF', '\u8000', '\uD800', '\uDC00', '\uFFFE', '\uFFFF'};
        Random random = new Random(402);
        for (int round = 0; round < 2_000; round++) {
            JsonRedaction.Names names = new JsonRedaction.Names();
            List<String> oracle = new ArrayList<>();
            int letters = 1 + random.nextInt(alphabet.length);
            int count = random.nextInt(60);
            int longest = random.nextInt(8);
            String shared = random.nextBoolean() ? "" : "p".repeat(random.nextInt(20));
            for (int i = 0; i < 2 * count; i++) {
                StringBuilder name = new StringBuilder(shared);
                for (int length = random.nextInt(longest + 1); length > 0; length--) {
                    name.append(alphabet[random.nextInt(letters)]);
                }
                String next = name.toString();
                int at = round;
                // Every other name is only looked up, so misses are as common as hits.
                if (i % 2 == 0 && !oracle.contains(next)) {
                    oracle.add(next);
                    names.add(next);
                }
                assertEquals(oracle.indexOf(next), names.indexOf(next), () -> "round " + at + ": " + escaped(next));
                assertEquals(oracle.size(), names.size());
            }
        }
    }

    /**
     * The index's cost per name does not grow with the other names: each shape of {@link #indexShapes} holds names
     * chosen against it (names chosen to collide in a hash, names that branch at one position over many distinct
     * characters, and names each a prefix of the next past a long shared beginning), and adding all of them must take
     * time that grows about linearly with their total length, by the growth of CPU time over eight times the length.
     * The timeout only ends a hang.
     */
    @Test
    void indexesNamesInLinearTime() {
        List<List<String>> small = indexShapes(1);
        List<List<String>> large = indexShapes(8);
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2),
                () -> RedactorTest.growthBeyondLinear(small, large, JsonRedactionNamesTest::totalLength,
                        JsonRedactionNamesTest::addAll));
        assertTrue(tooSlow.isEmpty(), () -> "time grows faster than linearly: " + tooSlow);
    }

    /**
     * The name checks on the structural path take time about linear in the text for names chosen against them: each
     * shape of {@link #indexShapes}, at a smaller size, is one object of those names, redacted as a text and as a
     * tree, and must be kept as it is (so the checks run on every name and nothing is masked whole) in time that grows
     * about linearly with its length. The per-name work of this path (decoding, the key-block check, redaction) is
     * linear and large, so this guards a hang or a quadratic cost, not the log factor of a hashed index, which
     * {@link #indexesMemberNamesWithoutHashing} guards. The timeout only ends a hang.
     */
    @Test
    void checksMemberNamesInLinearTime() {
        List<List<String>> smallNames = pathShapes(1);
        List<List<String>> largeNames = pathShapes(8);
        List<String> smallTexts = smallNames.stream().map(JsonRedactionNamesTest::object).toList();
        List<String> largeTexts = largeNames.stream().map(JsonRedactionNamesTest::object).toList();
        List<Map<String, Object>> smallTrees = smallNames.stream().map(JsonRedactionNamesTest::tree).toList();
        List<Map<String, Object>> largeTrees = largeNames.stream().map(JsonRedactionNamesTest::tree).toList();
        for (int shape = 0; shape < smallTexts.size(); shape++) {
            for (String text : List.of(smallTexts.get(shape), largeTexts.get(shape))) {
                assertEquals(text, Redactor.redact(text), () -> "shape kept as text: " + text.substring(0, 80));
            }
            for (Map<String, Object> tree : List.of(smallTrees.get(shape), largeTrees.get(shape))) {
                assertEquals(tree, Redactor.redactTree(tree), "shape kept as tree");
            }
        }
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2), () -> {
            List<String> slow = new ArrayList<>();
            RedactorTest.growthBeyondLinear(smallTexts, largeTexts, String::length, Redactor::redact)
                    .forEach(s -> slow.add("text " + s));
            RedactorTest.growthBeyondLinear(smallTrees, largeTrees, t -> object(List.copyOf(t.keySet())).length(),
                    Redactor::redactTree).forEach(s -> slow.add("tree " + s));
            return slow;
        });
        assertTrue(tooSlow.isEmpty(), () -> "time grows faster than linearly: " + tooSlow);
    }

    /** The name shapes of {@link #indexShapes} at the size {@link #checksMemberNamesInLinearTime} redacts. */
    private static List<List<String>> pathShapes(int scale) {
        return List.of(collidingNames(7 + Integer.numberOfTrailingZeros(scale), 128), branchingNames(256 * scale, 64),
                prefixChainNames(32 * scale, 64));
    }

    /** One JSON object of {@code names}, each with the value {@code 0}. */
    private static String object(List<String> names) {
        StringBuilder out = new StringBuilder("{");
        for (String name : names) {
            out.append(out.length() > 1 ? "," : "").append('"').append(name).append("\":0");
        }
        return out.append('}').toString();
    }

    /** One map of {@code names} in order, each with the value {@code 0}. */
    private static Map<String, Object> tree(List<String> names) {
        Map<String, Object> tree = new LinkedHashMap<>();
        names.forEach(name -> tree.put(name, 0));
        return tree;
    }

    /** Names that {@link #indexesNamesInLinearTime} adds, about {@code scale} times a base size per shape. */
    static List<List<String>> indexShapes(int scale) {
        return List.of(collidingNames(10 + Integer.numberOfTrailingZeros(scale), 512), branchingNames(4_096 * scale, 64),
                fanOutNames(16 * scale, 2_048), prefixChainNames(256 * scale, 64));
    }

    /** {@code 2^pairs} distinct names chosen to collide in a hash. */
    static List<String> collidingNames(int pairs, int shared) {
        String start = "n".repeat(shared);
        List<String> names = new ArrayList<>(1 << pairs);
        for (int i = 0; i < 1 << pairs; i++) {
            StringBuilder name = new StringBuilder(start);
            for (int j = 0; j < pairs; j++) {
                name.append(((i >> j) & 1) == 0 ? "Aa" : "BB");
            }
            names.add(name.toString());
        }
        return names;
    }

    /** {@code count} names, a shared beginning and then one distinct character each, so they branch at one position. */
    static List<String> branchingNames(int count, int shared) {
        String start = "n".repeat(shared);
        List<String> names = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            names.add(start + (char) (0x4E00 + i));
        }
        return names;
    }

    /** {@code groups} groups of distinct single-character branches, each after a shared beginning of its own. */
    static List<String> fanOutNames(int groups, int perGroup) {
        List<String> names = new ArrayList<>(groups * perGroup);
        for (int g = 0; g < groups; g++) {
            String start = "g" + g + "-";
            for (int i = 0; i < perGroup; i++) {
                names.add(start + (char) (0x4E00 + i));
            }
        }
        return names;
    }

    /** {@code count} names past a shared beginning, each one character longer than the one before. */
    static List<String> prefixChainNames(int count, int shared) {
        StringBuilder name = new StringBuilder("n".repeat(shared));
        List<String> names = new ArrayList<>(count);
        names.add(name.toString());
        for (int i = 1; i < count; i++) {
            names.add(name.append('x').toString());
        }
        // Longest first, so each shorter name is added after names that run past its end.
        java.util.Collections.reverse(names);
        return names;
    }

    private static int totalLength(List<String> names) {
        int total = 0;
        for (String name : names) {
            total += name.length() + 1;
        }
        return total;
    }

    private static void addAll(List<String> names) {
        JsonRedaction.Names index = new JsonRedaction.Names();
        for (String name : names) {
            if (!index.add(name)) {
                throw new AssertionError("a distinct name was taken for another");
            }
        }
    }

    private static String escaped(String name) {
        StringBuilder out = new StringBuilder();
        name.chars().forEach(c -> out.append(String.format(java.util.Locale.ROOT, "\\u%04X", c)));
        return out.toString();
    }

    /** The classes whose methods {@code JsonRedaction.Names} may call: none of them hashes what it is given. */
    private static final Set<String> NAMES_CALLEES = Set.of("java.lang.Object", "java.lang.String", "java.lang.Integer",
            "java.lang.Math", "java.util.Arrays");
    /**
     * The classes whose methods {@code JsonRedaction.PlainObject}, the map the tree path returns for an object (#402),
     * may call besides those: its names go into {@code Names}; it is built on the JDK's skeletal map, set, collection
     * and entry, and its views' spliterators on {@code Spliterators}, none of which hashes in what it calls; it reads
     * an entry it is asked about and compares values with {@code Objects.equals}; its unreadable member is the path's
     * own error.
     */
    private static final Set<String> PLAIN_OBJECT_CALLEES = Set.of("java.lang.Object", "java.util.AbstractMap",
            "java.util.AbstractSet", "java.util.AbstractCollection", "java.util.AbstractMap.SimpleImmutableEntry",
            "java.util.Map.Entry", "java.util.Objects", "java.util.Spliterators", "java.util.NoSuchElementException",
            NAMES, JSON_REDACTION + ".Unreadable");
    /** The one static factory that makes a map on the sites: it wraps a map it is given and indexes nothing itself. */
    private static final String WRAPPER = "java.util.Collections.unmodifiableMap";
    /** Methods that hash, or look up a hash table, whatever class declares them. */
    private static final Set<String> HASHING_METHODS = Set.of("hashCode", "identityHashCode", "intern", "hash");
    /** Methods that add to a set or map: building an index of names other than {@code Names}. */
    private static final Set<String> INDEXING_METHODS = Set.of("add", "addAll", "put", "putAll", "putIfAbsent",
            "computeIfAbsent", "compute", "merge");
    /**
     * The methods that check names, {@code Owner.method}, and whether each must call {@code Names.add}: the text
     * reader's object, the tree reader's name, the redaction of a node; the tree reader's value, which makes the
     * index for each map; and the tree path's entry point, which also builds the maps it returns (#402).
     */
    private static final List<String> NAME_CHECKS = List.of("Reader.readContainer", "TreeReader.name",
            "JsonRedaction.redact(Node)");
    private static final List<String> NAME_SITES = List.of("Reader.readContainer", "TreeReader.name",
            "TreeReader.read", "JsonRedaction.redact(Node)", "JsonRedaction.redactTree");

    /**
     * What breaks the hash-free rule in {@code source}, a version of {@code JsonRedaction.java}: in
     * {@code JsonRedaction.Names}, a call or method reference to a class other than {@code Names} itself and
     * {@link #NAMES_CALLEES}, a call to one of {@link #HASHING_METHODS}, or a switch on a {@code String}, which
     * compiles to a hash code; the same in {@code JsonRedaction.PlainObject}, which may also call
     * {@link #PLAIN_OBJECT_CALLEES}; a method of {@link #NAME_CHECKS} that does not call {@code Names.add}; and in the
     * methods of {@link #NAME_SITES} and every method of {@link JsonRedaction} they reach, any set or map they make
     * (constructed, or returned by a static factory) other than a {@code PlainObject} or the {@link #WRAPPER} of one,
     * any {@link #INDEXING_METHODS} call on a set or map, or a switch on a {@code String}. Fixed sets of names that are
     * only looked up, such as {@link Redactor#JWK_PRIVATE_MEMBERS}, are not indexes and are not reported.
     */
    static List<String> namesIndexViolations(String source) {
        CompiledSource compiled = CompiledSource.compile("JsonRedaction", source);
        Trees trees = compiled.trees();
        Types types = compiled.types();
        TypeElement names = compiled.elements().getTypeElement(NAMES);
        List<String> violations = new ArrayList<>();
        if (names == null) {
            violations.add("JsonRedaction has no class Names");
        } else {
            TreePath path = trees.getPath(names);
            new Rules(trees, types, "Names", violations, NAMES_CALLEES).scan(path, null);
        }
        TypeElement plainObject = compiled.elements().getTypeElement(PLAIN_OBJECT);
        if (plainObject == null) {
            violations.add("JsonRedaction has no class PlainObject");
        } else {
            Set<String> callees = new LinkedHashSet<>(NAMES_CALLEES);
            callees.addAll(PLAIN_OBJECT_CALLEES);
            new Rules(trees, types, "PlainObject", violations, callees).scan(trees.getPath(plainObject), null);
        }
        TypeElement redaction = compiled.type(JSON_REDACTION);
        ArrayDeque<ExecutableElement> pending = new ArrayDeque<>();
        for (String site : NAME_SITES) {
            ExecutableElement method = method(compiled, redaction, site);
            if (method == null) {
                violations.add("JsonRedaction has no method " + site);
                continue;
            }
            Rules rules = new Rules(trees, types, site, violations, null);
            TreePath path = trees.getPath(method);
            rules.scan(new TreePath(path, ((MethodTree) path.getLeaf()).getBody()), null);
            if (NAME_CHECKS.contains(site) && !rules.called.contains(NAMES + ".add")) {
                violations.add(site + " does not call JsonRedaction.Names.add");
            }
            pending.addAll(rules.reached);
        }
        // What the sites call in JsonRedaction, transitively, follows the same rules: an index built in a helper is
        // still an index of the names. Calls out of JsonRedaction (Jackson, the text engine) are not followed.
        Set<ExecutableElement> seen = new LinkedHashSet<>();
        while (!pending.isEmpty()) {
            ExecutableElement next = pending.poll();
            TreePath path = trees.getPath(next);
            if (!seen.add(next) || path == null || !(path.getLeaf() instanceof MethodTree tree) || tree.getBody() == null) {
                // A record's implicit members have no body of their own.
                continue;
            }
            String where = ((TypeElement) next.getEnclosingElement()).getSimpleName() + "." + next.getSimpleName();
            Rules rules = new Rules(trees, types, where, violations, null);
            rules.scan(new TreePath(path, tree.getBody()), null);
            pending.addAll(rules.reached);
        }
        return violations;
    }

    /** The method {@code site} ({@code Owner.method}, or {@code JsonRedaction.redact(Node)}) of {@code redaction}. */
    private static ExecutableElement method(CompiledSource compiled, TypeElement redaction, String site) {
        String owner = site.substring(0, site.indexOf('.'));
        String rest = site.substring(site.indexOf('.') + 1);
        boolean node = rest.endsWith("(Node)");
        String name = node ? rest.substring(0, rest.indexOf('(')) : rest;
        TypeElement type = owner.equals("JsonRedaction") ? redaction
                : compiled.elements().getTypeElement(JSON_REDACTION + "." + owner);
        if (type == null) {
            return null;
        }
        return type.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.METHOD && e.getSimpleName().contentEquals(name))
                .map(ExecutableElement.class::cast)
                .filter(m -> !node || (!m.getParameters().isEmpty()
                        && m.getParameters().get(0).asType().toString().endsWith(".Node")))
                .findFirst().orElse(null);
    }

    /** Reads one class or method body for the rules of {@link #namesIndexViolations}. */
    private static final class Rules extends TreePathScanner<Void, Void> {
        private final Trees trees;
        private final Types types;
        private final String where;
        private final List<String> violations;
        /** Whether this is one of the hash-free classes, which may call only themselves and {@link #callees}. */
        private final boolean index;
        /** The classes a hash-free class may call besides the hash-free classes; {@code null} on the sites. */
        private final Set<String> callees;
        final Set<String> called = new LinkedHashSet<>();
        /**
         * The methods and constructors of {@link JsonRedaction} and its nested classes, other than the hash-free
         * classes, called.
         */
        final Set<ExecutableElement> reached = new LinkedHashSet<>();

        Rules(Trees trees, Types types, String where, List<String> violations, Set<String> callees) {
            this.trees = trees;
            this.types = types;
            this.where = where;
            this.violations = violations;
            this.index = callees != null;
            this.callees = callees;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            reach(trees.getElement(getCurrentPath()), node);
            if (!index && trees.getElement(getCurrentPath()) instanceof ExecutableElement method
                    && method.getModifiers().contains(javax.lang.model.element.Modifier.STATIC)) {
                // A factory such as Set.of or Collectors.toSet; a set an instance hands out, such as a map's
                // entries, is read, not made.
                TypeMirror returned = trees.getTypeMirror(getCurrentPath());
                String factory = ((TypeElement) method.getEnclosingElement()).getQualifiedName() + "."
                        + method.getSimpleName();
                if (!factory.equals(WRAPPER) && (isCollection(returned, "java.util.Set")
                        || isCollection(returned, "java.util.Map")
                        || isCollection(returned, "java.util.stream.Collector"))) {
                    violations.add("in " + where + ": makes a " + returned + " with " + node.getMethodSelect());
                }
            }
            if (!index) {
                if (node.getMethodSelect() instanceof MemberSelectTree select
                        && INDEXING_METHODS.contains(select.getIdentifier().toString())) {
                    TypeMirror receiver = trees.getTypeMirror(new TreePath(getCurrentPath(), select.getExpression()));
                    if (isCollection(receiver, "java.util.Set") || isCollection(receiver, "java.util.Map")) {
                        violations.add("in " + where + ": indexes with " + receiver + "." + select.getIdentifier());
                    }
                }
            }
            return super.visitMethodInvocation(node, unused);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void unused) {
            Element target = trees.getElement(getCurrentPath());
            reach(target, node);
            if (!index && target != null) {
                TypeMirror made = target.getEnclosingElement().asType();
                boolean hashFree = target.getEnclosingElement() instanceof TypeElement type
                        && type.getQualifiedName().contentEquals(PLAIN_OBJECT);
                if (!hashFree && (isCollection(made, "java.util.Set") || isCollection(made, "java.util.Map"))) {
                    violations.add("in " + where + ": constructs " + types.erasure(made));
                }
            }
            return super.visitNewClass(node, unused);
        }

        @Override
        public Void visitMemberReference(MemberReferenceTree node, Void unused) {
            reach(trees.getElement(getCurrentPath()), node);
            return super.visitMemberReference(node, unused);
        }

        @Override
        public Void visitSwitch(SwitchTree node, Void unused) {
            selector(node.getExpression());
            return super.visitSwitch(node, unused);
        }

        @Override
        public Void visitSwitchExpression(SwitchExpressionTree node, Void unused) {
            selector(node.getExpression());
            return super.visitSwitchExpression(node, unused);
        }

        private void selector(ExpressionTree expression) {
            TypeMirror type = trees.getTypeMirror(new TreePath(getCurrentPath(), expression));
            if (type != null && type.toString().equals("java.lang.String")) {
                violations.add("in " + where + ": switches on a String, which hashes it");
            }
        }

        private void reach(Element target, Tree node) {
            if (!(target instanceof ExecutableElement method)) {
                violations.add("in " + where + ": cannot resolve " + node);
                return;
            }
            String owner = ((TypeElement) method.getEnclosingElement()).getQualifiedName().toString();
            String name = method.getSimpleName().toString();
            called.add(owner + "." + name);
            if ((owner.equals(JSON_REDACTION) || owner.startsWith(JSON_REDACTION + ".")) && !hashFree(owner)) {
                reached.add(method);
            }
            if (HASHING_METHODS.contains(name)) {
                violations.add("in " + where + ": hashes with " + owner + "." + name);
            } else if (index && !owner.equals(where.startsWith("Names") ? NAMES : PLAIN_OBJECT)
                    && !owner.startsWith(PLAIN_OBJECT + ".") && !callees.contains(owner)) {
                violations.add("in " + where + ": calls " + owner + "." + name);
            }
        }

        /** Whether {@code owner} is one of the hash-free classes, read by their own rules, or nested in one. */
        private static boolean hashFree(String owner) {
            return owner.equals(NAMES) || owner.equals(PLAIN_OBJECT) || owner.startsWith(PLAIN_OBJECT + ".");
        }

        /** Whether {@code type} is, erased, {@code collection} or a subtype of it. */
        private boolean isCollection(TypeMirror type, String collection) {
            if (type == null || type.getKind() != TypeKind.DECLARED) {
                return false;
            }
            TypeMirror erased = types.erasure(type);
            if (types.asElement(erased) instanceof TypeElement element
                    && element.getQualifiedName().contentEquals(collection)) {
                return true;
            }
            return types.directSupertypes(erased).stream().anyMatch(s -> isCollection(s, collection));
        }
    }
}
