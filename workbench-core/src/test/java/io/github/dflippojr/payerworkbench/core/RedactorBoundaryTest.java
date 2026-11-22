package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The boundaries where {@link JsonRedaction} chooses between the structural path and the text engine (#389), each
 * pinned on the text path ({@link Redactor#redact(String)}) and on the tree path ({@link Redactor#redactTree(Object)})
 * where it applies. Every secret here is synthetic, and key armor is built from its parts.
 */
class RedactorBoundaryTest {

    private static final String SECRET = "FAKE-SECRET-389-NOT-REAL";

    private static final String DASHES = "-".repeat(5);

    /** A private key block's opening armor line, built from its parts. */
    private static final String HEADER = DASHES + "BEGIN " + "PRIVATE" + " KEY" + DASHES;

    /** The matching closing armor line. */
    private static final String FOOTER = DASHES + "END " + "PRIVATE" + " KEY" + DASHES;

    /** Text with key material and a closing armor line, but no opening one: the rest of a block opened elsewhere. */
    private static final String REST = SECRET + "\n" + FOOTER;

    // ---- the unterminated-key rule at every JSON-in-string level ----------------------------------------------------

    /**
     * The levels of the grid: the last one the structural path reads, the first and second ones the text engine reads,
     * and the deepest one a text within {@link JsonRedaction#MAX_CHARS} can hold.
     */
    private static List<Integer> keyLevels() {
        return List.of(JsonRedaction.MAX_LEVELS - 1, JsonRedaction.MAX_LEVELS, JsonRedaction.MAX_LEVELS + 1,
                deepestLevel());
    }

    /** JSON whose one string opens a key block, the string's first character written as an escape. */
    private static String openKeyJson() {
        return "{\"k\":\"" + escapedFirst(HEADER) + "\"}";
    }

    /** The same JSON with a string that opens nothing. */
    private static String plainJson() {
        return "{\"k\":\"" + escapedFirst("plain words") + "\"}";
    }

    /** {@code inner} at JSON-in-string level {@code level} of a text whose later member holds {@link #REST}. */
    private static String textAt(String inner, int level) {
        return "{\"x\":" + quoted(wrap(inner, level - 1)) + ",\"note\":" + quoted(REST) + "}";
    }

    /** The same as a tree: the root map is level 0, its string values level 1. */
    private static Map<String, Object> treeAt(String inner, int level) {
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("x", wrap(inner, level - 1));
        tree.put("note", REST);
        return tree;
    }

    /** The deepest level at which {@link #textAt} stays within {@link JsonRedaction#MAX_CHARS}. */
    private static int deepestLevel() {
        int level = JsonRedaction.MAX_LEVELS + 1;
        while (textAt(openKeyJson(), level + 1).length() <= JsonRedaction.MAX_CHARS) {
            level++;
        }
        return level;
    }

    @Test
    void masksTheOutermostTextWhenAStringAtAnyLevelOpensAKeyBlockItDoesNotClose() {
        for (int level : keyLevels()) {
            String text = textAt(openKeyJson(), level);
            assertTrue(text.length() <= JsonRedaction.MAX_CHARS, "level " + level);
            assertMaskedWhole(Redactor.redact(text), "text, level " + level);
            assertMaskedWhole(Redactor.redactTree(treeAt(openKeyJson(), level)), "tree, level " + level);
        }
    }

    @Test
    void keepsTheSameShapeAtEveryLevelWhenNoStringOpensAKeyBlock() {
        // The control: the grid's texts are masked for the block they open, not for their shape or size.
        for (int level : keyLevels()) {
            assertNotEquals(Redactor.MASK, Redactor.redact(textAt(plainJson(), level)), "text, level " + level);
            assertNotEquals(Redactor.MASK, Redactor.redactTree(treeAt(plainJson(), level)), "tree, level " + level);
        }
    }

    // ---- the unterminated-key rule at every bound where the structural path stops reading -----------------------------

    /**
     * Spellings of a key block's opening armor line that only a decoding shows, as the content of a JSON string: its
     * first character as an escape, a letter of its label as an escape, and one whose closing dashes are the opening
     * dashes of a literal header that a literal footer closes.
     */
    private static List<String> hiddenOpeners() {
        int letter = HEADER.indexOf('P');
        String labelEscaped = HEADER.substring(0, letter) + escapedFirst(HEADER.substring(letter));
        String sharedDashes = escapedFirst(HEADER.substring(0, HEADER.length() - DASHES.length())) + HEADER + "\\n"
                + "body" + "\\n" + FOOTER;
        return List.of(escapedFirst(HEADER), labelEscaped, sharedDashes);
    }

    /** The control: a string with an escape that opens nothing. */
    private static final String PLAIN_OPENER = escapedFirst("plain words");

    /** A text the structural path stops reading before or at {@code opener}, a JSON string's content. */
    private record Shape(String name, java.util.function.UnaryOperator<String> around) {
    }

    private static List<Shape> rejectedShapes() {
        return List.of(
                new Shape("read error before it", o -> "[\"x\",oops,\"" + o + "\"]"),
                new Shape("read error before it, as a name", o -> "{oops:1,\"" + o + "\":1}"),
                new Shape("words after the root value", o -> "{\"a\":1} words \"" + o + "\""),
                new Shape("not JSON", o -> "note: " + o),
                new Shape("an unclosed string", o -> "[\"x\", \"" + o),
                new Shape("an unescaped control character before it", o -> "[\"a\tb\",\"" + o + "\"]"),
                new Shape("nesting at the depth bound", o -> nestedIn(JsonRedaction.MAX_DEPTH, "\"" + o + "\"")),
                new Shape("nesting past the depth bound", o -> nestedIn(JsonRedaction.MAX_DEPTH + 1, "\"" + o + "\"")),
                new Shape("nesting past the depth bound before it",
                        o -> nestedIn(JsonRedaction.MAX_DEPTH + 1, "1") + "[\"" + o + "\"]"));
    }

    /** Where a string at level 1 sits: a value, a secret member's value, a JWK private member's value, a name, an item. */
    private record Kind(String name, java.util.function.Function<String, String> text,
            java.util.function.Function<String, Object> tree) {
    }

    private static List<Kind> kinds() {
        return List.of(
                new Kind("value", s -> "{\"x\":" + quoted(s) + ",\"note\":" + quoted(REST) + "}", s -> ordered("x", s, "note", REST)),
                new Kind("secret value", s -> "{\"password\":" + quoted(s) + ",\"note\":" + quoted(REST) + "}",
                        s -> ordered("password", s, "note", REST)),
                new Kind("JWK private value", s -> "{\"kty\":\"RSA\",\"d\":" + quoted(s) + ",\"note\":" + quoted(REST) + "}",
                        s -> {
                            Map<String, Object> jwk = ordered("kty", "RSA", "d", s);
                            jwk.put("note", REST);
                            return jwk;
                        }),
                new Kind("name", s -> "{" + quoted(s) + ":1,\"note\":" + quoted(REST) + "}", s -> ordered(s, 1, "note", REST)),
                new Kind("item", s -> "[" + quoted(s) + "," + quoted(REST) + "]", s -> List.of(s, REST)));
    }

    @Test
    void masksTheOutermostTextWhenARejectedStringHidesAKeyBlockItDoesNotClose() {
        // Every cell is run, and the ones that miss are listed together: a grid, not a first failure.
        List<String> missed = new java.util.ArrayList<>();
        for (Shape shape : rejectedShapes()) {
            for (Kind kind : kinds()) {
                List<String> openers = hiddenOpeners();
                for (int i = 0; i < openers.size(); i++) {
                    String nested = shape.around().apply(openers.get(i));
                    String cell = shape.name() + ", " + kind.name() + ", opener " + i;
                    if (!maskedWhole(Redactor.redact(kind.text().apply(nested)))) {
                        missed.add("text: " + cell);
                    }
                    if (!maskedWhole(Redactor.redactTree(kind.tree().apply(nested)))) {
                        missed.add("tree: " + cell);
                    }
                }
                String control = shape.around().apply(PLAIN_OPENER);
                if (Redactor.MASK.equals(Redactor.redact(kind.text().apply(control)))) {
                    missed.add("text control masked: " + shape.name() + ", " + kind.name());
                }
                if (Redactor.MASK.equals(Redactor.redactTree(kind.tree().apply(control)))) {
                    missed.add("tree control masked: " + shape.name() + ", " + kind.name());
                }
            }
        }
        assertEquals(List.of(), missed);
    }

    /** A text of exactly {@code length} characters holding {@code nested} at level 1 and {@link #REST} after it. */
    private static String textOfLength(String nested, int length) {
        String head = "{\"x\":" + quoted(nested) + ",\"pad\":\"";
        String tail = "\",\"note\":" + quoted(REST) + "}";
        return head + "p".repeat(length - head.length() - tail.length()) + tail;
    }

    /** A tree string of exactly {@code length} characters: JSON whose string holds {@code opener}, then padding. */
    private static String stringOfLength(String opener, int length) {
        String head = "{\"k\":\"" + opener + "\",\"pad\":\"";
        return head + "p".repeat(length - head.length() - 2) + "\"}";
    }

    @Test
    void masksTheOutermostTextWhenAStringHidesAKeyBlockAtTheLengthBound() {
        for (int length : List.of(JsonRedaction.MAX_CHARS, JsonRedaction.MAX_CHARS + 1)) {
            String text = textOfLength("{\"k\":\"" + escapedFirst(HEADER) + "\"}", length);
            assertEquals(length, text.length());
            assertMaskedWhole(Redactor.redact(text), "text of length " + length);
            String string = stringOfLength(escapedFirst(HEADER), length);
            assertEquals(length, string.length());
            assertMaskedWhole(Redactor.redactTree(ordered("x", string, "note", REST)), "tree string of length " + length);
            String plainText = textOfLength("{\"k\":\"" + PLAIN_OPENER + "\"}", length);
            assertNotEquals(Redactor.MASK, Redactor.redact(plainText), "text control of length " + length);
            String plainString = stringOfLength(PLAIN_OPENER, length);
            assertNotEquals(Redactor.MASK, Redactor.redactTree(ordered("x", plainString, "note", REST)),
                    "tree control of length " + length);
        }
    }

    /**
     * {@code c} spelled so that {@code levels} decodings show it: a unicode escape whose backslash is itself spelled as
     * a unicode escape, {@code levels - 1} times over.
     */
    private static String chain(char c, int levels) {
        String last = String.format("u%04x", (int) c);
        return levels == 1 ? "\\" + last : "\\u005c" + "u005c".repeat(levels - 2) + last;
    }

    @Test
    void masksTheOutermostTextAtTheEscapeLevelBound() {
        String rest = HEADER.substring(1);
        for (int levels : List.of(JsonRedaction.MAX_KEY_LEVELS, JsonRedaction.MAX_KEY_LEVELS + 1)) {
            // A text's string is decoded once by the parser, so it is one level ahead of the same string in a tree.
            String text = "{\"x\":\"" + chain('-', levels) + rest + "\",\"note\":" + quoted(REST) + "}";
            assertMaskedWhole(Redactor.redact(text), "text, escape level " + levels);
            assertMaskedWhole(Redactor.redactTree(ordered("x", chain('-', levels - 1) + rest, "note", REST)),
                    "tree, escape level " + levels);
        }
        // The control: within the bound, escapes that show no key opener keep the text; past it, they mask it.
        int bound = JsonRedaction.MAX_KEY_LEVELS;
        String within = "{\"x\":\"" + chain('p', bound) + "lain words\",\"note\":\"n\"}";
        assertNotEquals(Redactor.MASK, Redactor.redact(within));
        assertNotEquals(Redactor.MASK, Redactor.redactTree(ordered("x", chain('p', bound - 1) + "lain words", "note", "n")));
        String past = "{\"x\":\"" + chain('p', bound + 1) + "lain words\",\"note\":\"n\"}";
        assertEquals(Redactor.MASK, Redactor.redact(past));
        assertEquals(Redactor.MASK, Redactor.redactTree(ordered("x", chain('p', bound) + "lain words", "note", "n")));
    }

    @Test
    void readsTheLongestEscapeChainWithinTheLengthBoundInLinearTime() {
        // The escape-level bound keeps the passes few: an escape chain as long as a text may be is masked quickly.
        int levels = (JsonRedaction.MAX_CHARS - 64) / 5;
        String text = "{\"x\":\"" + chain('-', levels) + "\"}";
        String string = chain('-', levels);
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(20), () -> {
            assertEquals(Redactor.MASK, Redactor.redact(text));
            assertEquals(Redactor.MASK, Redactor.redactTree(Map.of("x", string)));
        });
    }

    // ---- a text whose root is one JSON string (Place.ROOT) -----------------------------------------------------------

    /** A string the structural path writes anew: its first letter spelled as an escape, then a credential. */
    private static final String ESCAPED_BEARER = escapedFirst("A Bearer " + SECRET);

    @Test
    void readsATextWhoseRootIsOneJsonStringOnTheTree() {
        // On the tree: the escape is written anew, the credential masked and the whitespace around the root kept.
        assertEquals("  \"A Bearer [REDACTED]\"\n", Redactor.redact("  \"" + ESCAPED_BEARER + "\"\n"));
        // JSON held in the root string is read one level down: names that repeat there mask that string, not the text.
        assertEquals("\"[REDACTED]\"", Redactor.redact(quoted(REPEATED)));
        // Fails closed: a root string that opens a key block masks the text whole.
        assertMaskedWhole(Redactor.redact(quoted(HEADER)));
        assertMaskedWhole(Redactor.redact(quoted(textAt(openKeyJson(), JsonRedaction.MAX_LEVELS))));
    }

    @Test
    void redactsATreeWhoseRootIsOneStringAsTheSameRootString() {
        assertEquals("A Bearer [REDACTED]", Redactor.redactTree("A Bearer " + SECRET));
        assertMaskedWhole(Redactor.redactTree(REPEATED));
        assertMaskedWhole(Redactor.redactTree(HEADER));
        assertMaskedWhole(Redactor.redactTree(textAt(openKeyJson(), JsonRedaction.MAX_LEVELS)));
    }

    // ---- a text rejected for content after its root value ------------------------------------------------------------

    /** One JSON value whose string the structural path would write anew. */
    private static final String ESCAPED_OBJECT = "{\"a\":\"" + escapedFirst("A") + "\"}";

    @Test
    void readsATextWithContentAfterItsRootValueWithTheTextEngine() {
        // Whitespace after the root value is not content: the text is read on the tree, and the whitespace kept.
        assertEquals("{\"a\":\"A\"} \r\n\t", Redactor.redact(ESCAPED_OBJECT + " \r\n\t"));
        // Words or a second value after it: the text engine reads the text, which keeps the escape as it is spelled.
        for (String after : List.of(" trailing", " {}", "\"b\"", " 1")) {
            assertEquals(ESCAPED_OBJECT + after, Redactor.redact(ESCAPED_OBJECT + after), after);
        }
        assertEquals("{\"password\":\"[REDACTED]\"} trailing", Redactor.redact("{\"password\":\"" + SECRET + "\"} trailing"));
        // The same for JSON held in a string: only that string goes to the text engine.
        String nested = "{\"b\":" + quoted(ESCAPED_OBJECT + " trailing") + ",\"c\":\"" + escapedFirst("C") + "\"}";
        assertEquals("{\"b\":" + quoted(ESCAPED_OBJECT + " trailing") + ",\"c\":\"C\"}", Redactor.redact(nested));
        // Fails closed: the rejected text is read for a key block it opens, before and after its root value.
        assertMaskedWhole(Redactor.redact("{\"a\":\"" + escapedFirst(HEADER) + "\"} {\"n\":" + quoted(REST) + "}"));
        assertMaskedWhole(Redactor.redact("{\"n\":1} {\"a\":\"" + escapedFirst(HEADER) + "\"}"));
        // So with an opener the text spells plainly: the text engine alone would mask only from it on.
        assertMaskedWhole(Redactor.redact("{\"a\":" + quoted(HEADER) + "} {\"n\":" + quoted(REST) + "}"));
        assertMaskedWhole(Redactor.redact(textAt(openKeyJson() + " trailing", 1)));
    }

    @Test
    void redactsATreeStringWithContentAfterItsRootValueWithTheTextEngine() {
        assertEquals(Map.of("b", "{\"a\":\"A\"} "), Redactor.redactTree(Map.of("b", ESCAPED_OBJECT + " ")));
        assertEquals(Map.of("b", ESCAPED_OBJECT + " trailing"), Redactor.redactTree(Map.of("b", ESCAPED_OBJECT + " trailing")));
        assertMaskedWhole(Redactor.redactTree(treeAt(openKeyJson() + " trailing", 1)));
    }

    // ---- a text rejected through the parser's stream constraints, as against a plain read error ----------------------

    /** {@code inner} inside {@code depth} arrays. */
    private static String nestedIn(int depth, String inner) {
        return "[".repeat(depth) + inner + "]".repeat(depth);
    }

    /** Nesting one past {@link JsonRedaction#MAX_DEPTH}: the parser's stream constraints stop it. */
    private static String tooDeep(String string) {
        return nestedIn(JsonRedaction.MAX_DEPTH + 1, "\"" + string + "\"");
    }

    /** A read error (a comma before a closing bracket) at {@link JsonRedaction#MAX_DEPTH}, within the bound. */
    private static String readError(String string) {
        return "[".repeat(JsonRedaction.MAX_DEPTH) + "\"" + string + "\",]" + "]".repeat(JsonRedaction.MAX_DEPTH - 1);
    }

    @Test
    void masksJsonPastTheStreamConstraintsAndReadsAReadErrorWithTheTextEngine() {
        String escaped = escapedFirst("A");
        // Past the constraints: the text is masked whole, or the string that holds it.
        assertMaskedWhole(Redactor.redact(tooDeep(escaped)));
        assertEquals("{\"b\":\"[REDACTED]\",\"c\":1}", Redactor.redact("{\"b\":" + quoted(tooDeep(escaped)) + ",\"c\":1}"));
        // A read error within them: the text engine reads it, keeping the escape as it is spelled.
        assertEquals(readError(escaped), Redactor.redact(readError(escaped)));
        String nestedError = "{\"b\":" + quoted(readError(escaped)) + ",\"c\":1}";
        assertEquals(nestedError, Redactor.redact(nestedError));
        // Fails closed on both branches: a key block the rejected text opens masks the outermost text.
        String opener = escapedFirst(HEADER);
        for (String rejected : List.of(tooDeep(opener), readError(opener))) {
            assertMaskedWhole(Redactor.redact("{\"b\":" + quoted(rejected) + ",\"note\":" + quoted(REST) + "}"));
            Map<String, Object> tree = new LinkedHashMap<>();
            tree.put("b", rejected);
            tree.put("note", REST);
            assertMaskedWhole(Redactor.redactTree(tree));
        }
    }

    @Test
    void redactsATreeStringPastTheStreamConstraintsAsTheSameTextString() {
        String escaped = escapedFirst("A");
        assertEquals(Map.of("b", Redactor.MASK), Redactor.redactTree(Map.of("b", tooDeep(escaped))));
        assertEquals(Map.of("b", readError(escaped)), Redactor.redactTree(Map.of("b", readError(escaped))));
    }

    // ---- the last level the structural path reads, next to the first the text engine reads ---------------------------

    /** JSON whose names repeat: the structural path masks the string that holds it, the text engine keeps it. */
    private static final String REPEATED = "{\"a\":1,\"a\":2}";

    /** The text at the level above {@link #REPEATED} once the structural path masks the string holding it. */
    private static final String MASKED_HOLDER = "{\"b\":\"[REDACTED]\"}";

    @Test
    void readsAStringAtTheLastLevelOnTheTreeAndOneLevelDeeperWithTheTextEngine() {
        int last = JsonRedaction.MAX_LEVELS - 1;
        // A value: JSON at the last level is read on the tree and the string holding it masked.
        assertEquals(wrap(MASKED_HOLDER, last - 1), Redactor.redact(wrap(REPEATED, last)));
        assertEquals(Map.of("b", wrap(MASKED_HOLDER, last - 2)), Redactor.redactTree(Map.of("b", wrap(REPEATED, last - 1))));
        // A name, the same.
        assertEquals("{" + quoted(wrap(MASKED_HOLDER, last - 2)) + ":1}",
                Redactor.redact("{" + quoted(wrap(REPEATED, last - 1)) + ":1}"));
        assertEquals(Map.of(wrap(MASKED_HOLDER, last - 2), 1), Redactor.redactTree(Map.of(wrap(REPEATED, last - 1), 1)));
        // One level deeper the text engine reads it and keeps it.
        int first = JsonRedaction.MAX_LEVELS;
        assertEquals(wrap(REPEATED, first), Redactor.redact(wrap(REPEATED, first)));
        assertEquals(Map.of("b", wrap(REPEATED, first - 1)), Redactor.redactTree(Map.of("b", wrap(REPEATED, first - 1))));
        assertEquals("{" + quoted(wrap(REPEATED, first - 1)) + ":1}",
                Redactor.redact("{" + quoted(wrap(REPEATED, first - 1)) + ":1}"));
        assertEquals(Map.of(wrap(REPEATED, first - 1), 1), Redactor.redactTree(Map.of(wrap(REPEATED, first - 1), 1)));
        // A secret at either level is masked all the same, by the tree or by the text engine.
        for (int level : List.of(last, first)) {
            String out = Redactor.redact(wrap("{\"password\":\"" + SECRET + "\"}", level));
            assertTrue(out.contains(Redactor.MASK) && !out.contains(SECRET), "level " + level);
        }
    }

    // ---- helpers -----------------------------------------------------------------------------------------------------

    /** Whether {@code out} is the mask alone: no byte of the synthetic secret is left, nor any armor. */
    private static boolean maskedWhole(Object out) {
        String text = String.valueOf(out);
        return !text.contains(SECRET) && !text.contains(DASHES) && Redactor.MASK.equals(out);
    }

    private static void assertMaskedWhole(Object out, String cell) {
        String text = String.valueOf(out);
        assertFalse(text.contains(SECRET), "secret kept: " + cell);
        assertFalse(text.contains(DASHES), "armor kept: " + cell);
        assertEquals(Redactor.MASK, out, cell);
    }

    private static void assertMaskedWhole(Object out) {
        assertMaskedWhole(out, "");
    }

    /** A map of two members in order. */
    private static Map<String, Object> ordered(String a, Object aValue, String b, Object bValue) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(a, aValue);
        map.put(b, bValue);
        return map;
    }

    /** {@code text} held {@code times} times over as the string value of a one-member object. */
    private static String wrap(String text, int times) {
        String out = text;
        for (int i = 0; i < times; i++) {
            out = "{\"b\":" + quoted(out) + "}";
        }
        return out;
    }

    /** {@code text} with its first character written as a JSON unicode escape. */
    private static String escapedFirst(String text) {
        return String.format("\\u%04x", (int) text.charAt(0)) + text.substring(1);
    }

    /** {@code text} as a JSON string, quotes included; a line break as an escape. */
    private static String quoted(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
