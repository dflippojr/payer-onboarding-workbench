package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
            assertEquals(Redactor.MASK, Redactor.redact(text), "text, level " + level);
            assertEquals(Redactor.MASK, Redactor.redactTree(treeAt(openKeyJson(), level)), "tree, level " + level);
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
        assertEquals(Redactor.MASK, Redactor.redact(quoted(HEADER)));
        assertEquals(Redactor.MASK, Redactor.redact(quoted(textAt(openKeyJson(), JsonRedaction.MAX_LEVELS))));
    }

    @Test
    void redactsATreeWhoseRootIsOneStringAsTheSameRootString() {
        assertEquals("A Bearer [REDACTED]", Redactor.redactTree("A Bearer " + SECRET));
        assertEquals(Redactor.MASK, Redactor.redactTree(REPEATED));
        assertEquals(Redactor.MASK, Redactor.redactTree(HEADER));
        assertEquals(Redactor.MASK, Redactor.redactTree(textAt(openKeyJson(), JsonRedaction.MAX_LEVELS)));
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
        assertEquals(Redactor.MASK, Redactor.redact("{\"a\":\"" + escapedFirst(HEADER) + "\"} {\"n\":" + quoted(REST) + "}"));
        assertEquals(Redactor.MASK, Redactor.redact("{\"n\":1} {\"a\":\"" + escapedFirst(HEADER) + "\"}"));
        assertEquals(Redactor.MASK, Redactor.redact(textAt(openKeyJson() + " trailing", 1)));
    }

    @Test
    void redactsATreeStringWithContentAfterItsRootValueWithTheTextEngine() {
        assertEquals(Map.of("b", "{\"a\":\"A\"} "), Redactor.redactTree(Map.of("b", ESCAPED_OBJECT + " ")));
        assertEquals(Map.of("b", ESCAPED_OBJECT + " trailing"), Redactor.redactTree(Map.of("b", ESCAPED_OBJECT + " trailing")));
        assertEquals(Redactor.MASK, Redactor.redactTree(treeAt(openKeyJson() + " trailing", 1)));
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
        assertEquals(Redactor.MASK, Redactor.redact(tooDeep(escaped)));
        assertEquals("{\"b\":\"[REDACTED]\",\"c\":1}", Redactor.redact("{\"b\":" + quoted(tooDeep(escaped)) + ",\"c\":1}"));
        // A read error within them: the text engine reads it, keeping the escape as it is spelled.
        assertEquals(readError(escaped), Redactor.redact(readError(escaped)));
        String nestedError = "{\"b\":" + quoted(readError(escaped)) + ",\"c\":1}";
        assertEquals(nestedError, Redactor.redact(nestedError));
        // Fails closed on both branches: a key block the rejected text opens masks the outermost text.
        String opener = escapedFirst(HEADER);
        for (String rejected : List.of(tooDeep(opener), readError(opener))) {
            assertEquals(Redactor.MASK, Redactor.redact("{\"b\":" + quoted(rejected) + ",\"note\":" + quoted(REST) + "}"));
            Map<String, Object> tree = new LinkedHashMap<>();
            tree.put("b", rejected);
            tree.put("note", REST);
            assertEquals(Redactor.MASK, Redactor.redactTree(tree));
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
