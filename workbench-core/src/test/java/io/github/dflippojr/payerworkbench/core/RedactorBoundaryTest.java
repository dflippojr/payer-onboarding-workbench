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
