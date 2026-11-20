package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.io.JsonStringEncoder;
import tools.jackson.core.json.JsonFactory;

/**
 * An expectation for {@link Redactor#redact(String)} since its structural path (#377): the expected text with each JSON
 * string literal written as Jackson's encoder writes it, and every byte outside string literals as it is. It is written
 * apart from the Redactor, so a test that compares the Redactor's output with {@link #of(String)} exactly checks the
 * old expectation and nothing looser.
 *
 * <p>A text is rewritten only when it is one JSON value whose first character, after JSON whitespace, opens an object,
 * an array or a string, as the Redactor reads it. A string literal's content is rewritten the same way first, to
 * {@link JsonRedaction#MAX_LEVELS} levels, since the Redactor reads JSON held in a string as JSON. Any other text is
 * its own expectation.
 */
final class Canonical {

    private static final JsonFactory FACTORY = JsonFactory.builder().build();
    private static final JsonStringEncoder ENCODER = JsonStringEncoder.getInstance();

    private Canonical() {
    }

    /** Asserts that {@code input} redacts to exactly {@code expected} as Jackson's encoder spells its strings. */
    static void assertRedactsTo(String expected, String input) {
        assertRedactsTo(expected, input, input);
    }

    /** {@link #assertRedactsTo(String, String)} with {@code message} in the failure. */
    static void assertRedactsTo(String expected, String input, String message) {
        assertEquals(of(expected), Redactor.redact(input), message);
    }

    /** Asserts that the Redactor keeps {@code text}: exactly {@code text} as Jackson's encoder spells its strings. */
    static void assertKept(String text) {
        assertRedactsTo(text, text, text);
    }

    /** {@link #assertKept(String)} with {@code message} in the failure. */
    static void assertKept(String text, String message) {
        assertRedactsTo(text, text, message);
    }

    /** {@code text} with its string literals as Jackson's encoder writes them, if it is one JSON value. */
    static String of(String text) {
        return of(text, 0);
    }

    private static String of(String text, int level) {
        if (text == null || level >= JsonRedaction.MAX_LEVELS || !opensJson(text) || !oneValue(text)) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c != '"') {
                out.append(c);
                i++;
                continue;
            }
            int end = i + 1;
            while (text.charAt(end) != '"') {
                end += text.charAt(end) == '\\' ? 2 : 1;
            }
            out.append('"');
            ENCODER.quoteAsString(of(decoded(text.substring(i, end + 1)), level + 1), out);
            out.append('"');
            i = end + 1;
        }
        return out.toString();
    }

    /**
     * Whether the Redactor's structural path reads {@code text} (#377): it is one JSON value whose first character, after
     * JSON whitespace, opens an object, an array or a string.
     */
    static boolean isJson(String text) {
        return opensJson(text) && oneValue(text);
    }

    private static boolean opensJson(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return c == '{' || c == '[' || c == '"';
            }
        }
        return false;
    }

    /** Whether {@code text} is exactly one JSON value, with only JSON whitespace around it. */
    private static boolean oneValue(String text) {
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), text)) {
            int depth = 0;
            int roots = 0;
            for (JsonToken token = parser.nextToken(); token != null; token = parser.nextToken()) {
                if (token.isStructStart()) {
                    depth++;
                } else if (token.isStructEnd()) {
                    depth--;
                }
                if (depth == 0 && token != JsonToken.PROPERTY_NAME) {
                    roots++;
                }
            }
            return roots == 1;
        } catch (RuntimeException notJson) {
            return false;
        }
    }

    private static String decoded(String literal) {
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), literal)) {
            parser.nextToken();
            return parser.getString();
        }
    }
}
