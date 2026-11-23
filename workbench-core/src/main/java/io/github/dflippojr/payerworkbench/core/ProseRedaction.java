package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The structural path for text that is not one JSON value (#377, stage 2): each JSON value embedded in it is redacted on
 * the tree, as in stage 1, and the text around those values goes to the text rules ({@link Redactor#redact(String,
 * List)}), which then see no JSON value.
 *
 * <p>Reading a text at JSON-in-string level {@code level}:
 *
 * <ol>
 *   <li>Each {@code {} or {@code [} not inside a value already read starts an attempt to read one JSON value there with
 *       the stage-1 parser ({@link JsonRedaction#valueEnd}). A value that reads is redacted on the tree
 *       ({@link JsonRedaction#redact(String, int)}) and its canonical output is spliced back in. A string or name the
 *       attempt decodes that opens a private key block it does not close makes the outermost text the mask, whether or
 *       not the attempt reads a whole value, as in stage 1.
 *   <li>The first JSON-looking start that does not read ({@link #looksLikeJson}) masks the text from there to its end if
 *       the text after it, values that read included, holds secret vocabulary ({@link #hasVocabulary}): a JWK's
 *       {@code kty} or a secret name in a value after it may belong to the object that did not read. "The text" is the
 *       one being read at this level: the outermost text, or the decoded string the tree path hands down.
 *   <li>The rest, each value that read held by a placeholder, goes to the text rules once, so a secret name, form key
 *       or header line in the text still masks the value after it: a placeholder the rules mask takes its value with
 *       it.
 *   <li>Fail closed: if any decoding of the result's JSON escapes ({@link JsonRedaction#unescaped}, one level at a
 *       time) still holds something the text rules mask, the whole text is the mask. The text rules read only the
 *       plain spelling and JSON held in a string one level deep; this is what stands for every deeper escape level.
 * </ol>
 *
 * <p>Past {@link JsonRedaction#MAX_LEVELS} or {@link JsonRedaction#MAX_CHARS} no value is read, and every JSON-looking
 * start counts as one that does not read. Attempts that fail may read at most {@code 2n + 4096} characters in all of a
 * text of length {@code n}; past that, no more values are read, so the work stays linear.
 */
final class ProseRedaction {

    /** Starts a placeholder, after its opening brace; two digits and the closing brace follow. */
    private static final char HOLE = '';

    /** The first placeholder digit; the digits are {@code FIRST_DIGIT} to {@code }. */
    private static final char FIRST_DIGIT = '';

    /** The number of placeholder digits. */
    private static final int BASE = '' - FIRST_DIGIT + 1;

    /** The length of a placeholder: a brace, {@link #HOLE}, two digits and a brace. */
    private static final int HOLE_LENGTH = 5;

    /**
     * Secret vocabulary: a secret field name with any {@code _} or {@code -} between its letters, a credential header
     * name, the {@code kty} of a JWK, or an armor header, in any case.
     */
    private static final Pattern VOCABULARY = Pattern.compile("(?i)" + Redactor.SECRET_FIELDS.stream()
            .map(name -> String.join("[_-]?", name.split("")))
            .reduce((a, b) -> a + "|" + b).orElseThrow()
            + "|" + String.join("|", Redactor.SENSITIVE_HEADERS).replace("-", "[_-]?") + "|kty|-----BEGIN");

    private ProseRedaction() {
    }

    /** {@code text}, not one JSON value, at JSON-in-string level {@code level}, redacted. */
    static String redact(String text, int level) {
        boolean read = level < JsonRedaction.MAX_LEVELS && text.length() <= JsonRedaction.MAX_CHARS;
        List<int[]> spans = new ArrayList<>();
        List<String> values = new ArrayList<>();
        int failed = -1;
        char[] chars = read ? text.toCharArray() : null;
        long budget = 2L * text.length() + 4096;
        for (int at = nextStart(text, 0); at >= 0; ) {
            if (read && budget > 0 && spans.size() < BASE * BASE) {
                int end = JsonRedaction.valueEnd(chars, at, level);
                if (end < 0) {
                    budget -= Math.max(1, ~end - at);
                } else {
                    String value = redactedValue(text.substring(at, end), level);
                    if (value != null) {
                        spans.add(new int[] {at, end});
                        values.add(value);
                        at = nextStart(text, end);
                        continue;
                    }
                }
            }
            if (failed < 0 && looksLikeJson(text, at)) {
                failed = at;
            }
            at = nextStart(text, at + 1);
        }
        if (!spans.isEmpty() && holdsPlaceholderCharacters(text)) {
            // A placeholder could not be told apart from the text: fail closed.
            return hasVocabulary(text) ? Redactor.MASK : text;
        }
        StringBuilder prose = new StringBuilder(text.length());
        int copied = 0;
        int proseFailed = -1;
        for (int i = 0; i < spans.size(); i++) {
            int[] span = spans.get(i);
            if (failed >= 0 && proseFailed < 0 && span[0] > failed) {
                proseFailed = prose.length() + (failed - copied);
            }
            prose.append(text, copied, span[0]).append('{').append(HOLE)
                    .append((char) (FIRST_DIGIT + i / BASE)).append((char) (FIRST_DIGIT + i % BASE)).append('}');
            copied = span[1];
        }
        if (failed >= 0 && proseFailed < 0) {
            proseFailed = prose.length() + (failed - copied);
        }
        prose.append(text, copied, text.length());
        boolean maskTail = proseFailed >= 0 && hasVocabulary(text.substring(failed));
        String head = maskTail ? prose.substring(0, proseFailed) : prose.toString();
        String out = Redactor.redact(head, null);
        if (!settled(out)) {
            return Redactor.MASK;
        }
        String restored = restore(out, values);
        if (restored == null) {
            return Redactor.MASK;
        }
        return maskTail ? restored + Redactor.MASK : restored;
    }

    /** The JSON value {@code json} redacted on the tree, or {@code null} if that path will not read it. */
    private static String redactedValue(String json, int level) {
        try {
            return JsonRedaction.redact(json, level);
        } catch (JsonRedaction.Unreadable unreadable) {
            return null;
        }
    }

    /** Where the next {@code {} or {@code [} from {@code from} in {@code text} is, or -1. */
    private static int nextStart(String text, int from) {
        for (int i = from; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{' || c == '[') {
                return i;
            }
        }
        return -1;
    }

    /**
     * Whether the {@code {} or {@code [} at {@code at} looks like the start of JSON: after JSON whitespace, an object's
     * name or end ({@code "}, {@code '}, a backslash that may escape a quote, or {@code }}), or an array's first item
     * or end (also a bracket, a brace, a digit or a minus). A {@code [INFO]} or {@code {code}} in prose does not.
     */
    static boolean looksLikeJson(String text, int at) {
        int i = at + 1;
        while (i < text.length() && " \t\r\n".indexOf(text.charAt(i)) >= 0) {
            i++;
        }
        if (i == text.length()) {
            return true;
        }
        char c = text.charAt(i);
        if (c == '"' || c == '\'' || c == '\\') {
            return true;
        }
        if (text.charAt(at) == '{') {
            return c == '}';
        }
        return c == ']' || c == '[' || c == '{' || c == '-' || (c >= '0' && c <= '9');
    }

    /**
     * Whether {@code text}, or any decoding of its JSON escapes ({@link JsonRedaction#unescaped}, one level at a time),
     * holds secret vocabulary ({@link #VOCABULARY}) or anything the text rules mask. A text whose escapes still decode
     * after {@link JsonRedaction#MAX_KEY_LEVELS} levels counts as holding it.
     */
    static boolean hasVocabulary(String text) {
        String pass = text;
        for (int level = 0; ; level++) {
            if (VOCABULARY.matcher(pass).find() || !Redactor.redact(pass, null).equals(pass)) {
                return true;
            }
            String next = JsonRedaction.unescaped(pass);
            if (next == null) {
                return false;
            }
            if (level + 1 > JsonRedaction.MAX_KEY_LEVELS) {
                return true;
            }
            pass = next;
        }
    }

    /**
     * Whether no decoding of {@code out}'s JSON escapes, one level at a time, holds anything the text rules mask: the
     * text rules' output, read at every escape level below the one they read. A text whose escapes still decode after
     * {@link JsonRedaction#MAX_KEY_LEVELS} levels is not settled.
     */
    static boolean settled(String out) {
        String pass = out;
        for (int level = 0; ; level++) {
            String next = JsonRedaction.unescaped(pass);
            if (next == null) {
                return true;
            }
            if (level + 1 > JsonRedaction.MAX_KEY_LEVELS || !Redactor.redact(next, null).equals(next)) {
                return false;
            }
            pass = next;
        }
    }

    /** Whether {@code text} holds a character a placeholder uses. */
    private static boolean holdsPlaceholderCharacters(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (isPlaceholderCharacter(text.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPlaceholderCharacter(char c) {
        return c >= HOLE && c <= '';
    }

    /**
     * {@code out} with each placeholder the text rules kept replaced by its value, or {@code null} if a placeholder was
     * cut, repeated or moved: each must be whole, in order, or gone with a mask.
     */
    private static String restore(String out, List<String> values) {
        StringBuilder restored = null;
        int copied = 0;
        int last = -1;
        for (int i = 0; i < out.length(); i++) {
            if (!isPlaceholderCharacter(out.charAt(i))) {
                continue;
            }
            if (out.charAt(i) != HOLE || i == 0 || out.charAt(i - 1) != '{' || i + HOLE_LENGTH - 1 > out.length()
                    || out.charAt(i + HOLE_LENGTH - 2) != '}') {
                return null;
            }
            int high = out.charAt(i + 1) - FIRST_DIGIT;
            int low = out.charAt(i + 2) - FIRST_DIGIT;
            if (high < 0 || high >= BASE || low < 0 || low >= BASE) {
                return null;
            }
            int index = high * BASE + low;
            if (index <= last || index >= values.size()) {
                return null;
            }
            last = index;
            if (restored == null) {
                restored = new StringBuilder(out.length());
            }
            restored.append(out, copied, i - 1).append(values.get(index));
            copied = i + HOLE_LENGTH - 1;
            i = copied - 1;
        }
        return restored == null ? out : restored.append(out, copied, out.length()).toString();
    }
}
