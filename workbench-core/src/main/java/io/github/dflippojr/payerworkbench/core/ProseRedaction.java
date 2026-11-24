package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
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
 *       time) still holds a value the text rules meet as sensitive ({@link Redactor#meets}: a rule writes a mask over
 *       bytes that are not exactly the form it writes), the whole text is the mask. The text rules read only the
 *       plain spelling and JSON held in a string one level deep; this is what stands for every deeper escape level.
 * </ol>
 *
 * <p>Past {@link JsonRedaction#MAX_LEVELS} or {@link JsonRedaction#MAX_CHARS} no value is read, and every JSON-looking
 * start counts as one that does not read. Attempts that fail may read at most {@code 2n + 4096} characters in all of a
 * text of length {@code n}; past that, no more values are read, so the work stays linear.
 */
final class ProseRedaction {

    /** Starts a placeholder, after its opening brace; two digits and the closing brace follow. */
    private static final char HOLE = '\uE000';

    /** The first placeholder digit; the digits are {@code FIRST_DIGIT} to {@code \uEFFF}. */
    private static final char FIRST_DIGIT = '\uE001';

    /** The number of placeholder digits. */
    private static final int BASE = '\uEFFF' - FIRST_DIGIT + 1;

    /** The length of a placeholder: a brace, {@link #HOLE}, two digits and a brace. */
    private static final int HOLE_LENGTH = 5;

    /**
     * A secret name: a secret field name with any number of {@code _} or {@code -} around and between its letters, as
     * {@link Redactor#isSecretField} reads it, or a credential header name, in any case.
     */
    static final Pattern SECRET_NAME = Pattern.compile("(?i)" + Redactor.SECRET_FIELDS.stream()
            .map(name -> "[_-]*+" + String.join("[_-]*+", name.split("")) + "[_-]*+")
            .reduce((a, b) -> a + "|" + b).orElseThrow()
            + "|" + String.join("|", Redactor.SENSITIVE_HEADERS).replace("-", "[_-]?"));

    /** A JWK private member's name in quotes, which a JWK's {@code kty} makes secret. */
    private static final Pattern PRIVATE_NAME = Pattern.compile("\"(?:" + String.join("|", Redactor.JWK_PRIVATE_MEMBERS)
            + ")\\\\*\"");

    /**
     * What may lie between a name and its key separator, and between that and its value: quotes, whitespace (also any
     * Unicode space separator, which Java's {@code \\s} leaves out) and escapes
     * ({@code \\n}, a {@code \\u} escape, also spelling a quote or a colon), at any depth of backslashes.
     */
    private static final String GAP = "(?:[\\s\\p{Z}\u0085\"']|\\\\++(?:u[0-9A-Fa-f]{4}|[A-Za-z\"]))*+";

    /** A name's key separator, a colon or an equals sign, with the gap on both sides: the name is used as a key. */
    private static final Pattern TO_VALUE = Pattern.compile(GAP + "[:=]" + GAP);

    /**
     * A value that already is the mask, an {@code Authorization}-style scheme kept in front of it or not, and nothing
     * after it: the end, a delimiter, or a quote (one an odd run of backslashes escapes closes a string a level down).
     * Backslashes before a quote in an even run are content of the value, so the value is not the mask.
     */
    private static final Pattern MASKED = Pattern.compile("(?:[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*+ )?"
            + Pattern.quote(Redactor.MASK) + "(?=$|[\"',}\\]\\s]|(?:\\\\\\\\)*+\\\\(?:\"|u0022))");

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
        // Whether reading an embedded value met a sensitive value (Redactor#meets): the tree's secret-field rules read
        // names the text patterns cannot, so the fail-closed branch below asks the tree, not only the vocabulary.
        boolean[] valuesMet = {false};
        for (int at = nextStart(text, 0); at >= 0; ) {
            if (read && budget > 0 && spans.size() < BASE * BASE) {
                int end = JsonRedaction.valueEnd(chars, at, level);
                if (end < 0) {
                    budget -= Math.max(1, ~end - at);
                } else {
                    String json = text.substring(at, end);
                    String[] attempt = {null};
                    valuesMet[0] |= Redactor.meets(json.length(), () -> attempt[0] = redactedValue(json, level));
                    String value = attempt[0];
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
            // A placeholder could not be told apart from the text: fail closed. The text comes back as it came only when no
            // embedded value met a sensitive value and the text holds no vocabulary (automated review r1 on #412).
            return valuesMet[0] || hasVocabulary(text) ? Redactor.maskedWhole(text) : text;
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
        if (!settled(out, true)) {
            return Redactor.maskedWhole(text);
        }
        String restored = values.isEmpty() ? out : restore(out, values);
        if (restored == null) {
            return Redactor.maskedWhole(text);
        }
        if (maskTail) {
            Redactor.wrote(text.substring(failed), Redactor.MASK);
            return restored + Redactor.MASK;
        }
        return restored;
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
    static int nextStart(String text, int from) {
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
     * name or end ({@code "}, {@code '}, a backslash that may escape a quote, or {@code }}), or an array's string,
     * object, array or end. A {@code [INFO]}, a {@code [2026-11-23 ...]} or {@code [5f3a...]} in a log line, or a
     * {@code {code}} in prose does not: none holds a name a secret could follow.
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
        return text.charAt(at) == '{' ? c == '}' : c == ']' || c == '[' || c == '{';
    }

    /**
     * Whether {@code text}, or any decoding of its JSON escapes ({@link JsonRedaction#unescaped}, one level at a time),
     * holds secret vocabulary: an armor header, a secret name whose value is not already the mask ({@link #keyName}),
     * with a {@code kty} a JWK private member's quoted name so, or a value the text rules meet as sensitive ({@link #meetsSecret}). A text whose escapes still decode
     * after {@link JsonRedaction#MAX_KEY_LEVELS} levels counts as holding it.
     */
    static boolean hasVocabulary(String text) {
        String above = null;
        String pass = text;
        for (int level = 0; ; level++) {
            // As spelled, a name whose value already is the mask is the Redactor's own output read again; in a decoding,
            // where quotes of several levels meet, every name used as a key counts.
            boolean decoded = level > 0;
            if (pass.contains("-----BEGIN") || keyName(SECRET_NAME, pass, decoded)
                    || (pass.contains("kty") && keyName(PRIVATE_NAME, pass, decoded))
                    || (decoded ? Redactor.meetsInDecoding(above, pass, true) : meetsSecret(pass, true))) {
                return true;
            }
            String next = JsonRedaction.unescaped(pass);
            if (next == null) {
                return false;
            }
            if (level + 1 > JsonRedaction.MAX_KEY_LEVELS) {
                return true;
            }
            above = pass;
            pass = next;
        }
    }

    /**
     * Whether no decoding of {@code out}'s JSON escapes, one level at a time, holds a value the text rules meet as
     * sensitive ({@link #meetsSecret}), read at every escape level below the one they read. A text whose escapes still decode after
     * {@link JsonRedaction#MAX_KEY_LEVELS} levels is not settled. {@code jwkContext}: whether a {@code kty} name in a
     * decoding makes every JWK private member name in it a secret one, as it does for the text rules' own text; the
     * outermost output and a tree's are read without it, since their JWKs were read on the tree.
     */
    static boolean settled(String out, boolean jwkContext) {
        String pass = out;
        for (int level = 0; ; level++) {
            String next = JsonRedaction.unescaped(pass);
            if (next == null) {
                return true;
            }
            if (level + 1 > JsonRedaction.MAX_KEY_LEVELS || Redactor.meetsInDecoding(pass, next, jwkContext)) {
                return false;
            }
            pass = next;
        }
    }

    /**
     * Whether the text rules meet a sensitive value in {@code text} ({@link Redactor#meets}, #406 redesign): a rule
     * writes a mask over bytes that are not already exactly the form it writes. No comparison of the text before and
     * after decides it, so a secret value of punctuation, of masking markers or of whitespace counts as any other.
     */
    private static boolean meetsSecret(String text, boolean jwkContext) {
        return Redactor.meets(text.length(), () -> Redactor.textRules(text, null, jwkContext));
    }

    /**
     * Whether a name {@code names} finds in {@code text} is used as a key ({@link #TO_VALUE}: a colon or an equals sign
     * after it) whose value is not already the mask ({@link #MASKED}), or, with {@code evenMasked}, whatever its value. An output of the Redactor read again (an excerpt
     * of a redacted body in a finding's evidence, say) names secrets whose values are gone, and a name in prose
     * ("access_token present") is no key: neither is vocabulary a broken start hides. The text rules' own reading
     * ({@link #meetsSecret}) still counts every secret they would mask.
     */
    private static boolean keyName(Pattern names, String text, boolean evenMasked) {
        Matcher name = names.matcher(text);
        Matcher between = TO_VALUE.matcher(text);
        Matcher masked = MASKED.matcher(text);
        while (name.find()) {
            if (between.region(name.end(), text.length()).lookingAt()
                    && (evenMasked || !masked.region(between.end(), text.length()).lookingAt())) {
                return true;
            }
        }
        return false;
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
        return c >= HOLE && c <= '\uEFFF';
    }

    /**
     * {@code out} with each placeholder the text rules kept replaced by its value, or {@code null} if a placeholder was
     * cut, repeated or moved: each must be whole, in order, or gone with a mask.
     */
    static String restore(String out, List<String> values) {
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
