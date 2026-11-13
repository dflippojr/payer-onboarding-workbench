package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One reading of the JWK private members in a text that holds however the text spells their quotes, their whitespace
 * and the letters of their names (#352, security round 2). The Redactor's other readings each read one escape level
 * exactly; this one decodes every escape once, to a canonical form, and reads the JWKs there, so it is a backstop that
 * fails closed: a value that reading finds and the others leave whole or in part is masked here. It cannot replace
 * them, because the canonical form no longer tells one level from another: a value holding a quote of a deeper level
 * may end early in it, and only the exact readings bound that value.
 *
 * <p>The canonical form, which replay/test/leaks.mjs implements separately to the same rules:
 * <ul>
 * <li>The text is read up to the first line break inside a string of its level that opens where prose or a value starts
 * at that level, and not in a member's place ({@link #readable}).</li>
 * <li>A backslash starts an escape. Its backslash may be spelled as a run of backslashes and unicode escapes of a
 * backslash ({@code u005c} after a backslash), so an escape of any level, or chained through such escapes, is one
 * escape. After that run: {@code u} and four hex digits is that character; {@code n}, {@code r}, {@code t} or
 * {@code f} is whitespace; any other character is itself; nothing (the end of the text) is nothing.</li>
 * <li>A quote, plain or escaped, is a quote. Every character {@link Character#isWhitespace} reads, raw or escaped, is a
 * space.</li>
 * <li>A name is a quote after an object's opening bracket or a comma (spaces aside), 1 to 64 of {@code [A-Za-z_-]},
 * a quote, spaces and a colon. Each quote must decode to a quote of some level, and a letter the text spells as an
 * escape counts only if it is that letter at the level of the name's quotes ({@code "\\u0064"} in plain JSON is not
 * d). A kty counts only with a string value.</li>
 * <li>A private member is a name in {@link Redactor#JWK_PRIVATE_MEMBERS}; it is a JWK's when its object holds a kty,
 * the brackets read two ways: every bracket counted, or those inside strings skipped, a string closing at the first
 * quote that spaces and then a comma, a closing bracket, a colon or the end follow. Either way is enough, with a kty
 * whose quote is at the member's level ({@link #memberLevel}).</li>
 * <li>A member's value starts after spaces. A string closes at the first quote that spaces and quotes and then a comma,
 * a closing bracket, a colon or the end follow; it is masked unless it reads {@link Redactor#MASK} or nothing, and one
 * that never closes is masked to the end of the text. An object or array is masked to the bracket closing it, the
 * further of the two readings, or to the end of the text; a number, {@code true} or {@code false} is masked whole.
 * A quote deeper than the value's opening one ({@link #closeLevel}) closes nothing. Anything else (a bare word, a
 * second colon) is no value and is kept, as the other readings keep it. A mask is quoted
 * as the member's name opens, so it reads as a string at the name's level however the value was quoted.</li>
 * </ul>
 * Each step reads each character a fixed number of times, so the work is linear in the text's length.
 */
final class CanonicalJwks {

    /**
     * A stretch of the text to replace: where it starts and ends, what replaces it, and where the value's content
     * starts and ends in it (a string's without its quotes).
     */
    record Value(int start, int end, String replacement, int contentStart, int contentEnd) {
    }

    private static final char BACKSLASH = (char) 92;

    /**
     * Matches wherever the canonical form may spell kty: each letter plain or an escape of it, its backslash run before
     * it.
     * A text it does not match holds no JWK, and is read no further.
     */
    private static final Pattern KTY = Pattern.compile(
            "(?:k|u006[bB])(?:\\\\|u005[cC])*+(?:t|u0074)(?:\\\\|u005[cC])*+(?:y|u0079)");

    private static final Pattern SCALAR = Pattern.compile("-?\\d[\\d.eE+-]*|true\\b|false\\b");

    private CanonicalJwks() {
    }

    /** The canonical form of a text, and where each of its characters starts in the text (one longer, to its end). */
    static final class Canonical {

        private final String text;
        private final int[] origin;

        Canonical(String text, int[] origin) {
            this.text = text;
            this.origin = origin;
        }

        String text() {
            return text;
        }

        /** Where character {@code k} of the canonical form starts in the text ({@code k} up to its length). */
        int at(int k) {
            return origin[k];
        }

        /** How the text spells character {@code k} of the canonical form. */
        String spelling(String raw, int k) {
            return raw.substring(origin[k], origin[k + 1]);
        }
    }

    /**
     * A name the canonical reading finds: where its opening quote is and its value starts in the canonical form, whether
     * it is a kty, and its quote's level as {@link #flatLevel} reads it.
     */
    private record Name(int quote, int value, boolean kty, int level) {
    }

    /** What {@link #flatLevel} gives for a quote of a spelling it does not place: it goes with a name of any level. */
    private static final int ANY_LEVEL = -1;

    static Canonical canonical(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        int[] origin = new int[raw.length() + 1];
        int i = 0;
        while (i < raw.length()) {
            int start = i;
            char c = raw.charAt(i);
            char emit;
            if (c == BACKSLASH) {
                int j = i + 1;
                while (j < raw.length()) {
                    if (raw.charAt(j) == BACKSLASH) {
                        j++;
                    } else if (raw.charAt(j) == 'u' && raw.regionMatches(true, j + 1, "005c", 0, 4)) {
                        j += 5;
                    } else {
                        break;
                    }
                }
                if (j >= raw.length()) {
                    break;
                }
                char escaped = raw.charAt(j);
                if (escaped == 'u' && isHex(raw, j + 1)) {
                    char decoded = (char) Integer.parseInt(raw.substring(j + 1, j + 5), 16);
                    emit = Character.isWhitespace(decoded) ? ' ' : decoded;
                    i = j + 5;
                } else {
                    emit = "nrtf".indexOf(escaped) >= 0 || Character.isWhitespace(escaped) ? ' ' : escaped;
                    i = j + 1;
                }
            } else {
                emit = Character.isWhitespace(c) ? ' ' : c;
                i++;
            }
            origin[out.length()] = start;
            out.append(emit);
        }
        origin[out.length()] = raw.length();
        return new Canonical(out.toString(), Arrays.copyOf(origin, out.length() + 1));
    }

    private static boolean isHex(String raw, int from) {
        if (from + 4 > raw.length()) {
            return false;
        }
        for (int k = from; k < from + 4; k++) {
            char c = raw.charAt(k);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
                return false;
            }
        }
        return true;
    }

    /** Every JWK private member's value in {@code raw} that the canonical reading masks, as stretches of the text. */
    static List<Value> privateValues(String raw) {
        List<Value> values = new ArrayList<>();
        String read = raw.substring(0, readable(raw));
        if (read.indexOf('"') < 0 && !read.toLowerCase(java.util.Locale.ROOT).contains("u0022")
                || !KTY.matcher(read).find()) {
            return values;
        }
        Canonical canonical = canonical(read);
        int[] inStrings = openLevels(read);
        String t = canonical.text();
        int n = t.length();
        List<Name> names = new ArrayList<>();
        for (int q = t.indexOf('"'); q >= 0; q = t.indexOf('"', q + 1)) {
            int k = q + 1;
            while (k < n && k - q <= 64 && isNameChar(t.charAt(k))) {
                k++;
            }
            if (k == q + 1 || k >= n || t.charAt(k) != '"' || !inMemberPlace(t, q)) {
                continue;
            }
            String name = t.substring(q + 1, k);
            boolean kty = name.equals("kty");
            if (!kty && !Redactor.JWK_PRIVATE_MEMBERS.contains(name) || !lettersAtItsLevel(raw, canonical, q, k)) {
                continue;
            }
            int colon = afterSpace(t, k + 1);
            if (colon >= n || t.charAt(colon) != ':') {
                continue;
            }
            int value = afterSpace(t, colon + 1);
            if (!kty || value < n && t.charAt(value) == '"') {
                names.add(new Name(q, value, kty, memberLevel(canonical.spelling(raw, q), inStrings[canonical.at(q)])));
            }
        }
        if (names.isEmpty()) {
            return values;
        }
        // Whether spaces then a comma, a closing bracket, a colon or the end follow (a string's close for the lexed
        // reading), and whether spaces and quotes then a comma, a closing bracket, a colon or the end follow (a value's
        // close).
        boolean[] lexEnd = new boolean[n + 1];
        boolean[] valueEnd = new boolean[n + 1];
        lexEnd[n] = true;
        valueEnd[n] = true;
        for (int i = n - 1; i >= 0; i--) {
            char c = t.charAt(i);
            lexEnd[i] = c == ' ' ? lexEnd[i + 1] : ",}]:".indexOf(c) >= 0;
            valueEnd[i] = c == ' ' || c == '"' ? valueEnd[i + 1] : ",}]:".indexOf(c) >= 0;
        }
        // The first quote from each place that closes a string in the lexed reading, and a value.
        int[] nextLexClose = new int[n + 1];
        int[] nextValueClose = new int[n + 1];
        nextLexClose[n] = n;
        nextValueClose[n] = n;
        for (int i = n - 1; i >= 0; i--) {
            boolean quote = t.charAt(i) == '"';
            nextLexClose[i] = quote && lexEnd[i + 1] ? i : nextLexClose[i + 1];
            nextValueClose[i] = quote && valueEnd[i + 1] ? i : nextValueClose[i + 1];
        }
        boolean[] jwk = new boolean[names.size()];
        int[] counted = brackets(t, names, jwk, null);
        int[] lexed = brackets(t, names, jwk, nextLexClose);
        Matcher scalar = SCALAR.matcher(t);
        // Where the last string value read ends: a name before it is inside that value, which is masked or the mask.
        int readTo = 0;
        for (int j = 0; j < names.size(); j++) {
            Name name = names.get(j);
            int v = name.value();
            if (!jwk[j] || name.kty() || v >= n || name.quote() < readTo) {
                continue;
            }
            String quote = canonical.spelling(raw, name.quote());
            char c = t.charAt(v);
            if (c == '"') {
                // A quote deeper than the opening one is an escaped quote inside the value, which goes on past it.
                int open = closeLevel(canonical.spelling(raw, v));
                int close = nextValueClose[v + 1];
                while (close < n && closeLevel(canonical.spelling(raw, close)) > open) {
                    close = nextValueClose[close + 1];
                }
                readTo = close + 1;
                if (close >= n) {
                    values.add(new Value(canonical.at(v), raw.length(), quote + Redactor.MASK + quote,
                            canonical.at(v + 1), raw.length()));
                } else {
                    String content = t.substring(v + 1, close);
                    if (!content.isEmpty() && !content.equals(Redactor.MASK)) {
                        values.add(new Value(canonical.at(v), canonical.at(close + 1), quote + Redactor.MASK + quote,
                                canonical.at(v + 1), canonical.at(close)));
                    }
                }
            } else if (c == '{' || c == '[') {
                int end = Math.max(counted[v], lexed[v]);
                int stop = end < 0 ? raw.length() : canonical.at(end + 1);
                values.add(new Value(canonical.at(v), stop, quote + Redactor.MASK + quote, canonical.at(v), stop));
            } else if (scalar.region(v, n).lookingAt()) {
                int stop = canonical.at(scalar.end());
                values.add(new Value(canonical.at(v), stop, quote + Redactor.MASK + quote, canonical.at(v), stop));
            }
        }
        return values;
    }

    /**
     * Reads the brackets of the canonical text {@code t}: every bracket counted, or, with {@code nextClose}, those
     * outside strings, a string closing at {@code nextClose} of the place after its opening quote. Marks in {@code jwk}
     * each private member whose object holds a kty name in this reading, and returns where the bracket closing each
     * opening bracket is (-1: none, or not read as a bracket).
     */
    private static int[] brackets(String t, List<Name> names, boolean[] jwk, int[] nextClose) {
        int n = t.length();
        int[] match = new int[n];
        Arrays.fill(match, -1);
        int[] stack = new int[n];
        int top = 0;
        int[] owner = new int[names.size()];
        Arrays.fill(owner, -1);
        // For each object a kty is in: the levels of its kty names, one bit each, the top bit for ANY_LEVEL.
        java.util.Map<Integer, Long> typed = new java.util.HashMap<>();
        int next = 0;
        int i = 0;
        while (i < n) {
            while (next < names.size() && names.get(next).quote() < i) {
                next++;
            }
            if (next < names.size() && names.get(next).quote() == i) {
                owner[next] = top > 0 && t.charAt(stack[top - 1]) == '{' ? stack[top - 1] : -1;
                if (names.get(next).kty() && owner[next] >= 0) {
                    typed.merge(owner[next], levelBit(names.get(next).level()), (a, b) -> a | b);
                }
                next++;
            }
            char c = t.charAt(i);
            if (c == '{' || c == '[') {
                stack[top++] = i;
            } else if ((c == '}' || c == ']') && top > 0) {
                match[stack[--top]] = i;
            } else if (c == '"' && nextClose != null) {
                i = nextClose[i + 1] + 1;
                continue;
            }
            i++;
        }
        for (int j = 0; j < names.size(); j++) {
            long levels = owner[j] >= 0 ? typed.getOrDefault(owner[j], 0L) : 0L;
            int level = names.get(j).level();
            if ((levels & (levelBit(level) | levelBit(ANY_LEVEL))) != 0 || level == ANY_LEVEL && levels != 0) {
                jwk[j] = true;
            }
        }
        return match;
    }

    /**
     * How much of {@code raw} the canonical reading reads: up to the first line break inside a string, at any level,
     * that a quote of that level opens, or all of it (#342). A level is the run of backslashes before its quotes: none
     * for plain JSON, one for JSON embedded in a JSON string, three below that; its line break is a raw one at level 0
     * and an {@code n} or {@code r} after that run below it. Each level's strings open and close at its own quotes, a
     * run of any other length being content. JSON holds no line break in a string, so what follows one is prose quoting
     * a copy, which the exact readings decide on and keep; the canonical form, blind to levels, could not tell that
     * copy from JSON. Only a string opening where prose or a value starts at its level counts: after the start,
     * whitespace (raw, or escaped below level 0), a colon, an array's opening bracket, or the quote of a shallower
     * level opening the string that holds it. One opening in a member's place (after an object's opening bracket or a
     * comma) is a name, closed by a quote of another spelling, whose line break is whitespace before its colon; one
     * opening right after other text is the rest of a value.
     */
    private static int readable(String raw) {
        // For each level (run) a string is open at: whether its line breaks are read past.
        java.util.Map<Integer, Boolean> open = new java.util.HashMap<>();
        // The last character before here that is no whitespace at any level, and no backslash.
        char last = 0;
        // Whether the token before this one is where prose or a value may start (the start of the text, whitespace at
        // any level, a colon, an array's opening bracket), and the run of the quote it was, if it was one (else -1).
        boolean starts = true;
        int quoteRun = -1;
        int i = 0;
        while (i < raw.length()) {
            int run = 0;
            while (i + run < raw.length() && raw.charAt(i + run) == BACKSLASH) {
                run++;
            }
            if (i + run >= raw.length()) {
                break;
            }
            char c = raw.charAt(i + run);
            boolean space = run == 0 ? Character.isWhitespace(c) : run % 2 == 1 && "nrtf".indexOf(c) >= 0;
            if (c == '"') {
                if (open.containsKey(run)) {
                    open.remove(run);
                } else {
                    // Only a string opening where prose or a value starts, at its level, may be prose quoting a copy:
                    // after the start, whitespace, a colon, an array's opening bracket or the quote opening the string
                    // that holds its level; never right after other text, nor in a member's place.
                    boolean prose = starts || quoteRun >= 0 && quoteRun < run;
                    open.put(run, !prose || last == '{' || last == ',');
                }
            } else if (run == 0 ? c == '\n' || c == '\r' || c == 0x85 || c == 0x2028 || c == 0x2029
                    : run % 2 == 1 && (c == 'n' || c == 'r')) {
                if (Boolean.FALSE.equals(open.get(run))) {
                    return i;
                }
            }
            if (!space && (run == 0 || c == '"')) {
                last = c;
            }
            starts = space || run == 0 && (c == ':' || c == '[');
            quoteRun = c == '"' ? run : -1;
            i += run + 1;
        }
        return raw.length();
    }

    /** Whether the name opening at {@code q} in {@code t} follows an object's opening bracket or a comma. */
    private static boolean inMemberPlace(String t, int q) {
        int i = q - 1;
        while (i >= 0 && t.charAt(i) == ' ') {
            i--;
        }
        return i >= 0 && (t.charAt(i) == '{' || t.charAt(i) == ',');
    }

    /**
     * Whether the quotes at {@code open} and {@code close} of the canonical form are each a quote of some level ({@link
     * #nameQuoteLevel}), and every letter the text spells as an escape between them is that letter at the name's level:
     * decoded by the time the deeper of the two quotes' levels reads its content. {@code "\\u0064"} in plain JSON is a
     * backslash and {@code u0064}, not d; in JSON embedded in a JSON string it is d.
     */
    private static boolean lettersAtItsLevel(String raw, Canonical canonical, int open, int close) {
        int a = nameQuoteLevel(canonical.spelling(raw, open));
        int b = nameQuoteLevel(canonical.spelling(raw, close));
        if (a == NO_QUOTE || b == NO_QUOTE) {
            return false;
        }
        int level = Math.max(a, b);
        for (int k = open + 1; k < close; k++) {
            String spelling = canonical.spelling(raw, k);
            if (spelling.length() > 1 && level != Integer.MAX_VALUE && letterLevel(spelling) > level + 1) {
                return false;
            }
        }
        return true;
    }

    /** What {@link #nameQuoteLevel} gives for a spelling that decodes to something other than a quote. */
    private static final int NO_QUOTE = -1;

    /**
     * At which level a name's quote, as the text spells it, is a quote: how many times it is decoded as JSON string
     * content to get there; {@link Integer#MAX_VALUE} for a chain still decoding past {@link Redactor#NESTED_LEVELS} (a
     * quote of every level, fail closed); {@link #NO_QUOTE} for one that decodes to something else or not at all
     * ({@code \\"}: an escaped backslash and a quote of the level above, not a quote of one level).
     */
    private static int nameQuoteLevel(String spelling) {
        String s = spelling;
        for (int level = 0; level <= Redactor.NESTED_LEVELS; level++) {
            if (s.equals("\"")) {
                return level;
            }
            s = Redactor.unescapedOnce(s);
            if (s == null || s.isEmpty()) {
                return NO_QUOTE;
            }
        }
        return Integer.MAX_VALUE;
    }

    /** At which level {@code spelling}, an escape, reads as one character: how many decodings it takes to get there. */
    private static int letterLevel(String spelling) {
        String s = spelling;
        for (int level = 0; level <= Redactor.NESTED_LEVELS && s != null; level++) {
            if (s.length() == 1) {
                return level;
            }
            s = Redactor.unescapedOnce(s);
        }
        return Integer.MAX_VALUE;
    }

    /**
     * The level of a name whose opening quote the text spells {@code spelling}, with {@code open} the levels at which a
     * string is open there ({@link #openLevels}): its {@link #flatLevel}, one deeper for a quote spelled as a unicode
     * escape inside a string of its level, where it is a quote of the level below ({@code "x,\\u0022kty\\u0022:..."} is
     * a note's text, not a member), as it is not in a copied JWK, outside any string of its level (#352).
     */
    private static int memberLevel(String spelling, int open) {
        int level = flatLevel(spelling);
        boolean unicode = spelling.charAt(spelling.length() - 1) != '"';
        return unicode && level >= 0 && level < 31 && (open & (1 << level)) != 0 ? level + 1 : level;
    }

    /**
     * For each place in {@code read}, the levels at which a string is open there, one bit each: a level's strings open
     * and close at its plain quotes, after {@code 2^L - 1} backslashes, a run of any other length being content.
     */
    private static int[] openLevels(String read) {
        int[] open = new int[read.length() + 1];
        int levels = 0;
        int i = 0;
        while (i < read.length()) {
            int run = 0;
            while (i + run < read.length() && read.charAt(i + run) == BACKSLASH) {
                run++;
            }
            int stop = Math.min(i + run + 1, read.length());
            Arrays.fill(open, i, stop, levels);
            if (i + run < read.length() && read.charAt(i + run) == '"' && Integer.bitCount(run + 1) == 1 && run < 31) {
                levels ^= 1 << Integer.numberOfTrailingZeros(run + 1);
            }
            i = stop;
        }
        open[read.length()] = levels;
        return open;
    }

    private static long levelBit(int level) {
        return level == ANY_LEVEL || level >= 63 ? Long.MIN_VALUE : 1L << level;
    }

    /**
     * The level of a name's quote as a JSON text quoted inside JSON strings spells it, a unicode escape of a quote counting
     * as a quote of the level it is written at (as #352 reads a copied JWK): a plain quote after {@code 2^L - 1}
     * backslashes is level L; {@code \\u0022}, also with its backslash spelled as {@code u005c} escapes, is level 0, and
     * level L + 1 with its backslash escaped as a backslash at level L. A kty counts for a private member only at the
     * member's level, so {@code \\"kty\\"} inside a string of a plain-quoted object is no member of it. Any other
     * spelling is {@link #ANY_LEVEL} (fail closed).
     */
    static int flatLevel(String spelling) {
        int k = 0;
        while (k < spelling.length() && spelling.charAt(k) == BACKSLASH) {
            k++;
        }
        String rest = spelling.substring(k).toLowerCase(java.util.Locale.ROOT);
        if (rest.equals("\"")) {
            return Integer.bitCount(k + 1) == 1 ? Integer.numberOfTrailingZeros(k + 1) : ANY_LEVEL;
        }
        if (!rest.matches("(?:u005c)*u0022")) {
            return ANY_LEVEL;
        }
        int level = 0;
        while (k > 1 && k % 2 == 0) {
            k /= 2;
            level++;
        }
        return k == 1 ? level : ANY_LEVEL;
    }

    /**
     * The level at which a value's quote is a quote ({@link #nameQuoteLevel}), for bounding the value: a quote of no level
     * (an escaped backslash, then a plain quote) is level 0, and a chain still decoding past the levels read is deeper
     * than any.
     */
    private static int closeLevel(String spelling) {
        int level = nameQuoteLevel(spelling);
        return level == NO_QUOTE ? 0 : level;
    }

    private static boolean isNameChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-';
    }

    private static int afterSpace(String t, int from) {
        int i = from;
        while (i < t.length() && t.charAt(i) == ' ') {
            i++;
        }
        return i;
    }
}
