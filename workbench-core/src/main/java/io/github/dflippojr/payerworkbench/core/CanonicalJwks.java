package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntBinaryOperator;
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
 * <li>A line break inside a string of its level that opens where prose or a value starts at that level, and not in a
 * member's place, is skipped from, to the string holding that level's close, or at level 0 to the end
 * ({@link #skipped}).</li>
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
 * whose quote is at the member's level ({@link #memberLevel}), or for a private member at its quote's level as
 * written.</li>
 * <li>A member's value starts after spaces. A string closes at the first quote that spaces and quotes and then a comma,
 * a closing bracket, a colon or the end follow; it is masked unless it reads {@link Redactor#MASK} or nothing, and one
 * that never closes is masked to the end of the text. An object or array is masked to the bracket closing it, the
 * further of the two readings, or to the end of the text; a number, {@code true} or {@code false} is masked whole.
 * A quote deeper than the value's opening one ({@link #closeLevel}) closes nothing. Anything else (a bare word, a
 * second colon) is no value and is kept, as the other readings keep it. A mask is quoted
 * as the member's name opens, so it reads as a string at the name's level however the value was quoted.</li>
 * </ul>
 * Each step reads each character a fixed number of times, so the work is linear in the text's length.
 *
 * <p>The bound (#352): this reading applies within {@link Redactor#NESTED_LEVELS} levels of JSON nested in strings and
 * of escaping (a quote chain decoding within that many levels), the levels the Redactor's readers read; at the last
 * level and past it the string holding the JWK, or the text, is masked whole, and the leak scanner flags it. Where the
 * quote reading is ambiguous it fails closed, never guesses: a quote deeper than a value's opening one is escaped inside
 * the value, both in its bounds and in the reading that counts every bracket, which skips the brackets after such a
 * quote; a value or structure that never closes is masked to the end; and a comma, brace or bracket spelled as an escape
 * that decodes deeper than the strings open around it is no delimiter of its level, so the string holding it, or the
 * text, is masked whole ({@link #ambiguous}). The scanner flags each of these, and flags a text whose reading spends its
 * scan budget.
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
     * it is a kty, its level ({@link #memberLevel}) and its quote's level as written ({@link #flatLevel}).
     */
    private record Name(int quote, int value, boolean kty, int level, int written) {
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
        if (raw.indexOf('"') < 0 && !raw.toLowerCase(java.util.Locale.ROOT).contains("u0022")
                || !KTY.matcher(raw).find()) {
            return values;
        }
        // The text without what the reading skips (skipped), and where each of its places is in the text.
        int[] skips = skipped(raw);
        StringBuilder kept = new StringBuilder(raw.length());
        int[] toRaw = new int[raw.length() + 1];
        int from = 0;
        for (int r = 0; r <= skips.length; r += 2) {
            int to = r < skips.length ? skips[r] : raw.length();
            for (int k = from; k < to; k++) {
                toRaw[kept.length()] = k;
                kept.append(raw.charAt(k));
            }
            from = r < skips.length ? skips[r + 1] : raw.length();
        }
        toRaw[kept.length()] = raw.length();
        String read = kept.toString();
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
            if (!kty && !Redactor.JWK_PRIVATE_MEMBERS.contains(name) || !lettersAtItsLevel(read, canonical, q, k)) {
                continue;
            }
            int colon = afterSpace(t, k + 1);
            if (colon >= n || t.charAt(colon) != ':') {
                continue;
            }
            int value = afterSpace(t, colon + 1);
            if (!kty || value < n && t.charAt(value) == '"') {
                String spelling = canonical.spelling(read, q);
                int open = inStrings[canonical.at(q)];
                int level = memberLevel(spelling, open);
                // A kty whose quote no rule places goes with every level, but only where no string is open around it.
                if (!kty || level != ANY_LEVEL || open == 0) {
                    names.add(new Name(q, value, kty, level, flatLevel(spelling)));
                }
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
        // Each quote's levels, read once: decoded (closeLevel) and as a copied JWK reads it (flatLevel). A quote deeper
        // than a string's opening one is escaped inside it, in the structural reading as in a value's bounds.
        int[] strict = new int[n];
        int[] flat = new int[n];
        for (int k = 0; k < n; k++) {
            if (t.charAt(k) == '"') {
                String spelling = canonical.spelling(read, k);
                strict[k] = closeLevel(spelling);
                flat[k] = flatLevel(spelling);
            }
        }
        IntBinaryOperator deeper = (quote, opening) -> strict[quote] > strict[opening]
                || flat[quote] != ANY_LEVEL && flat[opening] != ANY_LEVEL && flat[quote] > flat[opening] ? 1 : 0;
        // Each private member's string value, bounded by its own quote level: the reading that counts every bracket
        // skips the brackets inside one past a quote escaped in it, so such a brace does not move the members after it.
        boolean[] inValue = new boolean[n];
        int valuesTo = 0;
        for (Name name : names) {
            int v = name.value();
            if (name.kty() || v >= n || v < valuesTo || t.charAt(v) != '"') {
                continue;
            }
            // Only past a quote read as escaped inside it (deeper than its opening one), where the reading is ambiguous.
            int close = nextValueClose[v + 1];
            int stepped = -1;
            while (close < n && deeper.applyAsInt(close, v) == 1) {
                stepped = stepped < 0 ? close : stepped;
                close = nextValueClose[close + 1];
            }
            if (stepped >= 0) {
                Arrays.fill(inValue, stepped, Math.min(close + 1, n), true);
            }
            valuesTo = close + 1;
        }
        boolean[] jwk = new boolean[names.size()];
        int[] counted = brackets(t, names, jwk, null, inValue);
        int[] lexed = brackets(t, names, jwk, nextLexClose, null);
        List<Value> wholesale = ambiguous(raw, read, canonical, toRaw, inStrings, names);
        if (!wholesale.isEmpty()) {
            return wholesale;
        }
        Matcher scalar = SCALAR.matcher(t);
        // Where the last string value read ends: a name before it is inside that value, which is masked or the mask.
        int readTo = 0;
        for (int j = 0; j < names.size(); j++) {
            Name name = names.get(j);
            int v = name.value();
            if (!jwk[j] || name.kty() || v >= n || name.quote() < readTo) {
                continue;
            }
            String quote = canonical.spelling(read, name.quote());
            char c = t.charAt(v);
            if (c == '"') {
                // A quote deeper than the opening one is an escaped quote inside the value, which goes on past it.
                int close = nextValueClose[v + 1];
                while (close < n && deeper.applyAsInt(close, v) == 1) {
                    close = nextValueClose[close + 1];
                }
                readTo = close + 1;
                if (close >= n) {
                    values.add(new Value(toRaw[canonical.at(v)], raw.length(), quote + Redactor.MASK + quote,
                            toRaw[canonical.at(v + 1)], raw.length()));
                } else {
                    String content = t.substring(v + 1, close);
                    if (!content.isEmpty() && !content.equals(Redactor.MASK)) {
                        values.add(new Value(toRaw[canonical.at(v)], rawEnd(toRaw, canonical.at(close + 1)),
                                quote + Redactor.MASK + quote, toRaw[canonical.at(v + 1)],
                                rawEnd(toRaw, canonical.at(close))));
                    }
                }
            } else if (c == '{' || c == '[') {
                // Unclosed in either reading: masked to the end (fail closed).
                int end = counted[v] == -1 || lexed[v] == -1 ? -1 : Math.max(counted[v], lexed[v]);
                int stop = end < 0 ? raw.length() : rawEnd(toRaw, canonical.at(end + 1));
                values.add(new Value(toRaw[canonical.at(v)], stop, quote + Redactor.MASK + quote, toRaw[canonical.at(v)],
                        stop));
            } else if (scalar.region(v, n).lookingAt()) {
                int stop = rawEnd(toRaw, canonical.at(scalar.end()));
                values.add(new Value(toRaw[canonical.at(v)], stop, quote + Redactor.MASK + quote, toRaw[canonical.at(v)],
                        stop));
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
    private static int[] brackets(String t, List<Name> names, boolean[] jwk, int[] nextClose, boolean[] skip) {
        int n = t.length();
        int[] match = new int[n];
        Arrays.fill(match, -2);
        java.util.ArrayDeque<Integer> stack = new java.util.ArrayDeque<>();
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
                Integer top = stack.peek();
                owner[next] = top != null && t.charAt(top) == '{' ? top : -1;
                if (names.get(next).kty() && owner[next] >= 0) {
                    typed.merge(owner[next], levelBit(names.get(next).level()), (a, b) -> a | b);
                }
                next++;
            }
            char c = skip != null && skip[i] ? ' ' : t.charAt(i);
            if (c == '{' || c == '[') {
                stack.push(i);
                match[i] = -1;
            } else if ((c == '}' || c == ']') && !stack.isEmpty()) {
                match[stack.pop()] = i;
            } else if (c == '"' && nextClose != null) {
                i = nextClose[i + 1] + 1;
                continue;
            }
            i++;
        }
        // A private member goes with a kty at its level, or at its quote's level as written (fail closed: which strings
        // are open is read from plain quotes, which a text mixing spellings may set out of step).
        for (int j = 0; j < names.size(); j++) {
            long levels = owner[j] >= 0 ? typed.getOrDefault(owner[j], 0L) : 0L;
            Name name = names.get(j);
            if ((levels & (levelBit(name.level()) | levelBit(name.written()) | levelBit(ANY_LEVEL))) != 0
                    || (name.level() == ANY_LEVEL || name.written() == ANY_LEVEL) && levels != 0) {
                jwk[j] = true;
            }
        }
        return match;
    }

    /**
     * What the canonical reading skips of {@code raw}, as start and end pairs, in order: from each line break inside a
     * string, at any level, that a quote of that level opens, to the quote closing the string that holds that level (a
     * quote after fewer backslashes), where reading goes on; at level 0, to the end (#342). A level is the run of backslashes before its quotes: none
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
    private static int[] skipped(String raw) {
        List<Integer> skips = new ArrayList<>();
        // For each level (run) a string is open at: whether its line breaks are read past.
        java.util.Map<Integer, Boolean> open = new java.util.HashMap<>();
        // The last character before here that is no whitespace at any level, and no backslash.
        char last = 0;
        // Whether the token before this one is where prose or a value may start (the start of the text, whitespace at
        // any level, a colon, an array's opening bracket), and the run of the quote it was, if it was one (else -1).
        boolean starts = true;
        int quoteRun = -1;
        // Where the last read for a private member's name began (afterPrivateName).
        int[] floor = {0};
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
                    open.put(run, !prose || last == '{' || last == ',' || afterPrivateName(raw, i, floor));
                }
            } else if ((run == 0 ? c == '\n' || c == '\r' || c == 0x85 || c == 0x2028 || c == 0x2029
                    : run % 2 == 1 && (c == 'n' || c == 'r')) && Boolean.FALSE.equals(open.get(run))) {
                // Skipped to the quote closing the string that holds this level (a quote of a shorter run), or at level
                // 0 to the end.
                int end = run == 0 ? raw.length() : closingShallower(raw, i + run + 1, run);
                skips.add(i);
                skips.add(end);
                int skippedRun = run;
                open.keySet().removeIf(level -> level >= skippedRun);
                starts = false;
                quoteRun = -1;
                i = end;
                continue;
            }
            if (!space && (run == 0 || c == '"')) {
                last = c;
            }
            starts = space || run == 0 && (c == ':' || c == '[');
            quoteRun = c == '"' ? run : -1;
            i += run + 1;
        }
        return skips.stream().mapToInt(Integer::intValue).toArray();
    }

    /** A private member's name and colon, in the canonical form, with spaces around them. */
    private static final Pattern PRIVATE_NAME_COLON = Pattern.compile(" *\"(?:d|p|q|dp|dq|qi|oth|k)\" *: *");

    /**
     * Whether the string opening at {@code at} in {@code raw} opens right after a private member's name and colon, so it
     * is that member's value, read through, never prose quoting a copy: the text back to the comma or opening brace
     * before it, read in the canonical form ({@link #canonical}) from its last comma or brace there, is that name and colon, so every spelling of its
     * quotes, letters and whitespace reads as it does there. The read goes back no further than {@code floor[0]}, where
     * the last one began, and sets it to {@code at}, so each stretch is read once.
     */
    private static boolean afterPrivateName(String raw, int at, int[] floor) {
        int k = at - 1;
        while (k >= floor[0] && raw.charAt(k) != ',' && raw.charAt(k) != '{') {
            k--;
        }
        int from = Math.max(k + 1, floor[0]);
        floor[0] = at;
        // Delimiters are read once decoded: the name is what follows the last comma or brace of the canonical form.
        String name = canonical(raw.substring(from, at)).text();
        name = name.substring(Math.max(name.lastIndexOf(','), name.lastIndexOf('{')) + 1);
        return PRIVATE_NAME_COLON.matcher(name).matches();
    }

    /** Where in the text the stretch of the kept text ending at {@code end} ends: just after its last character. */
    private static int rawEnd(int[] toRaw, int end) {
        return end == 0 ? toRaw[0] : toRaw[end - 1] + 1;
    }

    /**
     * Where the first quote after fewer than {@code run} backslashes, or unicode escape of a quote of a shallower level,
     * starts, from {@code from} in {@code raw}, or its end.
     */
    private static int closingShallower(String raw, int from, int run) {
        int i = from;
        while (i < raw.length()) {
            int k = 0;
            while (i + k < raw.length() && raw.charAt(i + k) == BACKSLASH) {
                k++;
            }
            if (i + k < raw.length() && raw.charAt(i + k) == '"' && k < run) {
                return i;
            }
            // ...or a unicode escape of a quote of a shallower level than the run's (flatLevel).
            if (k > 0 && raw.regionMatches(true, i + k, "u0022", 0, 5)) {
                int level = flatLevel(raw.substring(i, i + k + 5));
                if (level >= 0 && level < Integer.numberOfTrailingZeros(run + 1)) {
                    return i;
                }
            }
            i += k + 1;
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
     * and close at its plain quotes, after {@code 2^L - 1} backslashes, a run of any other length being content; a
     * unicode escape of a quote of that level ({@link #flatLevel}) that a colon follows closes one too, when it opened in
     * a member's place (a name) and its level's next plain quote does not close it as a name.
     */
    private static int[] openLevels(String read) {
        int[] open = new int[read.length() + 1];
        int levels = 0;
        // The levels whose open string opened in a member's place, and the last character no whitespace nor backslash.
        int names = 0;
        char last = 0;
        // For each level: up to where the open name's own close was looked up, and whether it closes as a name.
        int[] intactUntil = new int[31];
        boolean[] intact = new boolean[31];
        int i = 0;
        while (i < read.length()) {
            int run = 0;
            while (i + run < read.length() && read.charAt(i + run) == BACKSLASH) {
                run++;
            }
            int stop = Math.min(i + run + 1, read.length());
            int level = -1;
            boolean unicode = false;
            if (i + run < read.length() && read.charAt(i + run) == '"') {
                level = Integer.bitCount(run + 1) == 1 ? Integer.numberOfTrailingZeros(run + 1) : -1;
            } else if (run > 0 && read.regionMatches(true, i + run, "u0022", 0, 5)) {
                stop = i + run + 5;
                level = flatLevel(read.substring(i, stop));
                unicode = true;
            }
            Arrays.fill(open, i, stop, levels);
            if (level >= 0 && level < 31) {
                int bit = 1 << level;
                // A plain quote opens or closes a string of its level; a unicode escape of one closes a string of its
                // level that a plain quote opened in a member's place when a colon follows it: a name spelled with both
                // ("note\\u0022:), never a value.
                if (!unicode) {
                    names = (levels & bit) == 0 && (last == '{' || last == ',') ? names | bit : names & ~bit;
                    levels ^= bit;
                } else if ((levels & bit) != 0 && (names & bit) != 0 && colonAfter(read, stop)) {
                    // ...unless the name closes with its own plain quote before a colon, which keeps it whole. Looked
                    // up once for each string, so each is read ahead once.
                    if (intactUntil[level] <= i) {
                        int close = nextPlainQuote(read, stop, level);
                        intactUntil[level] = close + 1;
                        intact[level] = close < read.length() && colonAfter(read, close + (1 << level));
                    }
                    if (!intact[level]) {
                        levels ^= bit;
                        names &= ~bit;
                    }
                }
            }
            if (level >= 0 || unicode) {
                last = '"';
            } else if (run == 0 && i < read.length() && !Character.isWhitespace(read.charAt(i))) {
                last = read.charAt(i);
            }
            i = stop;
        }
        open[read.length()] = levels;
        return open;
    }

    /** Where the next plain quote of {@code level} (after {@code 2^level - 1} backslashes) starts from {@code from}, or the end. */
    private static int nextPlainQuote(String read, int from, int level) {
        int want = (1 << level) - 1;
        int i = from;
        while (i < read.length()) {
            int run = 0;
            while (i + run < read.length() && read.charAt(i + run) == BACKSLASH) {
                run++;
            }
            if (i + run < read.length() && read.charAt(i + run) == '"' && run == want) {
                return i;
            }
            i += run + 1;
        }
        return read.length();
    }

    /** Whether a colon comes next from {@code from} in {@code read}, after whitespace, raw or escaped at any level. */
    private static boolean colonAfter(String read, int from) {
        int i = from;
        while (i < read.length()) {
            char c = read.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == BACKSLASH) {
                int k = i;
                while (k < read.length() && read.charAt(k) == BACKSLASH) {
                    k++;
                }
                if (k >= read.length() || "nrt".indexOf(read.charAt(k)) < 0) {
                    return false;
                }
                i = k + 1;
            } else {
                return c == ':';
            }
        }
        return false;
    }

    /**
     * The fail-closed reading where a delimiter reads ambiguously: a comma, brace or bracket the text spells as an escape
     * that decodes at a level deeper than the strings open around it is no delimiter of the level it is at, so where the
     * text holds both a kty and a private member name, the string holding such a delimiter at level 0 is masked whole, or
     * the text when no string holds it. Empty when nothing reads ambiguously.
     */
    private static List<Value> ambiguous(String raw, String read, Canonical canonical, int[] toRaw, int[] inStrings,
            List<Name> names) {
        List<Value> wholesale = new ArrayList<>();
        if (names.stream().noneMatch(Name::kty) || names.stream().allMatch(Name::kty)) {
            return wholesale;
        }
        String t = canonical.text();
        int[] strings = null;
        int span = 0;
        int masked = -1;
        // The last quote before here, and its level once read.
        int quote = -1;
        int quoteLevel = 0;
        int quoteRead = -1;
        for (int k = 0; k < t.length(); k++) {
            if (t.charAt(k) == '"') {
                quote = k;
                continue;
            }
            if (",{}[]".indexOf(t.charAt(k)) < 0 || canonical.at(k + 1) - canonical.at(k) == 1) {
                continue;
            }
            // The strings open around it: as the plain quotes read them, or as deep as the last quote before it decodes.
            int depth = Integer.bitCount(inStrings[canonical.at(k)]);
            if (quote >= 0) {
                if (quoteRead != quote) {
                    // A quote that opens a string adds its level; one that closes a string (a comma, a closing bracket or
                    // a colon follows it, spaces aside) leaves its level.
                    int after = quote + 1;
                    while (after < t.length() && t.charAt(after) == ' ') {
                        after++;
                    }
                    boolean closes = after >= t.length() || ",}]:".indexOf(t.charAt(after)) >= 0;
                    int level = nameQuoteLevel(canonical.spelling(read, quote));
                    quoteLevel = level == Integer.MAX_VALUE ? level : Math.max(0, level) + (closes ? 0 : 1);
                    quoteRead = quote;
                }
                depth = Math.max(depth, quoteLevel);
            }
            if (letterLevel(canonical.spelling(read, k)) <= depth) {
                continue;
            }
            int at = toRaw[canonical.at(k)];
            if (at < masked) {
                continue;
            }
            if (strings == null) {
                strings = plainStrings(raw);
            }
            // The delimiters come in order, so the strings are walked once, from where the last search stopped.
            while (span < strings.length && strings[span + 1] <= at) {
                span += 2;
            }
            int open = span < strings.length && strings[span] < at ? span : -1;
            if (open < 0) {
                wholesale.clear();
                wholesale.add(new Value(0, raw.length(), Redactor.MASK, 0, raw.length()));
                return wholesale;
            }
            wholesale.add(new Value(strings[open] + 1, strings[open + 1], Redactor.MASK, strings[open] + 1,
                    strings[open + 1]));
            masked = strings[open + 1];
        }
        return wholesale;
    }

    /**
     * The strings of {@code raw} at level 0, as pairs of where each opening quote and closing quote (or the end) is: a
     * plain quote opens or closes one, and inside one a backslash escapes the character after it.
     */
    private static int[] plainStrings(String raw) {
        List<Integer> spans = new ArrayList<>();
        int i = 0;
        while (i < raw.length()) {
            if (raw.charAt(i) != '"') {
                i++;
                continue;
            }
            int close = i + 1;
            while (close < raw.length() && raw.charAt(close) != '"') {
                close += raw.charAt(close) == BACKSLASH ? 2 : 1;
            }
            close = Math.min(close, raw.length());
            spans.add(i);
            spans.add(close);
            i = close + 1;
        }
        return spans.stream().mapToInt(Integer::intValue).toArray();
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
