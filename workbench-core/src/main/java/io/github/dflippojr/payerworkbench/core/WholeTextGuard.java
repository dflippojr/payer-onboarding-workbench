package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The one rule for JWK private members when reading a text stops early (#360): wherever any exit, skip, cut-off,
 * budget, exception or ambiguous reading stops the complete canonical reading of a text, {@link Redactor} masks the
 * whole text. It replaces fixing each such path one at a time, which security rounds 3 to 6 on #356 showed misses the
 * next one. Over-masking is accepted; a miss is not.
 *
 * <p>The canonical reading of a text is strict JSON (RFC 8259) at level 0, and, level by level, the content of every
 * string in it that holds a quote at some escape level ({@link #mayHoldQuote}), which must be strict JSON in its turn:
 * so no quote is read two ways, no delimiter spelled as an escape is read where no string is open to decode it, and no
 * stretch is skipped as prose.
 * It reads {@link Redactor#NESTED_LEVELS} levels, 0 to {@code NESTED_LEVELS - 1}; a string that would need reading at
 * the last level or past it stops the reading. Every member of every object is kept, a repeated name included.
 *
 * <p>The rule applies to a text that may hold a JWK private member ({@link #mayHoldPrivateMember}): a {@code kty} name
 * and a quoted private member name, each in any spelling, at any escape level. Other texts hold no JWK, so nothing
 * here changes them. The leak scanner ({@code replay/test/leaks.mjs}) applies the same rule with code of its own.
 */
final class WholeTextGuard {

    /**
     * A {@code kty} name, each letter as itself or as the tail of a unicode escape, with any run of backslashes or
     * {@code u005c} escapes between them: it finds every spelling a reading at any level may decode to {@code kty}.
     */
    private static final Pattern KTY = Pattern.compile(
            "(?:k|u006[bB])(?:\\\\|u005[cC])*+(?:t|u0074)(?:\\\\|u005[cC])*+(?:y|u0079)");

    /**
     * The last character of a quote in any spelling ({@code "} or the tail of a {@code \\u0022} escape), one to three name
     * characters each plain or a unicode escape whose backslash may be spelled through backslashes and {@code u005c}
     * escapes (group 1), and a quote in any spelling ahead.
     */
    private static final Pattern QUOTED_NAME = Pattern.compile(
            "(?:\"|u0022)((?:[a-z]|\\\\(?:\\\\|u005[cC])*+u00[0-9A-Fa-f]{2}){1,3})(?=(?:\\\\|u005[cC])*+(?:\"|u0022))");

    /** A unicode escape inside a {@link #QUOTED_NAME} name: its last two hex digits are the character. */
    private static final Pattern NAME_ESCAPE = Pattern.compile("\\\\(?:\\\\|u005[cC])*+u00([0-9A-Fa-f]{2})");

    private WholeTextGuard() {
    }

    /**
     * Whether {@code text} may hold a JWK private member: a {@code kty} name and a quoted private member name, each in
     * any spelling, in the text or in it decoded loosely ({@link #looselyDecoded}) up to one level past the levels the
     * canonical reading reads. Loose decoding reads every escape, in a string or not, so a name whose own escape is
     * spelled as escapes a level up is found where it decodes. Only decoding that no longer changes the text decides
     * that it holds none: where decoding still changes it past those levels, neither name may have shown yet, so the
     * text may hold one.
     */
    static boolean mayHoldPrivateMember(String text) {
        boolean kty = false;
        boolean name = false;
        String view = text;
        for (int level = 0; level <= Redactor.NESTED_LEVELS + 1; level++) {
            kty = kty || KTY.matcher(view).find();
            name = name || holdsPrivateName(view);
            if (kty && name) {
                return true;
            }
            String next = view.indexOf('\\') < 0 ? view : looselyDecoded(view);
            if (next.equals(view)) {
                return false;
            }
            view = next;
        }
        // Decoding still changes the text past the levels read: undecided, so it may hold anything there.
        return true;
    }

    /** Whether {@code view} holds a {@link #QUOTED_NAME} that decodes to a private member name. */
    private static boolean holdsPrivateName(String view) {
        Matcher m = QUOTED_NAME.matcher(view);
        while (m.find()) {
            String name = NAME_ESCAPE.matcher(m.group(1)).replaceAll(e ->
                    String.valueOf((char) Integer.parseInt(e.group(1), 16)));
            if (Redactor.JWK_PRIVATE_MEMBERS.contains(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@code text} with every escape read once, wherever it is: a unicode escape as its character, a backslash before
     * {@code n}, {@code r}, {@code t}, {@code b} or {@code f} as that control character, before anything else as that
     * character. A backslash at the very end is kept.
     */
    static String looselyDecoded(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int n = text.length();
        int i = 0;
        while (i < n) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 == n) {
                out.append(c);
                i++;
                continue;
            }
            char next = text.charAt(i + 1);
            if (next == 'u' && i + 6 <= n && isHex(text, i + 2, i + 6)) {
                out.append((char) Integer.parseInt(text.substring(i + 2, i + 6), 16));
                i += 6;
                continue;
            }
            out.append(switch (next) {
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 't' -> '\t';
                case 'b' -> '\b';
                case 'f' -> '\f';
                default -> next;
            });
            i += 2;
        }
        return out.toString();
    }

    /** Whether {@code text} holds ASCII hex digits only from {@code from} to {@code to}, as a JSON unicode escape needs. */
    private static boolean isHex(String text, int from, int to) {
        for (int i = from; i < to; i++) {
            char c = text.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether {@code content} holds a quote, or one {@link #looselyDecoded} up to {@code levels} times does, or decoding
     * still changes it after that. Without a quote at any level it holds no JSON name at any level, so no member to read
     * and no string whose bounds a reading could shift.
     */
    static boolean mayHoldQuote(String content, int levels) {
        String view = content;
        for (int k = 0; k <= levels; k++) {
            if (view.indexOf('"') >= 0) {
                return true;
            }
            String next = view.indexOf('\\') < 0 ? view : looselyDecoded(view);
            if (next.equals(view)) {
                return false;
            }
            view = next;
        }
        return true;
    }

    /** Whether the canonical reading of {@code text} is complete: every level it needs reads as strict JSON. */
    static boolean readsCompletely(String text) {
        return reads(text, false);
    }

    /**
     * Whether the canonical reading of {@code text} is complete and every JWK private member it reads, at every level,
     * is masked: its value is the string {@link Redactor#MASK} (or {@code null}, which holds nothing). A JWK is an
     * object with a member named {@code kty}, its names read as JSON reads them.
     */
    static boolean readsMasked(String text) {
        return reads(text, true);
    }

    private static boolean reads(String text, boolean masked) {
        try {
            return new Reading(text, 0, masked).complete();
        } catch (RuntimeException | StackOverflowError e) {
            // An exception stops the reading too.
            return false;
        }
    }

    /** What a {@link Reading} has read: a string, an object or array, or a number, {@code true}, {@code false} or {@code null}. */
    private enum Kind { STRING, STRUCTURE, SCALAR, NULL }

    /** An object or array the {@link Reading} is inside. */
    private static final class Frame {
        final boolean object;
        boolean kty;
        boolean unmasked;
        String name;

        Frame(boolean object) {
            this.object = object;
        }
    }

    /** One level's strict JSON reading, without recursion through nested objects and arrays. */
    private static final class Reading {

        /** What {@link #value} did: read a value, opened an object or array, or found no JSON there. */
        private static final int READ = 0;
        private static final int OPENED = 1;
        private static final int FAILED = 2;

        private final String s;
        private final int level;
        private final boolean masked;
        private int i;
        private final Deque<Frame> open = new ArrayDeque<>();

        Reading(String s, int level, boolean masked) {
            this.s = s;
            this.level = level;
            this.masked = masked;
        }

        /** Whether the text is exactly one JSON value, every string in it that needs reading reads, and so on down. */
        boolean complete() {
            boolean expectValue = true;
            while (true) {
                if (expectValue) {
                    int read = value();
                    if (read == FAILED) {
                        return false;
                    }
                    if (read == OPENED) {
                        continue;
                    }
                    expectValue = false;
                }
                if (open.isEmpty()) {
                    space();
                    return i == s.length();
                }
                Frame top = open.peek();
                space();
                if (i >= s.length()) {
                    return false;
                }
                char c = s.charAt(i++);
                if (c == ',') {
                    if (top.object && !name()) {
                        return false;
                    }
                    expectValue = true;
                } else if (c == (top.object ? '}' : ']')) {
                    open.pop();
                    if (masked && top.kty && top.unmasked) {
                        return false;
                    }
                    read(Kind.STRUCTURE, null);
                } else {
                    return false;
                }
            }
        }

        /**
         * Reads one value ({@link #READ}), or opens a non-empty object or array ({@link #OPENED}), with an object's first
         * member's name read, so its first value comes next; or {@link #FAILED}.
         */
        private int value() {
            space();
            if (i >= s.length()) {
                return FAILED;
            }
            char c = s.charAt(i);
            if (c == '{' || c == '[') {
                i++;
                space();
                if (i < s.length() && s.charAt(i) == (c == '{' ? '}' : ']')) {
                    i++;
                    read(Kind.STRUCTURE, null);
                    return READ;
                }
                Frame frame = new Frame(c == '{');
                open.push(frame);
                return !frame.object || name() ? OPENED : FAILED;
            }
            boolean ok;
            if (c == '"') {
                String content = string();
                ok = content != null && nested(content);
                if (ok) {
                    read(Kind.STRING, content);
                }
            } else if (s.startsWith("null", i)) {
                i += 4;
                ok = true;
                read(Kind.NULL, null);
            } else if (s.startsWith("true", i) || s.startsWith("false", i)) {
                i += c == 't' ? 4 : 5;
                ok = true;
                read(Kind.SCALAR, null);
            } else {
                ok = number();
                read(Kind.SCALAR, null);
            }
            return ok ? READ : FAILED;
        }

        /** Reads a member name and its colon, for the object on top. */
        private boolean name() {
            space();
            if (i >= s.length() || s.charAt(i) != '"') {
                return false;
            }
            String name = string();
            if (name == null || !nested(name)) {
                return false;
            }
            space();
            if (i >= s.length() || s.charAt(i) != ':') {
                return false;
            }
            i++;
            open.peek().name = name;
            return true;
        }

        /** Records a value read, as the current member of the object on top. */
        private void read(Kind kind, String content) {
            Frame top = open.peek();
            if (top != null && top.object) {
                if ("kty".equals(top.name)) {
                    top.kty = true;
                }
                if (Redactor.JWK_PRIVATE_MEMBERS.contains(top.name) && kind != Kind.NULL
                        && !(kind == Kind.STRING && Redactor.MASK.equals(content))) {
                    top.unmasked = true;
                }
            }
        }

        /**
         * Whether a string's content reads: one in which no level of escaping holds a quote ({@link #mayHoldQuote}) holds
         * no JSON name at any level, and any other one must read as strict JSON a level down, within the levels read.
         */
        private boolean nested(String content) {
            if (!mayHoldQuote(content, Redactor.NESTED_LEVELS - level)) {
                return true;
            }
            return level + 1 < Redactor.NESTED_LEVELS && new Reading(content, level + 1, masked).complete();
        }

        private void space() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    return;
                }
                i++;
            }
        }

        /** Reads a strict JSON string at its opening quote: its content, or {@code null} if it is not one. */
        private String string() {
            StringBuilder out = new StringBuilder();
            i++;
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    return null;
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (i >= s.length()) {
                    return null;
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"', '\\', '/' -> out.append(e);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length() || !isHex(s, i, i + 4)) {
                            return null;
                        }
                        out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> {
                        return null;
                    }
                }
            }
            return null;
        }

        /** Reads a strict JSON number: whether there is one. */
        private boolean number() {
            int start = i;
            if (i < s.length() && s.charAt(i) == '-') {
                i++;
            }
            if (i < s.length() && s.charAt(i) == '0') {
                i++;
            } else if (digits() == 0) {
                return false;
            }
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                if (digits() == 0) {
                    return false;
                }
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) {
                    i++;
                }
                if (digits() == 0) {
                    return false;
                }
            }
            return i > start;
        }

        private int digits() {
            int start = i;
            while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') {
                i++;
            }
            return i - start;
        }
    }
}
