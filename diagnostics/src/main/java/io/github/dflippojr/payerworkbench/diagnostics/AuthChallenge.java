package io.github.dflippojr.payerworkbench.diagnostics;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * One challenge of a {@code WWW-Authenticate} header, read as RFC 9110 §11.2 writes it:
 * {@code challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]}. A parameter name counts only at the start
 * of a parameter (after the scheme, or after a comma and optional whitespace), and a quoted value is skipped
 * whole, so {@code error=} inside a quoted {@code error_uri} or a name such as {@code suberror} is never read as
 * {@code error}. Parameter names are lower-cased; a repeated name keeps its first value.
 */
record AuthChallenge(String scheme, Map<String, String> params) {
    private static final String TCHAR = "!#$%&'*+-.^_`|~";

    /** Every challenge in {@code header}, in order; parameters before any scheme go to a challenge named "". */
    static List<AuthChallenge> parse(String header) {
        List<String> schemes = new ArrayList<>();
        List<Map<String, String>> params = new ArrayList<>();
        int n = header.length();
        int i = 0;
        while (i < n) {
            char c = header.charAt(i);
            if (c == ',' || isSpace(c)) {
                i++;
                continue;
            }
            int end = tokenEnd(header, i);
            if (end == i) {
                i = elementEnd(header, i);
                continue;
            }
            String name = header.substring(i, end);
            int next = skipSpace(header, end);
            if (next < n && header.charAt(next) == '=') {
                if (schemes.isEmpty()) {
                    schemes.add("");
                    params.add(new LinkedHashMap<>());
                }
                int start = skipSpace(header, next + 1);
                StringBuilder value = new StringBuilder();
                i = start < n && header.charAt(start) == '"'
                        ? quoted(header, start + 1, value) : bare(header, start, value);
                params.getLast().putIfAbsent(name.toLowerCase(Locale.ROOT), value.toString());
                i = elementEnd(header, i);
            } else {
                schemes.add(name);
                params.add(new LinkedHashMap<>());
                i = skipToken68(header, next);
            }
        }
        List<AuthChallenge> challenges = new ArrayList<>();
        for (int k = 0; k < schemes.size(); k++) {
            challenges.add(new AuthChallenge(schemes.get(k), Collections.unmodifiableMap(params.get(k))));
        }
        return List.copyOf(challenges);
    }

    /**
     * The value of auth-param {@code name}, read from the first challenge that carries an {@code error} parameter;
     * when none does, from the first challenge that carries {@code name}.
     */
    static Optional<String> param(List<AuthChallenge> challenges, String name) {
        String key = name.toLowerCase(Locale.ROOT);
        for (AuthChallenge challenge : challenges) {
            if (challenge.params().containsKey("error")) {
                return Optional.ofNullable(challenge.params().get(key));
            }
        }
        return challenges.stream().map(c -> c.params().get(key)).filter(v -> v != null).findFirst();
    }

    /**
     * The scheme of the challenge {@link #param} reads from: the first challenge that carries an {@code error}
     * parameter, else the first challenge that names a scheme.
     */
    static Optional<String> scheme(List<AuthChallenge> challenges) {
        return challenges.stream().filter(c -> c.params().containsKey("error") && !c.scheme().isEmpty())
                .map(AuthChallenge::scheme).findFirst()
                .or(() -> challenges.stream().map(AuthChallenge::scheme).filter(s -> !s.isEmpty()).findFirst());
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t';
    }

    private static boolean isTchar(char c) {
        return c <= '~' && (Character.isLetterOrDigit(c) || TCHAR.indexOf(c) >= 0);
    }

    private static boolean isToken68Char(char c) {
        return Character.isLetterOrDigit(c) || "-._~+/".indexOf(c) >= 0;
    }

    private static int tokenEnd(String s, int i) {
        while (i < s.length() && isTchar(s.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int skipSpace(String s, int i) {
        while (i < s.length() && isSpace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    /** Reads a quoted-string body from just after its opening quote; returns the index after the closing quote. */
    private static int quoted(String s, int i, StringBuilder value) {
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') {
                return i;
            }
            if (c == '\\' && i < s.length()) {
                c = s.charAt(i++);
            }
            value.append(c);
        }
        return i;
    }

    private static int bare(String s, int i, StringBuilder value) {
        while (i < s.length() && s.charAt(i) != ',' && !Character.isWhitespace(s.charAt(i))) {
            value.append(s.charAt(i++));
        }
        return i;
    }

    /** Skips anything left in a malformed element up to the next comma outside a quoted string. */
    private static int elementEnd(String s, int i) {
        while (i < s.length() && s.charAt(i) != ',') {
            i = s.charAt(i) == '"' ? quoted(s, i + 1, new StringBuilder()) : i + 1;
        }
        return i;
    }

    /** After a scheme, skips a token68 credential ({@code Negotiate YII=}) when that is all the challenge holds. */
    private static int skipToken68(String s, int i) {
        int end = i;
        while (end < s.length() && isToken68Char(s.charAt(end))) {
            end++;
        }
        if (end == i) {
            return i;
        }
        while (end < s.length() && s.charAt(end) == '=') {
            end++;
        }
        end = skipSpace(s, end);
        return end == s.length() || s.charAt(end) == ',' ? end : i;
    }
}
