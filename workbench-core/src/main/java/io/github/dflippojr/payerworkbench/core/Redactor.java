package io.github.dflippojr.payerworkbench.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks credential material in strings and HTTP headers before they are stored,
 * shown or written to a report.
 *
 * <p>Covers bearer and basic credentials, JWT signatures (the header and payload
 * stay readable because their claims are useful for diagnosis), PEM blocks, and
 * the values of well-known secret fields such as {@code client_secret} and
 * {@code access_token} in form, query and JSON bodies. It is a safety net, not a
 * guarantee: callers should still avoid passing secrets around in the first place.
 */
public final class Redactor {

    /** Replacement text for masked material. */
    public static final String MASK = "[REDACTED]";

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \\1-----", Pattern.DOTALL);

    /** A private key header with no matching footer (truncated paste): mask to the end. */
    private static final Pattern UNTERMINATED_PEM_KEY = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----(?!\\s*" + Pattern.quote(MASK) + ").*", Pattern.DOTALL);

    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)\\b(Bearer|Basic)\\s+(?!(?:realm|error|error_description|scope)\\s*=\\s*[^\\s,])([A-Za-z0-9\\-._~+/]+=*)");

    /** Short all-letter words after "bearer"/"basic" are prose ("missing bearer token"), not credentials. */
    private static final Pattern PROSE_WORD = Pattern.compile("[A-Za-z]{1,15}");

    private static final Pattern JWT = Pattern.compile(
            "\\b(eyJ[A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]*)\\.[A-Za-z0-9_-]+");

    private static final String SECRET_KEYS =
            "client_secret|access_token|refresh_token|id_token|password|api_key|apikey";

    /** Possessive quantifiers: a plain alternation recurses per character and overflows on long values. */
    private static final Pattern JSON_SECRET = Pattern.compile(
            "(?i)\"(" + SECRET_KEYS + ")\"(\\s*:\\s*)\"(?:[^\"\\\\]++|\\\\.)*+\"");

    private static final Pattern FORM_SECRET = Pattern.compile(
            "(?i)\\b(" + SECRET_KEYS + ")=[^&\\s\"]*");

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-client-secret");

    private Redactor() {
    }

    /**
     * Returns {@code text} with credential material masked, or {@code null} if
     * {@code text} is {@code null}.
     */
    public static String redact(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String out = PEM_BLOCK.matcher(text).replaceAll(m ->
                Matcher.quoteReplacement("-----BEGIN " + m.group(1) + "-----\n" + MASK + "\n-----END " + m.group(1) + "-----"));
        out = UNTERMINATED_PEM_KEY.matcher(out).replaceAll(m ->
                Matcher.quoteReplacement("-----BEGIN " + m.group(1) + "-----\n" + MASK));
        out = AUTH_SCHEME.matcher(out).replaceAll(m -> PROSE_WORD.matcher(m.group(2)).matches()
                ? Matcher.quoteReplacement(m.group())
                : Matcher.quoteReplacement(m.group(1) + " " + MASK));
        out = JWT.matcher(out).replaceAll("$1.$2." + Matcher.quoteReplacement(MASK));
        out = JSON_SECRET.matcher(out).replaceAll("\"$1\"$2\"" + Matcher.quoteReplacement(MASK) + "\"");
        out = FORM_SECRET.matcher(out).replaceAll("$1=" + Matcher.quoteReplacement(MASK));
        return out;
    }

    /** Whether a header with this name carries credentials and must never be shown verbatim. */
    public static boolean isSensitiveHeader(String name) {
        return name != null && SENSITIVE_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    /**
     * Returns an unmodifiable copy of {@code headers} (iteration order kept) in
     * which credential headers are masked and every other value is passed through
     * {@link #redact(String)}. For {@code Authorization}-style headers the scheme
     * is kept ({@code Bearer [REDACTED]}) so diagnostics can still tell which
     * scheme was sent.
     */
    public static Map<String, List<String>> redactHeaders(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, List<String>> out = new LinkedHashMap<>();
        headers.forEach((name, values) -> {
            List<String> safe = values == null ? List.of() : values.stream()
                    .map(v -> redactHeaderValue(name, v))
                    .toList();
            out.put(name, safe);
        });
        return Collections.unmodifiableMap(out);
    }

    private static String redactHeaderValue(String name, String value) {
        if (value == null) {
            return null;
        }
        if (!isSensitiveHeader(name)) {
            return redact(value);
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.equals("authorization") || lower.equals("proxy-authorization")) {
            String trimmed = value.strip();
            int space = trimmed.indexOf(' ');
            if (space > 0) {
                return trimmed.substring(0, space) + " " + MASK;
            }
        }
        return MASK;
    }
}
