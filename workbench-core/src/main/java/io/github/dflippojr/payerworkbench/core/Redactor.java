package io.github.dflippojr.payerworkbench.core;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks credential material in strings and HTTP headers before they are stored,
 * shown or written to a report.
 *
 * <p>Covers bearer and basic credentials, JWT signatures (the header and payload
 * stay readable because their claims are useful for diagnosis), PEM blocks, and
 * the values of well-known secret fields such as {@code client_secret},
 * {@code access_token} and {@code private_key} in form and query bodies and in
 * JSON (string, number and boolean values, also in JSON embedded in a JSON
 * string; see {@link #isSecretField(String)}). It is a safety net, not a
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

    /**
     * A scheme, its token68 part (group 2) and anything else up to the next whitespace, quote,
     * comma, semicolon or backslash (group 3), so a {@code token:suffix} is masked whole.
     */
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)\\b(Bearer|Basic)\\s+(?!(?:realm|error|error_description|scope)\\s*=\\s*[^\\s,])"
                    + "([A-Za-z0-9\\-._~+/]+=*)([^\\s\"',;\\\\]*)");

    /** Short all-letter words after "bearer"/"basic" are prose ("missing bearer token."), not credentials. */
    private static final Pattern PROSE_WORD = Pattern.compile("[A-Za-z]{1,15}[.)]*");

    private static final Pattern JWT = Pattern.compile(
            "\\b(eyJ[A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]*)\\.[A-Za-z0-9_-]+");

    /**
     * JSON field names whose values are always masked, lower case without {@code _} and {@code -}
     * (see {@link #isSecretField(String)}).
     */
    private static final Set<String> SECRET_FIELDS = Set.of(
            "clientsecret", "accesstoken", "refreshtoken", "idtoken", "password", "apikey", "privatekey",
            "secret", "clientassertion", "assertion");

    /** A JSON number, {@code true} or {@code false}: a secret-named field holding one is masked too. */
    private static final String JSON_SCALAR = "-?+\\d[\\d.eE+-]*+|true\\b|false\\b";

    /**
     * A JSON field and its string or scalar value; group 1 is the name, checked with
     * {@link #isSecretField(String)}. Possessive quantifiers: a plain alternation recurses per
     * character and overflows on long values.
     */
    private static final Pattern JSON_FIELD = Pattern.compile(
            "\"([A-Za-z_-]{1,64})\"(\\s*:\\s*)(?:\"(?:[^\"\\\\]++|\\\\.)*+\"|" + JSON_SCALAR + ")");

    /** The same inside JSON that is itself embedded in a JSON string ({@code {\"key\": \"value\"}}). */
    private static final Pattern EMBEDDED_JSON_FIELD = Pattern.compile(
            "\\\\\"([A-Za-z_-]{1,64})\\\\\"(\\s*:\\s*)(?:\\\\\"(?:[^\"\\\\]++|\\\\[^\"])*+\\\\\"|" + JSON_SCALAR + ")");

    private static final String FORM_SECRET_KEYS =
            "client_secret|access_token|refresh_token|id_token|password|api_key|apikey|private_key";

    private static final Pattern FORM_SECRET = Pattern.compile(
            "(?i)\\b(" + FORM_SECRET_KEYS + ")=[^&\\s\"]*");

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
        out = AUTH_SCHEME.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isProse(m)
                ? m.group()
                : m.group(1) + " " + MASK));
        out = JWT.matcher(out).replaceAll("$1.$2." + Matcher.quoteReplacement(MASK));
        out = JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretField(m.group(1))
                ? "\"" + m.group(1) + "\"" + m.group(2) + "\"" + MASK + "\""
                : m.group()));
        out = EMBEDDED_JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretField(m.group(1))
                ? "\\\"" + m.group(1) + "\\\"" + m.group(2) + "\\\"" + MASK + "\\\""
                : m.group()));
        out = FORM_SECRET.matcher(out).replaceAll("$1=" + Matcher.quoteReplacement(MASK));
        return out;
    }

    /**
     * Whether a scheme match is prose ("Missing bearer token", "Basic authentication is required")
     * rather than a credential: one short all-letter word, and for {@code Basic} not the base64 of a
     * {@code user:pass} pair (RFC 7617), which can be all letters too ({@code dXNlcjpwYXNz}).
     */
    private static boolean isProse(MatchResult m) {
        String word = m.group(2) + m.group(3);
        return PROSE_WORD.matcher(word).matches()
                && !(m.group(1).equalsIgnoreCase("Basic") && isUserPass(m.group(2)));
    }

    private static boolean isUserPass(String token) {
        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Base64.getDecoder().decode(token)))
                    .toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            return false;
        }
        return decoded.indexOf(':') >= 0 && decoded.chars().noneMatch(Character::isISOControl);
    }

    /**
     * Whether a JSON field with this name holds a secret and is always masked. Case, {@code _} and
     * {@code -} are ignored, so {@code client_secret}, {@code clientSecret} and {@code client-secret}
     * all match.
     */
    public static boolean isSecretField(String name) {
        return name != null
                && SECRET_FIELDS.contains(name.toLowerCase(Locale.ROOT).replace("_", "").replace("-", ""));
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
