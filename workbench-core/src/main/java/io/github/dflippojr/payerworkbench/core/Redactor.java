package io.github.dflippojr.payerworkbench.core;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalAmount;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

/**
 * Masks credential material in strings and HTTP headers before they are stored,
 * shown or written to a report.
 *
 * <p>Covers bearer and basic credentials, JWT signatures (the header and payload
 * stay readable because their claims are useful for diagnosis), PEM blocks, and
 * the values of well-known secret fields such as {@code client_secret},
 * {@code access_token} and {@code private_key} in form and query bodies and in
 * JSON (any value, including an object such as a private JWK, also in JSON
 * embedded in a JSON string; see {@link #isSecretField(String)}). It is a safety net, not a
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
     * Where a word starts: a word boundary, or right after a JSON escape such as {@code \n}, which
     * leaves a letter in front of the word in text quoted inside a JSON string.
     */
    private static final String WORD_START = "(?:\\b|(?<=\\\\[nrtbf]))";

    /**
     * A JSON escape of a token68 character, also escaped again: {@code \/}, or a {@code \}{@code uXXXX}
     * escape of a letter, digit or one of {@code -._~+/=}. Serializers write these inside a token
     * ({@code System.Text.Json} escapes {@code +}, Gson {@code =}, PHP {@code /}).
     */
    private static final String ESCAPED_TOKEN_CHAR =
            "\\\\++(?:/|u00(?:2[BDEF]|3[0-9D]|[46][1-9A-F]|[57][0-9A]|5F|7E))";

    /**
     * A scheme, its token68 part (group 2, which may be URL-encoded) and anything else up to the next
     * whitespace, quote, comma, semicolon or backslash (group 3), so a {@code token:suffix} is masked
     * whole. Both parts read a JSON escape of a token character ({@link #ESCAPED_TOKEN_CHAR}) as the
     * character it stands for, so a token quoted by a serializer that escapes some of its characters
     * ({@code tok\/en}, {@code tok}{@code \}{@code u002Ben}) is masked whole too. Case-insensitive, so
     * the escapes' hex digits may be either case. Possessive quantifiers, as in {@link #JSON_FIELD}.
     */
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)" + WORD_START + "(Bearer|Basic)\\s+(?!(?:realm|error|error_description|scope)\\s*=\\s*[^\\s,])"
                    + "((?:[A-Za-z0-9\\-._~+/%]++|" + ESCAPED_TOKEN_CHAR + ")++=*)"
                    + "((?:[^\\s\"',;\\\\]++|" + ESCAPED_TOKEN_CHAR + ")*+)");

    /** Short all-letter words after "bearer"/"basic" are prose ("missing bearer token."), not credentials. */
    private static final Pattern PROSE_WORD = Pattern.compile("[A-Za-z]{1,15}[.)]*");

    private static final Pattern JWT = Pattern.compile(
            WORD_START + "(eyJ[A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]*)\\.[A-Za-z0-9_-]+");

    /**
     * JSON field names whose values are always masked, lower case without {@code _} and {@code -}
     * (see {@link #isSecretField(String)}).
     */
    static final Set<String> SECRET_FIELDS = Set.of(
            "clientsecret", "accesstoken", "refreshtoken", "idtoken", "password", "apikey", "privatekey",
            "secret", "clientassertion", "assertion");

    /** A JSON number, {@code true} or {@code false}: a secret-named field holding one is masked too. */
    private static final String JSON_SCALAR = "-?+\\d[\\d.eE+-]*+|true\\b|false\\b";

    /**
     * A JSON field and its string or scalar value; group 1 is the name, checked with
     * {@link #isSecretField(String)}. A string cut off by the end of the text (a body truncated at
     * the size limit) counts too, also when the cut leaves half an escape: a lone backslash at the
     * end, or before the line break that starts a note appended to the cut body. Possessive
     * quantifiers: a plain alternation recurses per character and overflows on long values.
     */
    private static final Pattern JSON_FIELD = Pattern.compile(
            "\"([A-Za-z_-]{1,64})\"(\\s*:\\s*)(?:\"(?:[^\"\\\\]++|\\\\.)*+(?:\"|\\\\?+(?=\\R|\\z))|"
                    + JSON_SCALAR + ")");

    /** A literal backslash, as a regex. */
    private static final String BACKSLASH = "\\\\";

    /** Any character but a quote or backslash, as a regex. */
    private static final String PLAIN = "[^\"\\\\]";

    /**
     * The same inside JSON that is itself embedded in a JSON string ({@code {\"key\": \"value\"}}),
     * where the inner string's own escapes are escaped again: an inner {@code \\} is four backslashes
     * and an inner {@code \"} three and a quote. A string cut off by the end of the text counts too,
     * and so does one cut off by the end of the outer string (an unescaped quote): embedded JSON that
     * was truncated before it was quoted. Either cut may leave up to three backslashes of an escape,
     * and a cut at the end of the text may be followed by a line break, as in {@link #JSON_FIELD}.
     */
    private static final Pattern EMBEDDED_JSON_FIELD = Pattern.compile(
            BACKSLASH + "\"([A-Za-z_-]{1,64})" + BACKSLASH + "\"(\\s*:\\s*)(?:" + BACKSLASH + "\"(?:" + PLAIN + "++"
                    + "|" + BACKSLASH.repeat(4) + "|" + BACKSLASH.repeat(3) + "\"|" + BACKSLASH.repeat(2) + PLAIN
                    + "|" + BACKSLASH + PLAIN + ")*+(?:" + BACKSLASH + "\"|(?:" + BACKSLASH + "){0,3}+(?=\"|\\R|\\z))|"
                    + JSON_SCALAR + ")");

    /** A JSON field whose value is an object or array; group 1 is the name. */
    private static final Pattern JSON_FIELD_STRUCTURE = Pattern.compile("\"([A-Za-z_-]{1,64})\"\\s*:\\s*(?=[{\\[])");

    /** The same inside JSON embedded in a JSON string. */
    private static final Pattern EMBEDDED_JSON_FIELD_STRUCTURE = Pattern.compile(
            BACKSLASH + "\"([A-Za-z_-]{1,64})" + BACKSLASH + "\"\\s*:\\s*(?=[{\\[])");

    private static final String FORM_SECRET_KEYS =
            "client_secret|access_token|refresh_token|id_token|password|api_key|apikey|private_key";

    /**
     * A form secret runs to the next {@code &}, whitespace or quote, or to a backslash that starts a
     * JSON escape ({@code \n}, {@code \"}) in a form body quoted inside JSON. Any other backslash,
     * an escaped one ({@code \\}) included, is part of the value.
     */
    private static final Pattern FORM_SECRET = Pattern.compile(
            "(?i)" + WORD_START + "(" + FORM_SECRET_KEYS + ")=(?:[^&\\s\"\\\\]++|" + BACKSLASH.repeat(2) + "|"
                    + BACKSLASH + "(?![nrtbf\"]))*+");

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
        out = maskStructures(out, JSON_FIELD_STRUCTURE, false);
        out = maskStructures(out, EMBEDDED_JSON_FIELD_STRUCTURE, true);
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
     * {@code user:pass} pair (RFC 7617), which can be all letters too ({@code dXNlcjpwYXNz}), even
     * with the period that ends a sentence after it.
     */
    private static boolean isProse(MatchResult m) {
        String word = m.group(2) + m.group(3);
        return PROSE_WORD.matcher(word).matches()
                && !(m.group(1).equalsIgnoreCase("Basic") && isUserPass(withoutTrailingPeriods(m.group(2))));
    }

    private static String withoutTrailingPeriods(String token) {
        int end = token.length();
        while (end > 0 && token.charAt(end - 1) == '.') {
            end--;
        }
        return token.substring(0, end);
    }

    /**
     * Replaces the object or array value of every secret-named field that {@code fields} finds with a
     * masked string, through its matching close bracket or, in a body cut off at the size limit, to
     * the end of the text.
     */
    private static String maskStructures(String text, Pattern fields, boolean embedded) {
        Matcher m = fields.matcher(text);
        StringBuilder out = null;
        int copied = 0;
        int from = 0;
        while (from < text.length() && m.find(from)) {
            from = m.end();
            if (isSecretField(m.group(1))) {
                String quote = embedded ? "\\\"" : "\"";
                out = out == null ? new StringBuilder(text.length()) : out;
                out.append(text, copied, m.end()).append(quote).append(MASK).append(quote);
                copied = endOfStructure(text, m.end(), embedded);
                from = copied;
            }
        }
        return out == null ? text : out.append(text, copied, text.length()).toString();
    }

    /**
     * Where the JSON object or array starting at {@code start} ends; brackets inside strings don't
     * count. In embedded JSON every character may carry one more escape ({@code \"} is a quote of
     * the inner JSON), and an unescaped quote ends the outer string and with it the inner JSON.
     */
    private static int endOfStructure(String text, int start, boolean embedded) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        int i = start;
        while (i < text.length()) {
            char c = text.charAt(i++);
            if (embedded && c == '"') {
                return i - 1;
            }
            if (embedded && c == '\\' && i < text.length()) {
                c = text.charAt(i++);
            }
            if (inString) {
                inString = escaped || c != '"';
                escaped = !escaped && c == '\\';
            } else if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if ((c == '}' || c == ']') && --depth == 0) {
                return i;
            }
        }
        return text.length();
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

    /**
     * Returns a copy of a JSON-like value in which every string has been through {@link #redact(String)}
     * and the value of every field named like a secret or a credential header is masked, recursively,
     * or {@code null} if {@code value} is {@code null}. Maps keep their iteration order, and their string
     * keys are redacted too; sets are copied, other collections and arrays become lists, and an
     * {@link Optional} keeps its redacted value; a record is rebuilt through its canonical constructor
     * from redacted components, so it keeps its type. Numbers, booleans, characters, enums, dates and
     * durations are returned as they are. Any other value, such as a {@code StringBuilder} or a parsed
     * JSON tree, becomes its redacted {@link String#valueOf(Object) string form}, so it cannot carry a
     * secret through unredacted. An {@code Authorization}-style field keeps its scheme
     * ({@code Bearer [REDACTED]}).
     */
    public static Object redactTree(Object value) {
        return redactTree(null, value);
    }

    private static Object redactTree(String key, Object value) {
        if (key != null && isSecretKey(key)) {
            return value instanceof List<?> list ? list.stream().map(v -> maskField(key, v)).toList() : maskField(key, value);
        }
        if (value == null || value instanceof Number || value instanceof Boolean || value instanceof Character
                || value instanceof Enum<?> || value instanceof TemporalAccessor || value instanceof TemporalAmount) {
            return value;
        }
        if (value instanceof String s) {
            return redact(s);
        }
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(k instanceof String s ? redact(s) : k, redactTree(String.valueOf(k), v)));
            return Collections.unmodifiableMap(out);
        }
        if (value instanceof Set<?> set) {
            Set<Object> out = new LinkedHashSet<>();
            set.forEach(v -> out.add(redactTree(null, v)));
            return Collections.unmodifiableSet(out);
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(v -> redactTree(null, v)).toList();
        }
        if (value.getClass().isArray()) {
            return IntStream.range(0, Array.getLength(value)).mapToObj(i -> redactTree(null, Array.get(value, i))).toList();
        }
        if (value instanceof Optional<?> optional) {
            return optional.map(v -> redactTree(null, v));
        }
        if (value instanceof Record record) {
            return redactRecord(record);
        }
        return redact(String.valueOf(value));
    }

    private static boolean isSecretKey(String key) {
        return isSecretField(key) || isSensitiveHeader(key);
    }

    /** Keeps the scheme of an {@code Authorization}-style value so it still says which was sent. */
    private static Object maskField(String key, Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String s && key.toLowerCase(Locale.ROOT).endsWith("authorization")) {
            return redactHeaderValue("Authorization", s);
        }
        return MASK;
    }

    /**
     * Rebuilds a record from its redacted components. A secret-named component that cannot hold the
     * mask (not a string) becomes {@code null}, or {@code 0} or {@code false} for a primitive.
     */
    private static Record redactRecord(Record record) {
        RecordComponent[] components = record.getClass().getRecordComponents();
        Object[] values = new Object[components.length];
        Class<?>[] types = new Class<?>[components.length];
        try {
            for (int i = 0; i < components.length; i++) {
                Method accessor = components[i].getAccessor();
                accessor.trySetAccessible();
                types[i] = components[i].getType();
                values[i] = fitting(types[i], redactTree(components[i].getName(), accessor.invoke(record)));
            }
            Constructor<? extends Record> canonical = record.getClass().getDeclaredConstructor(types);
            canonical.trySetAccessible();
            return canonical.newInstance(values);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Cannot redact a " + record.getClass().getName(), e);
        }
    }

    /** {@code value} if a component of {@code type} can hold it, otherwise that type's empty value. */
    private static Object fitting(Class<?> type, Object value) {
        Object empty = type.isPrimitive() ? Array.get(Array.newInstance(type, 1), 0) : null;
        return (empty == null ? type : empty.getClass()).isInstance(value) ? value : empty;
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
