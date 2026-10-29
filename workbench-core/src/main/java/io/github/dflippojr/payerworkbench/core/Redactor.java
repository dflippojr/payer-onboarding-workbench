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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Masks credential material in strings and HTTP headers before they are stored,
 * shown or written to a report.
 *
 * <p>Covers {@code Bearer}, {@code Basic}, {@code Token} and {@code DPoP} credentials (a
 * {@code Bearer} one also URL-encoded, {@code Bearer%20} or {@code Bearer+}), JWT signatures
 * (the header and payload stay readable because their claims are useful for diagnosis), PEM
 * blocks and PGP private key blocks, the private members of a JWK ({@link #JWK_PRIVATE_MEMBERS}
 * of a JSON object with a {@code kty} member), and the values of well-known secret fields such
 * as {@code client_secret}, {@code access_token} and {@code private_key} in form and query
 * bodies and in JSON (any value, including an object such as a private JWK, also in JSON
 * embedded in a JSON string; see {@link #isSecretField(String)}). The value of a
 * credential header ({@link #isSensitiveHeader(String)}, such as {@code Cookie}) is
 * masked in a header map, in a {@code Name: value} line of free text and in a JSON field
 * of that name. It is a safety net, not a guarantee: callers should still avoid passing
 * secrets around in the first place.
 *
 * <p>Out of scope (#262): other schemes in free text, such as {@code Digest response=...}
 * (an {@code Authorization} header or line is still masked whole); URL-encoded separators
 * after any scheme but {@code Bearer}; JWK member names outside an object with a
 * {@code kty} member, so an ordinary field named {@code d} or {@code k} is kept.
 */
public final class Redactor {

    /** Replacement text for masked material. */
    public static final String MASK = "[REDACTED]";

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \\1-----", Pattern.DOTALL);

    /**
     * A private key header, PEM or PGP ({@code PRIVATE KEY BLOCK}), with no matching footer (truncated
     * paste): mask to the end.
     */
    private static final Pattern UNTERMINATED_PEM_KEY = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----(?!\\s*" + Pattern.quote(MASK) + ").*", Pattern.DOTALL);

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
     * A scheme (group 1), its token68 part (group 2, which may be URL-encoded) and anything else up to
     * the next whitespace, quote, comma, semicolon or backslash (group 3), so a {@code token:suffix} is
     * masked whole. After {@code Bearer} the space may be URL-encoded too ({@code Bearer%20},
     * {@code Bearer+}), also right after another escape ({@code %3A%20Bearer%20}). Both parts read a
     * JSON escape of a token character ({@link #ESCAPED_TOKEN_CHAR}) as the character it stands for,
     * so a token quoted by a serializer that escapes some of its characters
     * ({@code tok\/en}, {@code tok}{@code \}{@code u002Ben}) is masked whole too. Case-insensitive, so
     * the escapes' hex digits may be either case. Possessive quantifiers, as in {@link #JSON_FIELD}.
     */
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)(?:" + WORD_START + "|(?<=%[0-9A-F]{2})(?=Bearer))(Bearer|Basic|Token|DPoP)"
                    + "(?:\\s+|(?<=Bearer)(?:%20|\\+)++)(?!(?:realm|error|error_description|scope)\\s*=\\s*[^\\s,])"
                    + "((?:[A-Za-z0-9\\-._~+/%]++|" + ESCAPED_TOKEN_CHAR + ")++=*)"
                    + "((?:[^\\s\"',;\\\\]++|" + ESCAPED_TOKEN_CHAR + ")*+)");

    /** Short all-letter words after a scheme are prose ("missing bearer token."), not credentials. */
    private static final Pattern PROSE_WORD = Pattern.compile("[A-Za-z]{1,15}[.)]*");

    /** What follows a scheme with no letter or digit ({@code ->}) is not a credential either. */
    private static final Pattern PUNCTUATION = Pattern.compile("[^A-Za-z0-9]*+");

    private static final Pattern JWT = Pattern.compile(
            WORD_START + "(eyJ[A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]*)\\.[A-Za-z0-9_-]+");

    /**
     * JSON field names whose values are always masked, lower case without {@code _} and {@code -}
     * (see {@link #isSecretField(String)}).
     */
    static final Set<String> SECRET_FIELDS = Set.of(
            "clientsecret", "accesstoken", "refreshtoken", "idtoken", "password", "apikey", "privatekey",
            "secret", "clientassertion", "assertion");

    /**
     * The private members of a JWK (RFC 7518 section 6: the RSA private key and other primes, the EC and
     * OKP private key, the symmetric key), masked only in a JSON object that has a {@code kty} member,
     * where {@link #isSecretField(String)} does not apply: elsewhere these are ordinary short names.
     */
    static final Set<String> JWK_PRIVATE_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

    /** The {@code kty} member that makes a JSON object a JWK; it starts at the name's opening quote. */
    private static final Pattern JWK_TYPE = Pattern.compile("\"kty\"\\s*:");

    /** A JSON number, {@code true} or {@code false}: a secret-named field holding one is masked too. */
    private static final String JSON_SCALAR = "-?+\\d[\\d.eE+-]*+|true\\b|false\\b";

    /**
     * A JSON field and its string or scalar value; group 1 is the name, checked with
     * {@link #isSecretKey(String)}, and group 3 the string's content. A string cut off by the end of
     * the text (a body truncated at the size limit) counts too, also when the cut leaves half an
     * escape: a lone backslash at the end, or before the line break that starts a note appended to the
     * cut body. Possessive quantifiers: a plain alternation recurses per character and overflows on
     * long values.
     */
    private static final Pattern JSON_FIELD = Pattern.compile(
            "\"([A-Za-z_-]{1,64})\"(\\s*:\\s*)(?:\"((?:[^\"\\\\]++|\\\\.)*+)(?:\"|\\\\?+(?=\\R|\\z))|"
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
            BACKSLASH + "\"([A-Za-z_-]{1,64})" + BACKSLASH + "\"(\\s*:\\s*)(?:" + BACKSLASH + "\"((?:" + PLAIN + "++"
                    + "|" + BACKSLASH.repeat(4) + "|" + BACKSLASH.repeat(3) + "\"|" + BACKSLASH.repeat(2) + PLAIN
                    + "|" + BACKSLASH + PLAIN + ")*+)(?:" + BACKSLASH + "\"|(?:" + BACKSLASH + "){0,3}+(?=\"|\\R|\\z))|"
                    + JSON_SCALAR + ")");

    /** A JSON field whose value is an object or array; group 1 is the name. */
    private static final Pattern JSON_FIELD_STRUCTURE = Pattern.compile("\"([A-Za-z_-]{1,64})\"\\s*:\\s*(?=[{\\[])");

    /** The same inside JSON embedded in a JSON string. */
    private static final Pattern EMBEDDED_JSON_FIELD_STRUCTURE = Pattern.compile(
            BACKSLASH + "\"([A-Za-z_-]{1,64})" + BACKSLASH + "\"\\s*:\\s*(?=[{\\[])");

    /** {@link #JWK_TYPE} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_JWK_TYPE = Pattern.compile(BACKSLASH + "\"kty" + BACKSLASH + "\"\\s*:");

    /** Header names whose values are always masked, lower case (see {@link #isSensitiveHeader(String)}). */
    static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-client-secret");

    /**
     * The name of a credential header line, {@code Name: value}, and its colon: group 2 of
     * {@link #HEADER_LINE} and {@link #ESCAPED_HEADER_LINE} is the name, any {@link #SENSITIVE_HEADERS}
     * name in any case (only the name ignores case), and group 1 everything from where the line starts
     * to the value. A line starts at the start of the text or after a line break (also an escaped one
     * in a JSON string), and may be indented; a header name anywhere else ({@code see the Cookie:
     * header docs}) is prose. The names are letters and {@code -} only.
     */
    private static final String HEADER_NAME = "((?i:" + String.join("|", SENSITIVE_HEADERS) + ")):";

    /**
     * A header line in plain text. The value (group 3) runs to the end of the line ({@code ;} and {@code =} are
     * part of a cookie), or to a backslash that starts a JSON {@code \n} or {@code \r} escape, as in
     * {@link #FORM_SECRET}.
     */
    private static final Pattern HEADER_LINE = Pattern.compile("(?m)^([ \\t]*+" + HEADER_NAME + "[ \\t]*+)"
            + "((?:[^\\r\\n\\\\]++|" + BACKSLASH.repeat(2) + "|" + BACKSLASH + "(?![nr]))*+)");

    /** Spaces and tabs, also tabs escaped in a JSON string at any depth. */
    private static final String ESCAPED_SPACE = "(?:[ \\t]|" + BACKSLASH + "++t)*+";

    /**
     * The start of a header line quoted inside a JSON string, after an escaped line break; its indent
     * and the space after the colon may be escaped tabs too. Its value ends where
     * {@link #endOfEscapedLine} says.
     */
    private static final Pattern ESCAPED_HEADER_LINE = Pattern.compile("(?<=" + BACKSLASH + "[nr])("
            + ESCAPED_SPACE + HEADER_NAME + ESCAPED_SPACE + ")");

    /**
     * The first word of an {@code Authorization}-style value (an RFC 9110 token, group 1) and more after it;
     * it is kept only if it is one of {@link #AUTH_SCHEMES}.
     */
    private static final Pattern SCHEME = Pattern.compile(
            "[ \\t]*+([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*+)[ \\t]++\\S");

    /**
     * Authentication schemes an {@code Authorization}-style value keeps in front of the mask, lower case:
     * the IANA HTTP Authentication Scheme Registry, and {@code Token}, {@code NTLM} and
     * {@code AWS4-HMAC-SHA256}. Any other first word may be the credential itself.
     */
    private static final Set<String> AUTH_SCHEMES = Set.of(
            "basic", "bearer", "concealed", "digest", "dpop", "gnap", "hoba", "mutual", "negotiate", "oauth",
            "privatetoken", "scram-sha-1", "scram-sha-256", "vapid", "token", "ntlm", "aws4-hmac-sha256");

    /**
     * Every {@link #SECRET_FIELDS} name as a form key: an optional {@code _} or {@code -} may separate
     * any two letters, and the match is case-insensitive. That is the normalization
     * {@link #isSecretField(String)} applies, so {@code client_secret}, {@code clientSecret} and
     * {@code client-secret} all match {@code clientsecret}. The names are lower-case letters only.
     */
    private static final String FORM_SECRET_KEYS = SECRET_FIELDS.stream()
            .map(name -> String.join("[_-]?", name.split("")))
            .collect(Collectors.joining("|"));

    /**
     * A form secret runs to the next {@code &}, whitespace or quote, or to a backslash that starts a
     * JSON escape ({@code \n}, {@code \"}) in a form body quoted inside JSON. Any other backslash,
     * an escaped one ({@code \\}) included, is part of the value.
     */
    private static final Pattern FORM_SECRET = Pattern.compile(
            "(?i)" + WORD_START + "(" + FORM_SECRET_KEYS + ")=(?:[^&\\s\"\\\\]++|" + BACKSLASH.repeat(2) + "|"
                    + BACKSLASH + "(?![nrtbf\"]))*+");


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
        out = JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretKey(m.group(1))
                ? "\"" + m.group(1) + "\"" + m.group(2) + "\"" + masked(m.group(1), m.group(3)) + "\""
                : m.group()));
        out = EMBEDDED_JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretKey(m.group(1))
                ? "\\\"" + m.group(1) + "\\\"" + m.group(2) + "\\\"" + masked(m.group(1), m.group(3)) + "\\\""
                : m.group()));
        out = maskJwks(out, false);
        out = maskJwks(out, true);
        out = FORM_SECRET.matcher(out).replaceAll("$1=" + Matcher.quoteReplacement(MASK));
        out = HEADER_LINE.matcher(out).replaceAll(Redactor::maskHeaderLine);
        out = maskEscapedHeaderLines(out);
        return out;
    }

    /**
     * A header line with its value masked. A line with no value is left as it is, and so is an
     * {@code Authorization}-style line whose {@code Bearer} or {@code Basic} value {@link #AUTH_SCHEME}
     * keeps as prose ({@code Authorization: Bearer access token required}), as it does anywhere else.
     * After {@code Token} or {@code DPoP} such a line is a credential ({@code Authorization: Token abc}).
     */
    private static String maskHeaderLine(MatchResult m) {
        String value = m.group(3);
        String line = keepsLine(m.group(2), value) ? m.group() : m.group(1) + masked(m.group(2), value);
        return Matcher.quoteReplacement(line);
    }

    private static boolean keepsLine(String name, String value) {
        Matcher scheme = AUTH_SCHEME.matcher(value);
        return value.isBlank() || (keepsScheme(name) && scheme.lookingAt()
                && scheme.group(1).matches("(?i)Bearer|Basic") && isProse(scheme));
    }

    /** Masks the value of every header line quoted inside a JSON string, as {@link #maskHeaderLine} does. */
    private static String maskEscapedHeaderLines(String text) {
        Matcher m = ESCAPED_HEADER_LINE.matcher(text);
        StringBuilder out = null;
        int copied = 0;
        int from = 0;
        while (from < text.length() && m.find(from)) {
            // The backslashes before the n or r of the line break in front of the line.
            int depth = Integer.lowestOneBit(backslashesBefore(text, m.start() - 1));
            int end = endOfEscapedLine(text, m.end(), depth);
            String value = text.substring(m.end(), end);
            from = Math.max(end, m.end() + 1);
            if (!keepsLine(m.group(2), value)) {
                out = out == null ? new StringBuilder(text.length()) : out;
                out.append(text, copied, m.end()).append(masked(m.group(2), value));
                copied = end;
            }
        }
        return out == null ? text : out.append(text, copied, text.length()).toString();
    }

    private static int backslashesBefore(String text, int index) {
        int i = index;
        while (i > 0 && text.charAt(i - 1) == '\\') {
            i--;
        }
        return index - i;
    }

    /**
     * Where the value of a header line quoted inside a JSON string ends: at the line break or the
     * closing quote of that string, or at the end of the text. The line break before the line was
     * escaped with {@code depth} backslashes: 1 in a JSON string, 2 in JSON embedded in one, and so on.
     * There, a run of {@code c} backslashes before {@code n} or {@code r} is a line break when
     * {@code c % (2 * depth) == depth}, and before a quote ends the string when
     * {@code c % (2 * depth) < depth}. Anything else, such as an escaped quote in a quoted cookie value,
     * is part of the value.
     */
    private static int endOfEscapedLine(String text, int start, int depth) {
        int i = start;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '\r' || c == '\n' || c == '"') {
                return i;
            }
            int run = i;
            while (i < text.length() && text.charAt(i) == '\\') {
                i++;
            }
            if (i == text.length()) {
                return i;
            }
            int escapes = (i - run) % (2 * depth);
            char next = text.charAt(i);
            if (next == '\r' || next == '\n') {
                return i;
            }
            if (i > run && (((next == 'n' || next == 'r') && escapes == depth) || (next == '"' && escapes < depth))) {
                return run;
            }
            i++;
        }
        return i;
    }

    /**
     * The mask for the value of the secret field or credential header {@code name}: an
     * {@code Authorization}-style string value keeps its scheme ({@code Bearer [REDACTED]}) when it starts
     * with one of {@link #AUTH_SCHEMES}; any other value (or {@code null}, for a number or boolean) is
     * masked whole.
     */
    private static String masked(String name, String value) {
        if (value != null && keepsScheme(name)) {
            Matcher scheme = SCHEME.matcher(value);
            if (scheme.lookingAt() && AUTH_SCHEMES.contains(scheme.group(1).toLowerCase(Locale.ROOT))) {
                return scheme.group(1) + " " + MASK;
            }
        }
        return MASK;
    }

    private static boolean keepsScheme(String name) {
        return name.toLowerCase(Locale.ROOT).endsWith("authorization");
    }

    /**
     * Whether a scheme match is prose ("Missing bearer token", "Basic authentication is required")
     * rather than a credential: one short all-letter word, and for {@code Basic} not the base64 of a
     * {@code user:pass} pair (RFC 7617), which can be all letters too ({@code dXNlcjpwYXNz}), even
     * with the period that ends a sentence after it. So is punctuation with no letter or digit, as in
     * {@code POST /oauth/token -> 200}.
     */
    private static boolean isProse(MatchResult m) {
        String word = m.group(2) + m.group(3);
        // Token is also an ordinary word, as in "token endpoint: <url>".
        if (m.group(1).equalsIgnoreCase("Token") && word.endsWith(":")) {
            word = word.substring(0, word.length() - 1);
        }
        return PUNCTUATION.matcher(word).matches() || PROSE_WORD.matcher(word).matches()
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
     * Replaces the object or array value of every field named like a secret or a credential header
     * that {@code fields} finds with a masked string, through its matching close bracket or, in a body
     * cut off at the size limit, to the end of the text.
     */
    private static String maskStructures(String text, Pattern fields, boolean embedded) {
        Matcher m = fields.matcher(text);
        StringBuilder out = null;
        int copied = 0;
        int from = 0;
        while (from < text.length() && m.find(from)) {
            from = m.end();
            if (isSecretKey(m.group(1))) {
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

    /**
     * Masks the {@link #JWK_PRIVATE_MEMBERS} of every JSON object with a {@code kty} member, as a secret
     * field is masked: a string or scalar value becomes the mask, and so does an object or array, through
     * its close bracket. Only the JWK's own members count, not those of an object inside or next to it.
     * Each object is read once, so the time stays linear in the length of the text.
     */
    private static String maskJwks(String text, boolean embedded) {
        Matcher type = (embedded ? EMBEDDED_JWK_TYPE : JWK_TYPE).matcher(text);
        String kty = embedded ? "\\\"kty\\\"" : "\"kty\"";
        Set<Integer> read = new HashSet<>();
        Map<Integer, Integer> matching = new HashMap<>();
        TreeSet<Integer> names = new TreeSet<>();
        int outside = -1;
        while (type.find()) {
            int start = read.contains(type.start()) ? -1 : startOfObject(text, type.start(), embedded, matching, outside);
            outside = start < 0 && !read.contains(type.start()) ? type.start() : outside;
            for (JsonObject object : start < 0 ? List.<JsonObject>of() : objects(text, start, embedded, matching)) {
                read.addAll(object.names());
                if (object.names().stream().anyMatch(name -> text.startsWith(kty, name))) {
                    names.addAll(object.names());
                }
            }
        }
        if (names.isEmpty()) {
            return text;
        }
        Matcher field = (embedded ? EMBEDDED_JSON_FIELD : JSON_FIELD).matcher(text);
        Matcher structure = (embedded ? EMBEDDED_JSON_FIELD_STRUCTURE : JSON_FIELD_STRUCTURE).matcher(text);
        String masked = embedded ? "\\\"" + MASK + "\\\"" : "\"" + MASK + "\"";
        StringBuilder out = new StringBuilder(text.length());
        int copied = 0;
        for (int name : names) {
            if (name < copied) {
                continue;
            }
            if (structure.region(name, text.length()).lookingAt() && JWK_PRIVATE_MEMBERS.contains(structure.group(1))) {
                out.append(text, copied, structure.end()).append(masked);
                copied = endOfStructure(text, structure.end(), embedded);
            } else if (field.region(name, text.length()).lookingAt() && JWK_PRIVATE_MEMBERS.contains(field.group(1))) {
                out.append(text, copied, field.end(2)).append(masked);
                copied = field.end();
            }
        }
        return out.append(text, copied, text.length()).toString();
    }

    /** A JSON object found by {@link #objects}: where it starts and where each of its own members' names starts. */
    private record JsonObject(int start, List<Integer> names) {
    }

    /**
     * Where the JSON object that holds the member whose name starts at {@code member} starts, or -1 if
     * it is not in an object. Reads back from the member, skipping strings and closed brackets, and
     * jumping over each object already read (see {@link #objects}). Reading back to {@code outside}, a
     * member found not to be in an object, outside any string and bracket, ends the same way. In
     * embedded JSON, where an inner quote is {@code \"} and an escaped one {@code \\\"}, an unescaped
     * quote is the start of the outer string, so the member is not in embedded JSON.
     */
    private static int startOfObject(String text, int member, boolean embedded, Map<Integer, Integer> matching,
            int outside) {
        int depth = 0;
        boolean inString = false;
        for (int i = member - 1; i >= 0; i--) {
            char c = text.charAt(i);
            if (c == '"') {
                int run = backslashesBefore(text, i);
                if (embedded && run % 2 == 0) {
                    return -1;
                }
                if (run % (embedded ? 4 : 2) == (embedded ? 1 : 0)) {
                    inString = !inString;
                }
                i -= run;
                if (i == outside && !inString && depth == 0) {
                    return -1;
                }
            } else if (!inString && c == '}' && matching.containsKey(i)) {
                i = matching.get(i);
            } else if (!inString && (c == '}' || c == ']')) {
                depth++;
            } else if (!inString && (c == '{' || c == '[')) {
                if (depth == 0) {
                    return c == '{' ? i : -1;
                }
                depth--;
            }
        }
        return -1;
    }

    /**
     * Every JSON object from the one starting at {@code start} through its close bracket (or the end of
     * the text), the ones inside it included, with where each of its own members' names starts: the
     * opening quote, or in embedded JSON the backslash before it. Reads the text as
     * {@link #endOfStructure} does. {@code matching} maps each bracket of an object read so far to the
     * other one: this adds the objects it closes, and skips an object read before.
     */
    private static List<JsonObject> objects(String text, int start, boolean embedded, Map<Integer, Integer> matching) {
        List<JsonObject> found = new ArrayList<>();
        // The open objects, innermost last, with null for an open array.
        List<JsonObject> open = new ArrayList<>();
        boolean inString = false;
        boolean escaped = false;
        boolean nameNext = false;
        int i = start;
        while (i < text.length()) {
            int at = i;
            char c = text.charAt(i++);
            if (embedded && c == '"') {
                break;
            }
            if (embedded && c == '\\' && i < text.length()) {
                c = text.charAt(i++);
            }
            if (inString) {
                inString = escaped || c != '"';
                escaped = !escaped && c == '\\';
            } else if (c == '"') {
                inString = true;
                if (nameNext) {
                    open.getLast().names().add(at);
                    nameNext = false;
                }
            } else if (c == '{' && at > start && matching.containsKey(at)) {
                i = matching.get(at) + 1;
                nameNext = false;
            } else if (c == '{') {
                JsonObject object = new JsonObject(at, new ArrayList<>());
                found.add(object);
                open.add(object);
                nameNext = true;
            } else if (c == '[') {
                open.add(null);
                nameNext = false;
            } else if (c == ',') {
                nameNext = open.getLast() != null;
            } else if (c == '}' || c == ']') {
                JsonObject object = open.removeLast();
                if (object != null) {
                    matching.put(at, object.start());
                    matching.put(object.start(), at);
                }
                nameNext = false;
                if (open.isEmpty()) {
                    break;
                }
            }
        }
        return found;
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
     * ({@code Bearer [REDACTED]}). In a map with a {@code kty} key (a JWK) the
     * {@link #JWK_PRIVATE_MEMBERS} are masked too.
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
            boolean jwk = map.keySet().stream().anyMatch("kty"::equals);
            map.forEach((k, v) -> out.put(k instanceof String s ? redact(s) : k,
                    jwk && k instanceof String name && JWK_PRIVATE_MEMBERS.contains(name)
                            ? maskField(name, v)
                            : redactTree(String.valueOf(k), v)));
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
        if (value instanceof String s && keepsScheme(key)) {
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
