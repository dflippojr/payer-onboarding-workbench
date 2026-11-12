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
import java.util.Arrays;
import java.util.BitSet;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.IntPredicate;
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
 * of a JSON object with a {@code kty} member, also in JSON nested in JSON strings at any
 * depth), and the values of well-known secret fields such as {@code client_secret},
 * {@code access_token} and {@code private_key} in form and query bodies and in JSON (any
 * value, including an object such as a private JWK, also in JSON nested in JSON strings at any
 * depth and in JSON whose quotes are spelled {@code \\u0022}; see {@link #isSecretField(String)}). The value of a
 * credential header ({@link #isSensitiveHeader(String)}, such as {@code Cookie}) is
 * masked in a header map, in a {@code Name: value} line of free text and in a JSON field
 * of that name. A JSON member name is read as JSON reads it, a {@code \\u} escape as the
 * character it spells ({@code "kt\\u0079"} is {@code kty}). It is a safety net, not a
 * guarantee: callers should still avoid passing secrets around in the first place.
 *
 * <p>Out of scope (#262): other schemes in free text, such as {@code Digest response=...}
 * (an {@code Authorization} header or line is still masked whole); URL-encoded separators
 * after any scheme but {@code Bearer}; JWK member names outside an object with a
 * {@code kty} member, so an ordinary field named {@code d} or {@code k} is kept (except in
 * text too tangled to find the JWKs in linear time, where every such name is masked); in a
 * name in embedded JSON, a {@code \\u} escape whose own {@code u} or hex digits the outer
 * string spells as escapes too.
 */
public final class Redactor {

    /** Replacement text for masked material. */
    public static final String MASK = "[REDACTED]";

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \\1-----", Pattern.DOTALL);

    /**
     * A private key header, PEM or PGP ({@code PRIVATE KEY BLOCK}), not already masked. One that is in no
     * {@link #PEM_BLOCK} has no matching footer (a truncated paste) and is masked to the end of the text.
     */
    private static final Pattern UNTERMINATED_PEM_KEY = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----(?!\\s*" + Pattern.quote(MASK) + ")");

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
     * A JSON escape of any whitespace {@code \s} matches (space, tab, line feed, vertical tab, form feed, carriage
     * return), also escaped again: {@code \t}, {@code \n}, {@code \f}, {@code \r} or a {@code \}{@code uXXXX} escape
     * ({@code 0020}, {@code 0009} to {@code 000D}, either case). After a scheme it is the whitespace it stands for, as
     * {@link #ESCAPED_TOKEN_CHAR} is the character it stands for, so a serializer that writes
     * {@code Bearer<tab><token>} as {@code Bearer\t<token>} does not hide the token (#212).
     */
    private static final String ESCAPED_WHITESPACE = "\\\\++(?:[nrtf]|u00(?:20|0[9A-D]))";

    /** {@link #ESCAPED_WHITESPACE} of a space or tab only. */
    private static final String ESCAPED_SPACE_OR_TAB = "\\\\++(?:t|u00(?:20|09))";

    /**
     * A scheme (group 1), its token68 part (group 2, which may be URL-encoded) and anything else up to
     * the next whitespace, quote, comma, semicolon or backslash (group 3), so a {@code token:suffix} is
     * masked whole. After {@code Bearer} the space may be URL-encoded too ({@code Bearer%20},
     * {@code Bearer+}), also right after another escape ({@code %3A%20Bearer%20}). After {@code Token}
     * and {@code DPoP}, ordinary words, only spaces and tabs are: a word on the next line
     * ({@code a bearer token}, then a JWT) is not their credential. The whitespace may be written as a JSON
     * escape ({@link #ESCAPED_WHITESPACE}, after {@code Token} and {@code DPoP} {@link #ESCAPED_SPACE_OR_TAB}),
     * read in place, not decoded first. Both parts read a
     * JSON escape of a token character ({@link #ESCAPED_TOKEN_CHAR}) as the character it stands for,
     * so a token quoted by a serializer that escapes some of its characters
     * ({@code tok\/en}, {@code tok}{@code \}{@code u002Ben}) is masked whole too. Case-insensitive, so
     * the escapes' hex digits may be either case. Possessive quantifiers, as in {@link #JSON_FIELD}.
     */
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)(?:" + WORD_START + "|(?<=%[0-9A-F]{2})(?=Bearer))(Bearer|Basic|Token|DPoP)"
                    + "(?:(?:[ \\t]|" + ESCAPED_SPACE_OR_TAB + ")++|(?<=Bearer|Basic)(?:\\s|" + ESCAPED_WHITESPACE + ")++"
                    + "|(?<=Bearer)(?:%20|\\+))(?!(?:realm|error|error_description|scope)\\s*=\\s*[^\\s,])"
                    + "((?:[A-Za-z0-9\\-._~+/%]++|" + ESCAPED_TOKEN_CHAR + ")++=*)"
                    + "((?:[^\\s\"',;\\\\]++|" + ESCAPED_TOKEN_CHAR + ")*+)");

    /** Short all-letter words after a scheme are prose ("missing bearer token."), not credentials. */
    private static final Pattern PROSE_WORD = Pattern.compile("[A-Za-z]{1,15}[.)]*");

    /**
     * A signed JWT. Each run of token characters is tried once, from its start, up to its first {@code eyJ} at a word
     * start (#310): every later {@code eyJ} in that run meets the same dots, so it cannot match where the first did
     * not, and retrying each one makes {@code eyJ-eyJ-eyJ-...} quadratic. Whatever comes before that {@code eyJ} is in
     * group 1 and goes back unchanged.
     */
    private static final Pattern JWT = Pattern.compile(
            "(?<![A-Za-z0-9_-])((?>[A-Za-z0-9_-]*?" + WORD_START + "eyJ)[A-Za-z0-9_-]*+)"
                    + "\\.([A-Za-z0-9_-]*+)\\.[A-Za-z0-9_-]++");

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

    /** A literal backslash, as a regex. */
    private static final String BACKSLASH = "\\\\";

    /**
     * A character of a JSON member name: a letter, {@code _} or {@code -}, or the {@code \\u} escape of
     * any character, as JSON may spell one ({@code "kt\\u0079"} is {@code kty}). {@link #decodeName}
     * gives the name the escapes spell, which is the one compared.
     */
    private static final String NAME_CHAR = "(?:[A-Za-z_-]|" + BACKSLASH + "u[0-9A-Fa-f]{4})";

    /**
     * {@link #NAME_CHAR} in JSON embedded in a JSON string: the inner escape's backslash is escaped
     * ({@code \\\\u0064}), or the outer string spells the character itself ({@code \\u0064}).
     */
    private static final String EMBEDDED_NAME_CHAR = "(?:[A-Za-z_-]|" + BACKSLASH + "{1,2}u[0-9A-Fa-f]{4})";

    /** A {@code \\u} escape in a name matched with {@link #NAME_CHAR} or {@link #EMBEDDED_NAME_CHAR}. */
    private static final Pattern NAME_ESCAPE = Pattern.compile(BACKSLASH + "++u([0-9A-Fa-f]{4})");

    /** A unicode escape, from its backslash: {@code u} and four hex digits, either case. */
    private static final Pattern UNICODE_ESCAPE = Pattern.compile(BACKSLASH + "u([0-9A-Fa-f]{4})");

    /** The {@code kty} member name, each letter also as a {@code \\u} escape; it starts at the opening quote. */
    private static final Pattern KTY_NAME = Pattern.compile("\"" + spelled("kty", false) + "\"");

    /** The {@code kty} member that makes a JSON object a JWK; it starts at the name's opening quote. */
    private static final Pattern JWK_TYPE = Pattern.compile(KTY_NAME.pattern() + "\\s*:");

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
            "\"(" + NAME_CHAR + "{1,64})\"(\\s*:\\s*)(?:\"((?:[^\"\\\\]++|\\\\.)*+)(?:\"|\\\\?+(?=\\R|\\z))|"
                    + JSON_SCALAR + ")");

    /** Any character but a quote or backslash, as a regex. */
    private static final String PLAIN = "[^\"\\\\]";

    /** Whitespace in JSON embedded in a JSON string, where a line break or tab is escaped. */
    private static final String EMBEDDED_SPACE = "(?:\\s|" + BACKSLASH + "[nrt])*+";

    /**
     * The same inside JSON that is itself embedded in a JSON string ({@code {\"key\": \"value\"}}),
     * where the inner string's own escapes are escaped again: an inner {@code \\} is four backslashes
     * and an inner {@code \"} three and a quote. A string cut off by the end of the text counts too,
     * and so does one cut off by the end of the outer string (an unescaped quote): embedded JSON that
     * was truncated before it was quoted. Either cut may leave up to three backslashes of an escape,
     * and a cut at the end of the text may be followed by a line break, as in {@link #JSON_FIELD}. The outer
     * string may spell the closing quote {@code \\u0022}.
     */
    private static final Pattern EMBEDDED_JSON_FIELD = Pattern.compile(
            BACKSLASH + "\"(" + EMBEDDED_NAME_CHAR + "{1,64})" + BACKSLASH + "\"(" + EMBEDDED_SPACE + ":" + EMBEDDED_SPACE + ")(?:"
                    + BACKSLASH + "\"((?:" + PLAIN + "++"
                    + "|" + BACKSLASH.repeat(4) + "|" + BACKSLASH.repeat(3) + "\"|" + BACKSLASH.repeat(2) + PLAIN
                    + "|" + BACKSLASH + "(?!u0022)" + PLAIN + ")*+)(?:" + BACKSLASH + "(?:\"|u0022)|(?:" + BACKSLASH
                    + "){0,3}+(?=\"|\\R|\\z))|"
                    + JSON_SCALAR + ")");

    /** A JSON field whose value is an object or array; group 1 is the name. */
    private static final Pattern JSON_FIELD_STRUCTURE = Pattern.compile("\"(" + NAME_CHAR + "{1,64})\"\\s*:\\s*(?=[{\\[])");

    /** The same inside JSON embedded in a JSON string. */
    private static final Pattern EMBEDDED_JSON_FIELD_STRUCTURE = Pattern.compile(
            BACKSLASH + "\"(" + EMBEDDED_NAME_CHAR + "{1,64})" + BACKSLASH + "\"" + EMBEDDED_SPACE + ":" + EMBEDDED_SPACE
                    + "(?=[{\\[])");

    /**
     * A JSON member name and its colon in a view {@link #readNestedLevels} gives, or in the text; group 1 is the name.
     * Its whitespace may be escaped, as in {@link #EMBEDDED_SPACE}: a view keeps every escape but a quote's and a
     * backslash's, so whitespace the text escapes more than once still reads as escaped there.
     */
    private static final Pattern FIELD_NAME = Pattern.compile("\"(" + NAME_CHAR + "{1,64})\"" + EMBEDDED_SPACE + ":");

    /** {@link #JSON_FIELD} with whitespace as in {@link #FIELD_NAME}; group 1 is the name, group 3 a string's content. */
    private static final Pattern VIEW_JSON_FIELD = Pattern.compile(
            "\"(" + NAME_CHAR + "{1,64})\"(" + EMBEDDED_SPACE + ":" + EMBEDDED_SPACE + ")(?:\"((?:[^\"\\\\]++|\\\\.)*+)"
                    + "(?:\"|\\\\?+(?=\\R|\\z))|" + JSON_SCALAR + ")");

    /** {@link #JSON_FIELD_STRUCTURE} with whitespace as in {@link #FIELD_NAME}. */
    private static final Pattern VIEW_JSON_FIELD_STRUCTURE = Pattern.compile(
            "\"(" + NAME_CHAR + "{1,64})\"" + EMBEDDED_SPACE + ":" + EMBEDDED_SPACE + "(?=[{\\[])");

    /** The same inside JSON embedded in a JSON string, as {@link #EMBEDDED_JSON_FIELD} starts; it starts at the backslash. */
    private static final Pattern EMBEDDED_FIELD_NAME = Pattern.compile(
            BACKSLASH + "\"(" + EMBEDDED_NAME_CHAR + "{1,64})" + BACKSLASH + "\"" + EMBEDDED_SPACE + ":");

    /**
     * For each reading of {@link #secretFieldMasks} ({@code PLAIN_READING}, {@code EMBEDDED_READING},
     * {@code FLAT_READING}): the pattern that finds a name, the one for a name before an object or array, and the one for
     * a name and its string or scalar value.
     */
    private static final Reading[] READINGS = {
        new Reading(FIELD_NAME, VIEW_JSON_FIELD_STRUCTURE, VIEW_JSON_FIELD),
        new Reading(EMBEDDED_FIELD_NAME, EMBEDDED_JSON_FIELD_STRUCTURE, EMBEDDED_JSON_FIELD),
        new Reading(FIELD_NAME, VIEW_JSON_FIELD_STRUCTURE, VIEW_JSON_FIELD),
    };

    /** A {@link #READINGS} entry: the pattern for a name, for a name before an object or array, and for a name and value. */
    private record Reading(Pattern name, Pattern structure, Pattern field) {
    }

    /** {@link #KTY_NAME} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_KTY_NAME = Pattern.compile(
            BACKSLASH + "\"" + spelled("kty", true) + BACKSLASH + "\"");

    /** {@link #JWK_TYPE} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_JWK_TYPE = Pattern.compile(EMBEDDED_KTY_NAME.pattern() + EMBEDDED_SPACE + ":");

    /** The name of a {@link #JWK_PRIVATE_MEMBERS} field, each letter also as a {@code \\u} escape, through its colon. */
    private static final Pattern JWK_PRIVATE_NAME = Pattern.compile("\"" + privateNames(false) + "\"\\s*:");

    /** {@link #JWK_PRIVATE_NAME} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_JWK_PRIVATE_NAME = Pattern.compile(
            BACKSLASH + "\"" + privateNames(true) + BACKSLASH + "\"" + EMBEDDED_SPACE + ":");

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
     * {@code name} (lower-case letters) as a regex for a JSON member name: each letter as it is, or as
     * its {@code \\u} escape in either hex case, its backslash as in {@link #NAME_CHAR} or, if
     * {@code embedded}, {@link #EMBEDDED_NAME_CHAR}.
     */
    private static String spelled(String name, boolean embedded) {
        String escape = embedded ? BACKSLASH + "{1,2}u00" : BACKSLASH + "u00";
        return name.chars()
                .mapToObj(c -> "(?:" + (char) c + "|" + escape + "(?i:" + Integer.toHexString(c) + "))")
                .collect(Collectors.joining());
    }

    /** The {@link #JWK_PRIVATE_MEMBERS} names, {@link #spelled} as in JSON, as a regex alternation. */
    private static String privateNames(boolean embedded) {
        return JWK_PRIVATE_MEMBERS.stream().map(name -> spelled(name, embedded)).collect(Collectors.joining("|", "(?:", ")"));
    }

    /**
     * The member name a name matched with {@link #NAME_CHAR} or {@link #EMBEDDED_NAME_CHAR} spells, each
     * {@code \\u} escape decoded: the name JSON reads, so {@code "\\u0064"} is {@code d}.
     */
    static String decodeName(String name) {
        if (name.indexOf('\\') < 0) {
            return name;
        }
        return NAME_ESCAPE.matcher(name).replaceAll(m ->
                Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1), 16))));
    }

    /**
     * Returns {@code text} with credential material masked, or {@code null} if
     * {@code text} is {@code null}.
     */
    public static String redact(String text) {
        return redact(text, null);
    }

    /**
     * {@link #redact(String)}, adding to {@code reads}, unless it is {@code null}, each read JWK discovery makes:
     * at which escape level, and how much of that level's budget was left before and after it.
     */
    static String redact(String text, List<DiscoveryRead> reads) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        // The JWKs' private members and the PEM and PGP blocks are found in the text as it came, and masked
        // together: masking either first would hide the other (an unterminated block masked to the end of the
        // text may hold the JWK's kty; a JWK member's mask may hold the block's header).
        Discovery discovery = new Discovery(text.length(), reads);
        List<Mask> masks = jwkMasks(text, discovery);
        List<Mask> pem = pemMasks(text);
        masks.addAll(pem);
        // So are the secret names no strict reading reads (fail closed, owner decision on #339): the string a JWK read
        // masks whole, as one holding JSON nested deeper than NESTED_LEVELS, may hold such a name but not its value, which
        // the name's mask then still covers ({"password\u005c...u0022:"s3cr3t"}, review on a7a1eef).
        masks.addAll(unconsumedSecretNameMasks(text));
        String out = applyMasks(text, masks);
        // A stray quote in a masked block may have hidden a JWK member from that read ({"kty":"RSA","note":
        // "-----BEGIN PRIVATE KEY-----"-----END PRIVATE KEY-----","d":...}): with the blocks masked, the JWKs are
        // found once more, spending what that read left of each level's budget, but never more than a first read of
        // the shortened text would get, with the same fallback once it is spent. This only adds masks.
        if (!pem.isEmpty()) {
            discovery.readAgain();
            out = applyMasks(out, jwkMasks(out, discovery));
        }
        out = maskSchemeCredentials(out);
        out = JWT.matcher(out).replaceAll("$1.$2." + Matcher.quoteReplacement(MASK));
        // Before the patterns read the text itself, so a secret object those would cut at a bracket inside a string quoted
        // with \\u0022 is read whole in the flattened view first (review on 9de277d); they then find its mask and keep it.
        // Fail closed (owner decision on #339): every secret name no strict reading of its level reads is masked from its
        // colon first, on the text as it came, and again at the end, after the passes below.
        out = maskUnconsumedSecretNames(out);
        out = maskNestedSecretFields(out);
        out = maskStructures(out, JSON_FIELD_STRUCTURE, false);
        out = maskStructures(out, EMBEDDED_JSON_FIELD_STRUCTURE, true);
        out = JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretKey(decodeName(m.group(1)))
                ? "\"" + m.group(1) + "\"" + m.group(2) + "\"" + masked(decodeName(m.group(1)), m.group(3)) + "\""
                : m.group()));
        out = EMBEDDED_JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecretKey(decodeName(m.group(1)))
                ? "\\\"" + m.group(1) + "\\\"" + m.group(2) + "\\\"" + masked(decodeName(m.group(1)), m.group(3)) + "\\\""
                : m.group()));
        out = FORM_SECRET.matcher(out).replaceAll("$1=" + Matcher.quoteReplacement(MASK));
        out = HEADER_LINE.matcher(out).replaceAll(Redactor::maskHeaderLine);
        out = maskEscapedHeaderLines(out);
        return maskUnconsumedSecretNames(out);
    }

    /**
     * Masks every credential {@link #AUTH_SCHEME} finds, keeping the scheme ({@code Bearer [REDACTED]}).
     * A match kept as prose ({@link #isProse}) is read again from its word, so a scheme there
     * ({@code token DPoP <credential>}) is found too.
     */
    private static String maskSchemeCredentials(String text) {
        Matcher m = AUTH_SCHEME.matcher(text);
        StringBuilder out = null;
        int copied = 0;
        int from = 0;
        while (from < text.length() && m.find(from)) {
            if (isProse(m)) {
                from = m.end(1);
                continue;
            }
            out = out == null ? new StringBuilder(text.length()) : out;
            out.append(text, copied, m.start()).append(m.group(1)).append(' ').append(MASK);
            copied = m.end();
            from = copied;
        }
        return out == null ? text : out.append(text, copied, text.length()).toString();
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
     * with the period that ends a sentence after it. So is an arrow after {@code Token}, as the app's own
     * log lines put one after a token endpoint ({@code POST /oauth/token -> 200}); any other punctuation, and
     * an arrow after any other scheme, may be a credential ({@code Bearer -._~+/=}).
     */
    private static boolean isProse(MatchResult m) {
        String word = m.group(2) + m.group(3);
        boolean token = m.group(1).equalsIgnoreCase("Token");
        if (token && word.equals("->")) {
            return true;
        }
        // Token is also an ordinary word, as in "token endpoint: <url>".
        if (token && word.endsWith(":")) {
            word = word.substring(0, word.length() - 1);
        }
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
            if (isSecretKey(decodeName(m.group(1)))) {
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
        return endOfStructure(text, start, embedded, i -> false);
    }

    /**
     * {@link #endOfStructure} that, read as plain JSON, also ends at a quote {@code outer} names: one of a level above,
     * which ends the string holding the structure.
     */
    private static int endOfStructure(String text, int start, boolean embedded, IntPredicate outer) {
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
            if (!embedded && c == '"' && outer.test(i - 1)) {
                return i - 1;
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
     * {@link #endOfStructure} in a {@link #flattened} view. A quote the view turned
     * bare ({@code quotes}) inside a value a plain quote opens (after a colon, or an array item) is that string's own
     * {@code \\u0022}, not its closing quote (review on 84afef7: the object in {@code {"note":"a\\u0022{"}} ran on to
     * the end of the text). In a name a plain quote opens, such a quote closes the name only before its colon, so a name
     * may open with a plain quote and close with {@code \\u0022} (review on 22ff6ea) and still hold one elsewhere
     * ({@code "pass\\u0022word"}); the view turns it bare only where the name is not valid on its own
     * ({@link FlatContext}). A string such a quote opens closes at a quote of either kind. It also ends at a quote
     * {@code outer} names.
     */
    private static int endOfFlatStructure(String json, int start, BitSet quotes, IntPredicate outer) {
        BitSet arrays = new BitSet();
        int depth = 0;
        char before = 0;
        boolean inString = false;
        boolean plainValue = false;
        boolean plainName = false;
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && outer.test(i)) {
                return i;
            }
            if (inString) {
                boolean own = quotes.get(i) && (plainValue || (plainName && !beforeColon(json, i + 1)));
                inString = escaped || c != '"' || own;
                escaped = !escaped && c == '\\';
                continue;
            }
            if (c == '"') {
                inString = true;
                boolean value = before == ':' || (arrays.get(depth) && (before == '[' || before == ','));
                plainValue = value && !quotes.get(i);
                plainName = !value && !quotes.get(i);
            } else if (c == '{' || c == '[') {
                arrays.set(++depth, c == '[');
            } else if ((c == '}' || c == ']') && --depth == 0) {
                return i + 1;
            }
            if (!Character.isWhitespace(c)) {
                before = c;
            }
        }
        return json.length();
    }

    /**
     * For each position in {@code json}, where the string holding the JSON there ends: at the next quote of the level
     * above ({@code outer}, before the backslash a level down shows in front of it) or, for embedded JSON, the next bare
     * quote; else at the end. Read once from the end, so it costs one pass.
     */
    private static int[] stringEnds(String json, boolean embedded, IntPredicate outer) {
        int[] ends = new int[json.length() + 1];
        int next = json.length();
        ends[json.length()] = next;
        for (int k = json.length() - 1; k >= 0; k--) {
            if (json.charAt(k) == '"') {
                if (outer.test(k)) {
                    next = k > 0 && json.charAt(k - 1) == '\\' ? k - 1 : k;
                } else if (embedded && backslashesBefore(json, k) % 2 == 0) {
                    next = k;
                }
            }
            ends[k] = Math.min(next, json.length());
        }
        return ends;
    }

    /**
     * For a value the flattened view closes at the quote at {@code close} in {@code json}: where the value ends when that
     * quote is read as escaped instead, or {@code -1} when it is not. A quote the view turned bare from {@code \\u0022}
     * after a number of backslashes that is 2 more than a multiple of 4 ({@code \\\\\\u0022} in the text) is an
     * escaped backslash and a quote at the view's level, and, read as text copied from inside a JSON string, an escaped
     * quote one level down (review on 92c40cb). Read that way the value goes on to the next quote that closes it there:
     * a turned-bare one after a multiple of 4 backslashes, or a plain one after an even number, else to {@code limit}.
     */
    private static int escapedQuoteEnd(String json, int close, int limit, BitSet quotes) {
        if (close >= json.length() || !quotes.get(close) || backslashesBefore(json, close) % 4 != 2) {
            return -1;
        }
        for (int k = json.indexOf('"', close + 1); k >= 0 && k < limit; k = json.indexOf('"', k + 1)) {
            int run = backslashesBefore(json, k);
            if (quotes.get(k) ? run % 4 == 0 : run % 2 == 0) {
                return k;
            }
        }
        return limit;
    }

    /**
     * Whether a value's closing quote just before {@code at} in {@code json} ends it: at the end, or before whitespace, a
     * separator, a bracket, a colon, a quote or an escape. Before anything else (a name, as in {@code "x"n":1}), the
     * quote is the value's only by a misreading.
     */
    private static boolean endsValue(String json, int at) {
        return at >= json.length() || ",}]:\"\\".indexOf(json.charAt(at)) >= 0 || Character.isWhitespace(json.charAt(at));
    }

    /**
     * Whether the string from {@code from} in {@code text}, a name a plain quote opens, closes with a plain quote that a
     * colon follows: a valid name, whose {@code \\u0022} escapes are its own however a colon follows them
     * ({@code "note\\u0022:foo":}, security round 3). It reads to the first plain quote, which the caller then reads
     * past, so the work stays linear.
     */
    private static boolean closesAsName(String text, int from) {
        int i = from;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '\\') {
                i += 2;
            } else if (c == '"') {
                return beforeColon(text, i + 1);
            } else {
                i++;
            }
        }
        return false;
    }

    /** Whether the next character from {@code from} in {@code json} that is not whitespace is a colon. */
    private static boolean beforeColon(String json, int from) {
        int i = from;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        return i < json.length() && json.charAt(i) == ':';
    }

    /**
     * Masks the {@link #JWK_PRIVATE_MEMBERS} of every JSON object with a {@code kty} member, as a secret
     * field is masked: a string or scalar value becomes the mask, and so does an object or array, through
     * its close bracket. Only the JWK's own members count, not those of an object inside or next to it.
     * Finding the JWKs reads at most {@code 4n + 1024} characters of a text of length {@code n}, then
     * masks every private member name in the text instead, in a JWK or not: text that spends that budget
     * is nothing a payer would send, so it is over-masked rather than read for longer. {@code characters} is the
     * budget; {@link #redact(String)} gives {@code 4n + 1024}. {@code embedded}: JSON embedded in a JSON string.
     */
    static String maskJwks(String text, boolean embedded, int characters) {
        List<JwkValue> values = jwkValues(text, embedded, new int[] {characters});
        if (values.isEmpty()) {
            return text;
        }
        String masked = embedded ? "\\\"" + MASK + "\\\"" : "\"" + MASK + "\"";
        StringBuilder out = new StringBuilder(text.length());
        int copied = 0;
        for (JwkValue value : values) {
            out.append(text, copied, value.start()).append(masked);
            copied = value.end();
        }
        return out.append(text, copied, text.length()).toString();
    }

    /**
     * Where the value of each JWK private member that {@link #maskJwks(String, boolean, int)} masks starts and
     * ends, in order and apart: the opening quote (or bracket) through the closing quote (or bracket), and
     * where the member's name starts (its opening quote, or in embedded JSON the backslash before it). The
     * searches spend {@code budget[0]}, one character a step, and leave in it what is left (below 0 once spent).
     */
    private static List<JwkValue> jwkValues(String text, boolean embedded, int[] budget) {
        Matcher type = (embedded ? EMBEDDED_JWK_TYPE : JWK_TYPE).matcher(text);
        Matcher kty = (embedded ? EMBEDDED_KTY_NAME : KTY_NAME).matcher(text);
        // Where the text read by objects() so far ends: every object before it is known.
        int readEnd = 0;
        Map<Integer, Integer> matching = new HashMap<>();
        TreeSet<Integer> names = new TreeSet<>();
        // The last kty found not to be in an object, and how its search ended.
        int outside = -1;
        int outsideResult = NOT_IN_BRACKETS;
        while (type.find()) {
            int member = type.start();
            if (member < readEnd || !opensName(text, member, embedded, budget)) {
                continue;
            }
            int start = startOfObject(text, member, embedded, matching, outside, outsideResult, budget);
            if (start == OUT_OF_TIME) {
                names = everyPrivateMember(text, embedded);
                break;
            }
            if (start < 0) {
                outside = member;
                outsideResult = start;
                continue;
            }
            List<JsonObject> objects = new ArrayList<>();
            int end = objects(text, start, embedded, matching, objects, budget);
            if (end == OUT_OF_TIME) {
                names = everyPrivateMember(text, embedded);
                break;
            }
            readEnd = end;
            for (JsonObject object : objects) {
                if (object.names().stream().anyMatch(name -> kty.region(name, text.length()).lookingAt())) {
                    names.addAll(object.names());
                }
            }
        }
        List<JwkValue> values = new ArrayList<>();
        Matcher field = (embedded ? EMBEDDED_JSON_FIELD : JSON_FIELD).matcher(text);
        Matcher structure = (embedded ? EMBEDDED_JSON_FIELD_STRUCTURE : JSON_FIELD_STRUCTURE).matcher(text);
        int copied = 0;
        // The length of a quote: an embedded one has a backslash before it.
        int quote = embedded ? 2 : 1;
        for (int name : names) {
            // A name inside a value already masked goes with it, except one that opens on the quote that closed
            // that value (malformed: {"d":""p":...}), whose own value still comes after it.
            if (name < copied - quote) {
                continue;
            }
            if (structure.region(name, text.length()).lookingAt() && structure.end() >= copied
                    && JWK_PRIVATE_MEMBERS.contains(decodeName(structure.group(1)))) {
                copied = endOfStructure(text, structure.end(), embedded);
                values.add(new JwkValue(structure.end(), copied, name));
            } else if (field.region(name, text.length()).lookingAt() && field.end(2) >= copied
                    && JWK_PRIVATE_MEMBERS.contains(decodeName(field.group(1)))) {
                copied = field.end();
                values.add(new JwkValue(field.end(2), copied, name));
            }
        }
        return values;
    }

    /** A JWK private member's value found by {@link #jwkValues}: where it starts and ends, and where its name starts. */
    private record JwkValue(int start, int end, int name) {
    }

    /** The most levels of JSON nested in JSON strings that {@link #maskNestedJwks(String, int)} reads one by one. */
    static final int NESTED_LEVELS = 16;

    /**
     * Masks the {@link #JWK_PRIVATE_MEMBERS} of the JWKs nested in JSON strings that {@link #maskJwks(String,
     * boolean, int)} does not reach: two or more levels deep (a JWK in a JSON string in a JSON string), or spelled
     * with unicode escapes ({@code \\u0022} for a quote, {@code \\u003A} for a colon). Each round reads the
     * next level down as JSON embedded one level deep: it decodes the unicode escapes of the outermost string
     * of a view of the text ({@link #normalized}), masks that view's JWKs as {@code maskJwks} does, then takes
     * that level of escaping off ({@link #unescaped}). Each mask is quoted with the quote of its member's name
     * as the text spells it, so it is never longer than what it replaces. There are at most
     * {@link #NESTED_LEVELS} rounds, each reading at most {@code 4n + 1024} characters of a view no longer than
     * the text; JSON nested deeper than that is nothing a payer sends, and each string that holds it is masked
     * whole instead. {@code characters} is the budget to read in each round, or {@code 4m + 1024} for a view
     * of length {@code m} if it is negative, as {@link #redact(String)} reads.
     */
    static String maskNestedJwks(String text, int characters) {
        return applyMasks(text, nestedJwkMasks(text, characters, null));
    }

    /**
     * What {@link #maskNestedJwks(String, int)} masks, as masks on the text. With a {@code discovery}, each round
     * spends that level's budget there instead of {@code characters}.
     */
    private static List<Mask> nestedJwkMasks(String text, int characters, Discovery discovery) {
        List<Mask> masks = new ArrayList<>();
        View deepest = readNestedLevels(text, (view, normal, depth, fresh) -> {
            String json = normal.text();
            // With no quote one level deep, the view holds no JWK maskJwks would find in embedded JSON.
            if (json.contains("\\\"")) {
                List<JwkValue> values = discovery != null ? discovery.read("nested " + depth, json, true,
                        discovery.nested(depth, json.length()))
                        : jwkValues(json, true, new int[] {characters < 0 ? 4 * json.length() + 1024 : characters});
                for (JwkValue value : values) {
                    String quote = quoteOf(text, normal, value.name(), 2);
                    masks.add(new Mask(normal.at(value.start()), normal.at(value.end()), quote + MASK + quote));
                }
            }
            flatJwkMasks(text, view, depth, fresh, characters, discovery, masks);
        });
        if (deepest != null) {
            List<Mask> strings = stringsHoldingEscapes(text);
            masks.addAll(strings);
            // A string found only in a view (its quotes spelled as unicode escapes in the text) has no bare
            // quote to bound it by: with an escape still unread outside every string found, mask the text
            // whole.
            if (!holdsEveryEscape(strings, deepest)) {
                masks.add(new Mask(0, text.length(), MASK));
            }
        }
        return masks;
    }

    /**
     * Adds to {@code masks} the JWK private members no other read finds because the text spells some of a JWK's quotes
     * {@code \\u0022} and the rest plain ({@code {"kty":"oct",\\u0022d\\u0022:"x"}}, #352): the normalized view decodes
     * them to {@code \\"}, a level below the plain {@code "kty"}, so no reading of it holds both. The level's
     * {@link #flattened} view turns them bare, at the level of the view's own quotes, and is read here as plain JSON,
     * spending the level's nested budget. A string value's mask keeps the text's spelling of its quotes; an object, array
     * or scalar's is quoted as the member's name is.
     */
    private static void flatJwkMasks(String text, View view, int depth, BitSet fresh, int characters, Discovery discovery,
            List<Mask> masks) {
        View flat = flattened(view, new BitSet(), fresh);
        if (flat == null) {
            return;
        }
        String json = flat.text();
        List<JwkValue> values = discovery != null ? discovery.read("nested " + depth, json, false,
                discovery.nested(depth, json.length()))
                : jwkValues(json, false, new int[] {characters < 0 ? 4 * json.length() + 1024 : characters});
        for (JwkValue value : values) {
            int start = value.start();
            int end = value.end();
            boolean string = json.charAt(start) == '"';
            String open = quoteOf(text, flat, string ? start : value.name(), 1);
            String close = string && end - 1 > start && json.charAt(end - 1) == '"' ? quoteOf(text, flat, end - 1, 1) : open;
            masks.add(new Mask(flat.at(start), flat.at(end), open + MASK + close));
        }
    }

    /**
     * Reads one view of the text that {@link #readNestedLevels} gives: the view before its unicode escapes are decoded,
     * the view {@link #normalized}, the escape level it reads, and where in the text each quote starts that taking the
     * level above's escaping off made ({@link #unescaped}; {@code null} at depth 1, where every quote is the level's).
     */
    @FunctionalInterface
    private interface LevelReader {
        void read(View view, View normal, int depth, BitSet fresh);
    }

    /**
     * Gives {@code reader}, level by level, each view of the text that holds JSON nested in JSON strings beyond what
     * the plain and embedded patterns read on the text itself: two or more levels deep, or spelled with unicode
     * escapes. Each view is {@link #normalized} and reads the next level down as JSON embedded one level deep; the
     * next view takes that level of escaping off ({@link #unescaped}). There are at most {@link #NESTED_LEVELS}
     * views, each no longer than the text, so the walk is linear in its length. Returns the deepest view when the
     * text still holds an escape after the last level (JSON nested deeper than {@code NESTED_LEVELS}), else
     * {@code null}.
     */
    private static View readNestedLevels(String text, LevelReader reader) {
        // No quote with three backslashes before it and no unicode escape: all JSON is plain or one level deep,
        // where the patterns on the text itself read it.
        if (!text.contains("\\\\\\\"") && !UNICODE_ESCAPE.matcher(text).find()) {
            return null;
        }
        View view = new View(text, null);
        BitSet fresh = null;
        for (int depth = 1; ; depth++) {
            View normal = normalized(view);
            String json = normal.text();
            // One level deep with no unicode escape to decode, the text itself is this view.
            if (depth > 1 || normal != view) {
                reader.read(view, normal, depth, fresh);
            }
            if (!json.contains("\\\"") && !UNICODE_ESCAPE.matcher(json).find()) {
                return null;
            }
            if (depth == NESTED_LEVELS) {
                return normal;
            }
            fresh = new BitSet();
            view = unescaped(normal, fresh);
        }
    }

    /**
     * The opening quote, {@code length} characters of {@code normal}, of the member name that starts at {@code name}
     * there, as the text spells it
     * ({@code \"}, {@code \\\"}, {@code \\u0022}...): a mask quoted with it reads at that name's level.
     */
    private static String quoteOf(String text, View normal, int name, int length) {
        return text.substring(normal.at(name), normal.at(name + length));
    }

    /**
     * A quote as some escape level spells it: a run of backslashes, each also spelled {@code \\u005c} by the level
     * above, then a quote or a {@code \\u0022} escape. A {@code u005c} or {@code u0022} counts after a backslash or
     * after a {@code u005c} that does, so a chain of {@code \\u005c} escapes ({@code \\u005cu005cu0022}) is a quote
     * at any depth (owner decision on #339, 2026-11-09; review on a7a1eef). {@link #quoteLevel} says which level it is
     * a quote of, decoding the chain at most {@link #NESTED_LEVELS} times; a chain deeper than that is a quote of no
     * level, which no strict reading reads, so a secret name quoted with it is masked.
     */
    private static final String ANY_QUOTE = "(?:\\\\|(?<=\\\\|u005[cC])u005[cC])*+(?:\"|(?<=\\\\|u005[cC])u0022)";

    /** A backslash as any escape level spells it: a backslash, then more of them or {@code \\u005c} escapes of one. */
    private static final String ANY_BACKSLASH = "\\\\(?:\\\\|u005[cC])*+";

    /**
     * A {@code \\u} escape whose backslash is spelled as {@link #ANY_BACKSLASH}, its four hex digits in group 1; not a
     * {@code \\u005c} itself, which is a backslash, in no secret name, so a run of them splits into escapes one way only.
     */
    private static final Pattern ANY_UNICODE_ESCAPE = Pattern.compile(ANY_BACKSLASH + "u(?!005[cC])([0-9A-Fa-f]{4})");

    /**
     * From just after a name's opening quote: the name (group 1, a secret one if {@link #isSecretKey(String)} says so
     * of it decoded), its closing quote (group 2) spelled as {@link #ANY_QUOTE} however the opening one is, whitespace
     * written plainly or escaped at any level, and the colon, which may be a {@code \\u003a} escape. The backslash of
     * each escape in the name or the colon may be spelled through a chain of {@code \\u005c} escapes too. With the opening
     * quote ({@link #maskUnconsumedSecretNames}), every place any reading of any level may find a secret field.
     */
    private static final Pattern ANY_SECRET_NAME = Pattern.compile(
            "((?:[A-Za-z_-]|" + ANY_BACKSLASH + "u(?!005[cC])[0-9A-Fa-f]{4}){1,64}?)(" + ANY_QUOTE + ")"
            + "(?:\\s|(?:\\\\|u005[cC])++(?:[nrt]|u00(?:20|09|0[aAdD])))*+(?::|(?:\\\\|u005[cC])*+(?<=\\\\|u005[cC])u003[aA])");

    /** What a {@link Decoder} reads at the end of its level: the end of the text, or the quote closing the string. */
    private static final int END = -1;

    /** What a {@link Decoder} reads where its level is not JSON string content: a bad escape or a raw control character. */
    private static final int BAD = -2;

    /** No character read ahead. */
    private static final int NONE = Integer.MIN_VALUE;

    /**
     * Masks every secret name's value that no strict reading of the name's own level consumes (owner decision on #339,
     * fail closed; Codex round 5 on 8e6f207: a trigger per spelling missed the next spelling). It does not depend on
     * how any other reading reads the text, and it replaces the triggers each review round added for one shape.
     *
     * <p>Every {@link #ANY_SECRET_NAME} match is a candidate, whatever its quotes' levels. Where the text starts with a
     * valid JSON value its strings are certain (text after it, as a note after a cut body, is not), and so are those inside a string whose content is valid JSON in its turn, level by
     * level. A candidate at a certain level is the member name it reads as, a whole string there with a value valid
     * JSON gives it, or it crosses a string's quote there and is no name at all ({@code {"x\\u0022password":1}}).
     * Either way it is left to the other passes, and valid JSON keeps every byte. Anywhere else, in text that is not
     * valid JSON or inside a string whose content is not, a candidate is read strictly at its level: both quotes must
     * be quotes of that level ({@link #quoteLevel}), the name a whole string there, then a colon, a whole JSON value
     * and the rest of its object, valid up to its close bracket or the end of the text ({@link #consumedValueEnd}). A candidate that reads so is
     * left to the other passes too. Any other one has its value masked from just after its colon to the end of the
     * outermost string that holds it, or, when no valid JSON around it says where that is, to the end of the text: an
     * end found by a nested or escaped reading is never used. The mask is quoted with the name's closing quote as the
     * text spells it, so the masked field reads strictly at that level and this pass leaves it as it is; a closing quote of no
     * level is left out, and the mask is unquoted. Candidates
     * inside a value masked or read whole are skipped, so each part of the text is read a bounded number of times.
     */
    private static String maskUnconsumedSecretNames(String text) {
        return applyMasks(text, unconsumedSecretNameMasks(text));
    }

    /** What {@link #maskUnconsumedSecretNames} masks, as masks on the text. */
    private static List<Mask> unconsumedSecretNameMasks(String text) {
        Matcher m = ANY_SECRET_NAME.matcher(text);
        Certainty certainty = null;
        ProvenObjects proven = new ProvenObjects();
        List<Mask> masks = new ArrayList<>();
        int skipTo = 0;
        // Each quote and each \\u0022 may close a name's opening quote; the pattern is tried only where a name can start.
        int plain = text.indexOf('"');
        int unicode = unicodeQuote(text, 0);
        while (plain >= 0 || unicode >= 0) {
            boolean isPlain = unicode < 0 || (plain >= 0 && plain < unicode);
            int quote = isPlain ? plain : unicode;
            int name = quote + (isPlain ? 1 : 5);
            if (isPlain) {
                plain = text.indexOf('"', quote + 1);
            } else {
                unicode = unicodeQuote(text, quote + 1);
            }
            if (name >= text.length() || !isNameStart(text.charAt(name))) {
                continue;
            }
            int open = quoteRunStart(text, quote);
            if ((open == quote && !isPlain) || open < skipTo || !m.region(name, text.length()).lookingAt()
                    || !isSecretKey(decodedThroughChains(m.group(1)))) {
                continue;
            }
            // A value the strict reading consumes is left to the other passes wherever the name is; only a name it does
            // not read needs to know where the text's strings are certain.
            int consumed = consumedValueEnd(text, open, name, m.start(2), m.end(2), proven);
            if (consumed >= 0) {
                skipTo = Math.max(skipTo, consumed);
                continue;
            }
            if (certainty == null) {
                certainty = new Certainty(text);
            }
            int end = certainty.maskEnd(open, m.end(2));
            if (end == NONE) {
                continue;
            }
            // A quote of no level (a chain decoded to one only past NESTED_LEVELS) is one no reading reads: the mask is
            // left unquoted rather than quoted with what reads as JSON nested deeper than that.
            String closer = quoteLevel(m.group(2)) < 0 ? "" : m.group(2);
            masks.add(new Mask(m.end(), end, closer + MASK + closer));
            skipTo = end;
        }
        return masks;
    }

    /**
     * The next {@code \\u0022} escape's {@code u} in {@code text} from {@code from}, after a backslash or a {@code u005c}
     * ({@link #ANY_QUOTE}), or -1.
     */
    private static int unicodeQuote(String text, int from) {
        for (int i = text.indexOf("u0022", from); i >= 0; i = text.indexOf("u0022", i + 1)) {
            if ((i > 0 && text.charAt(i - 1) == '\\') || endsBackslashEscape(text, i)) {
                return i;
            }
        }
        return -1;
    }

    /** Whether a {@code u005c} or {@code u005C} ends at {@code end} in {@code text}. */
    private static boolean endsBackslashEscape(String text, int end) {
        return end >= 5 && text.startsWith("u005", end - 5) && (text.charAt(end - 1) == 'c' || text.charAt(end - 1) == 'C');
    }

    /**
     * {@code name} with each escape {@link #ANY_UNICODE_ESCAPE} matches decoded, however long the chain of backslashes
     * spelling its backslash: {@code pass\\u005cu0077ord} is {@code password}.
     */
    private static String decodedThroughChains(String name) {
        if (name.indexOf('\\') < 0) {
            return name;
        }
        return ANY_UNICODE_ESCAPE.matcher(name).replaceAll(e ->
                Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(e.group(1), 16))));
    }

    private static boolean isNameStart(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-' || c == '\\';
    }

    /**
     * Where the quote whose {@code "} or {@code u0022} is at {@code quote} in {@code text} starts: its whole run of
     * backslashes before it, each also spelled {@code \\u005c}, through a chain of them ({@link #ANY_QUOTE}), from the
     * first plain backslash of the run; {@code quote} when no backslash starts one.
     */
    private static int quoteRunStart(String text, int quote) {
        int start = quote;
        int i = quote;
        while (true) {
            if (i > 0 && text.charAt(i - 1) == '\\') {
                start = --i;
            } else if (endsBackslashEscape(text, i)) {
                i -= 5;
            } else {
                return start;
            }
        }
    }

    /**
     * The escape level at which {@code spelling} is one quote: 0 for {@code "}, 1 for {@code \"} or {@code \\u0022}, 2
     * for {@code \\\"}, {@code \\\\u0022} or {@code \\u005c\"}, and so on; -1 when it is a quote of no one level, as
     * {@code \\"} (an escaped backslash, then the quote of the level above), or of one past {@link #NESTED_LEVELS}.
     */
    static int quoteLevel(String spelling) {
        String s = spelling;
        for (int level = 0; level <= NESTED_LEVELS && s != null; level++) {
            if (s.equals("\"")) {
                return level;
            }
            s = unescapedOnce(s);
        }
        return -1;
    }

    /** {@code s} read as the content of a JSON string, or {@code null} when it is not that: a bare quote, a bad escape. */
    private static String unescapedOnce(String s) {
        Decoder d = new Decoder(s + "\"", 0, 1);
        StringBuilder out = new StringBuilder(s.length());
        for (int c = d.next(); c != END; c = d.next()) {
            if (c == BAD) {
                return null;
            }
            out.append((char) c);
        }
        return d.at() == s.length() ? out.toString() : null;
    }

    /**
     * The text at one escape level, read from a position where every level above is inside a string: level 0 is the
     * text itself, and each level the content of a JSON string of the level above it, decoded. A quote of the level
     * above ends it ({@link #END}); so does the end of the text. Each character it reads costs one per level.
     */
    private static final class Decoder {

        private final String text;
        private final Decoder outer;
        private int pos;
        private int peeked = NONE;
        private int peekedAt;
        /** Whether the end of the level has been read. */
        private boolean ended;

        Decoder(String text, int from, int level) {
            this.text = text;
            this.outer = level == 0 ? null : new Decoder(text, from, level - 1);
            this.pos = from;
        }

        /** Whether the level ended at the end of the text, not at a quote of the level above. */
        boolean atTextEnd() {
            return ended && at() >= text.length();
        }

        /** Where the next character starts in the text: the end of everything read so far. */
        int at() {
            if (peeked != NONE) {
                return peekedAt;
            }
            return outer == null ? pos : outer.at();
        }

        int peek() {
            if (peeked == NONE) {
                peekedAt = at();
                peeked = read();
                ended |= peeked == END;
            }
            return peeked;
        }

        /** The next character, or {@link #END} or {@link #BAD}, which it keeps returning. */
        int next() {
            int c = peek();
            if (c >= 0) {
                peeked = NONE;
            }
            return c;
        }

        private int read() {
            if (outer == null) {
                return pos < text.length() ? text.charAt(pos++) : END;
            }
            int c = outer.next();
            if (c == '"' || c < 0) {
                return c == '"' ? END : c;
            }
            if (isControl(c)) {
                return BAD;
            }
            return c == '\\' ? escape(outer) : c;
        }
    }

    /**
     * Whether {@code c} is a control character JSON string content may not hold raw. A tab, line feed or carriage return
     * is let through: text copied from pretty-printed JSON into a string keeps them raw, and the patterns read them as
     * whitespace there too.
     */
    private static boolean isControl(int c) {
        return c >= 0 && c < 0x20 && c != '\t' && c != '\n' && c != '\r';
    }

    /** The character the escape after a backslash in {@code d} stands for, or {@link #BAD}. */
    private static int escape(Decoder d) {
        int e = d.next();
        switch (e) {
            case '"', '\\', '/' -> {
                return e;
            }
            case 'b' -> {
                return '\b';
            }
            case 'f' -> {
                return '\f';
            }
            case 'n' -> {
                return '\n';
            }
            case 'r' -> {
                return '\r';
            }
            case 't' -> {
                return '\t';
            }
            case 'u' -> {
                int code = 0;
                for (int i = 0; i < 4; i++) {
                    int h = d.next();
                    int digit = h < 0 ? -1 : Character.digit(h, 16);
                    if (digit < 0) {
                        return BAD;
                    }
                    code = code * 16 + digit;
                }
                return code;
            }
            default -> {
                return BAD;
            }
        }
    }

    /**
     * Reads one JSON value from {@code d}, strictly, after any whitespace: whether it is whole and valid. Each string's
     * position goes to {@code strings}, if that is not {@code null}, as {@code {open, content, close, end}} in the
     * text. It keeps a stack of open brackets instead of recursing, so depth costs nothing more.
     */
    private static boolean readValue(Decoder d, List<int[]> strings) {
        StringBuilder open = new StringBuilder();
        boolean value = true;
        while (true) {
            skipSpace(d);
            if (value) {
                int c = d.peek();
                if (c == '{' || c == '[') {
                    d.next();
                    skipSpace(d);
                    if (d.peek() == (c == '{' ? '}' : ']')) {
                        d.next();
                    } else {
                        open.append((char) c);
                        if (c == '{' && !readMemberName(d, strings)) {
                            return false;
                        }
                        continue;
                    }
                } else if (c == '"' ? !readString(d, strings) : !readScalar(d)) {
                    return false;
                }
                value = false;
                continue;
            }
            if (open.isEmpty()) {
                return true;
            }
            char top = open.charAt(open.length() - 1);
            int c = d.next();
            if (c == ',') {
                value = true;
                if (top == '{' && !readMemberName(d, strings)) {
                    return false;
                }
            } else if (c == (top == '{' ? '}' : ']')) {
                open.setLength(open.length() - 1);
            } else {
                return false;
            }
        }
    }

    /** Reads a member name and its colon from {@code d}, after any whitespace: whether both are there. */
    private static boolean readMemberName(Decoder d, List<int[]> strings) {
        skipSpace(d);
        if (d.peek() != '"' || !readString(d, strings)) {
            return false;
        }
        skipSpace(d);
        return d.next() == ':';
    }

    private static void skipSpace(Decoder d) {
        for (int c = d.peek(); c == ' ' || c == '\t' || c == '\n' || c == '\r'; c = d.peek()) {
            d.next();
        }
    }

    /** Reads a JSON string from {@code d}, at its opening quote: whether it is whole and valid. */
    private static boolean readString(Decoder d, List<int[]> strings) {
        int open = d.at();
        d.next();
        int content = d.at();
        while (true) {
            int close = d.at();
            int c = d.next();
            if (c == '"') {
                if (strings != null) {
                    strings.add(new int[] {open, content, close, d.at()});
                }
                return true;
            }
            if (c < 0 || isControl(c) || (c == '\\' && escape(d) == BAD)) {
                return false;
            }
        }
    }

    /** Reads a JSON number, {@code true}, {@code false} or {@code null} from {@code d}: whether it is one. */
    private static boolean readScalar(Decoder d) {
        int c = d.peek();
        if (c == 't' || c == 'f' || c == 'n') {
            String word = c == 't' ? "true" : c == 'f' ? "false" : "null";
            for (int i = 0; i < word.length(); i++) {
                if (d.next() != word.charAt(i)) {
                    return false;
                }
            }
            return true;
        }
        if (c == '-') {
            d.next();
        }
        if (d.peek() == '0') {
            d.next();
        } else if (!digits(d)) {
            return false;
        }
        if (d.peek() == '.') {
            d.next();
            if (!digits(d)) {
                return false;
            }
        }
        if (d.peek() == 'e' || d.peek() == 'E') {
            d.next();
            if (d.peek() == '+' || d.peek() == '-') {
                d.next();
            }
            return digits(d);
        }
        return true;
    }

    /** Reads one or more digits from {@code d}: whether there was one. */
    private static boolean digits(Decoder d) {
        boolean any = false;
        while (d.peek() >= '0' && d.peek() <= '9') {
            d.next();
            any = true;
        }
        return any;
    }

    /**
     * Where the value of the name in {@code text} ends when the strict reading of the name's level consumes it, or -1;
     * its opening quote runs from {@code open} to {@code name}, and its closing one from {@code close} to {@code end}: both quotes are quotes of one level, the name is a whole string there that
     * ends at {@code end}, and a colon, a whole JSON value and the rest of its object ({@link #readRestOfObject}) follow.
     */
    private static int consumedValueEnd(String text, int open, int name, int close, int end, ProvenObjects proven) {
        int level = quoteLevel(text.substring(open, name));
        if (level < 0 || level != quoteLevel(text.substring(close, end))) {
            return -1;
        }
        Decoder d = new Decoder(text, open, level);
        if (d.peek() != '"' || !readString(d, null) || d.at() != end) {
            return -1;
        }
        skipSpace(d);
        if (d.next() != ':' || !readValue(d, null)) {
            return -1;
        }
        int valueEnd = d.at();
        if (proven.covers(level, valueEnd)) {
            return valueEnd;
        }
        if (!readRestOfObject(d)) {
            return -1;
        }
        proven.add(level, valueEnd, d.at());
        return valueEnd;
    }

    /**
     * Where, at each level, the rest of an object read after a secret field's value was found valid ({@link
     * #readRestOfObject}): from that value's end to the object's close bracket or the end of the text. A later secret
     * field of that level whose value ends in that span is in the same object, or in an object valid inside it, so the
     * rest of its object is valid too and is not read again (automated review on b00189e: reading it for each field made
     * an object of n secret fields cost n squared). The candidates come in order, so the last span per level is enough.
     */
    private static final class ProvenObjects {

        private final int[] from = new int[NESTED_LEVELS + 1];
        private final int[] to = new int[NESTED_LEVELS + 1];

        boolean covers(int level, int valueEnd) {
            return from[level] < to[level] && from[level] <= valueEnd && valueEnd <= to[level];
        }

        void add(int level, int valueEnd, int end) {
            from[level] = valueEnd;
            to[level] = end;
        }
    }

    /**
     * Reads the rest of the object a member's value was read in, after that value: whether it is valid JSON up to the
     * object's close bracket, or up to the end of the text, as in a body cut at the size limit. Anything else after the
     * value ({@code "",CR3T"}) is a reading that leaves part of the value unread, and so is a quote of the level above
     * before the close bracket: it ends the level only where the strings above are certain, which no local reading knows.
     */
    private static boolean readRestOfObject(Decoder d) {
        while (true) {
            skipSpace(d);
            int c = d.next();
            if (c == '}' || c == END) {
                return c == '}' || d.atTextEnd();
            }
            if (c != ',' || !readMemberName(d, null) || !readValue(d, null)) {
                return d.ended && d.atTextEnd();
            }
        }
    }

    /**
     * Where the text's strings are certain: everywhere, when the text is valid JSON, and, level by level, inside each
     * such string whose content is valid JSON too. Each string's content is read once, when a candidate first needs it.
     */
    private static final class Certainty {

        private final String text;
        /** The strings of the JSON value the text starts with, when it starts with a valid one, else {@code null}. */
        private final List<int[]> top;
        /** Where that value ends: text after it, such as a note after a body cut at the size limit, is not certain. */
        private final int certainEnd;
        /** The strings inside each string read so far, by where it opens; {@link #NOT_JSON} when its content is not JSON. */
        private final Map<Integer, List<int[]>> inside = new HashMap<>();
        /** What {@link #stringsInside} gives for a string whose content is not valid JSON. */
        private static final List<int[]> NOT_JSON = Collections.unmodifiableList(new ArrayList<>());

        Certainty(String text) {
            this.text = text;
            List<int[]> strings = new ArrayList<>();
            Decoder d = new Decoder(text, 0, 0);
            boolean valid = readValue(d, strings);
            this.top = valid ? strings : null;
            this.certainEnd = valid ? d.at() : 0;
        }

        /**
         * For a candidate from {@code open} to {@code end} that the strict reading of its level does not read: where its
         * mask ends, or {@link #NONE} when it is left to the other passes, being no name at a level that is certain.
         */
        int maskEnd(int open, int end) {
            if (top == null || open >= certainEnd) {
                return text.length();
            }
            List<int[]> strings = top;
            int[] outermost = null;
            for (int level = 1; ; level++) {
                int[] holder = holding(strings, open, end);
                if (holder == null) {
                    // A member name of a certain level, or no name at all: it crosses a string's quote there.
                    return NONE;
                }
                if (outermost == null) {
                    outermost = holder;
                }
                strings = level > NESTED_LEVELS ? NOT_JSON : stringsInside(holder, level);
                if (strings == NOT_JSON) {
                    return outermost[2];
                }
            }
        }

        /** The string among {@code strings} whose content holds the text from {@code from} to {@code to}, or {@code null}. */
        private static int[] holding(List<int[]> strings, int from, int to) {
            int low = 0;
            int high = strings.size() - 1;
            int[] found = null;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                if (strings.get(mid)[1] <= from) {
                    found = strings.get(mid);
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }
            return found != null && to <= found[2] ? found : null;
        }

        /**
         * The strings inside {@code string}, whose content is read at {@code level}, when that content is valid JSON;
         * else {@link #NOT_JSON}.
         */
        private List<int[]> stringsInside(int[] string, int level) {
            return inside.computeIfAbsent(string[0], k -> {
                List<int[]> strings = new ArrayList<>();
                Decoder d = new Decoder(text, string[1], level);
                boolean valid = readValue(d, strings);
                skipSpace(d);
                return valid && d.peek() == END && d.at() == string[2] ? strings : NOT_JSON;
            });
        }
    }

    /**
     * Masks the value of every secret-named field ({@link #isSecretKey(String)}) in JSON nested in JSON strings that
     * {@link #JSON_FIELD} and {@link #EMBEDDED_JSON_FIELD} do not reach on the text itself: two or more levels deep,
     * or spelled with unicode escapes ({@code \\u0022} for a quote, also at the top level of text copied from
     * inside a string, and on only some of a field's quotes). Each level {@link #readNestedLevels} gives is read as
     * plain JSON, as JSON embedded one level deep and {@link #flattened}. A string value's content becomes the mask, so
     * each of its quotes keeps the text's spelling; a number or boolean, and an object or array through its close
     * bracket, become the mask quoted as the field's name is. A field no strict reading of its own level reads (quoted
     * two ways, or with a value no reading reads) was masked from its colon by {@link #maskUnconsumedSecretNames} before
     * this runs. A value already masked is masked the same way again. JSON nested deeper than {@link #NESTED_LEVELS} is
     * masked string by string by {@link #nestedJwkMasks} before this runs.
     */
    private static String maskNestedSecretFields(String text) {
        SecretMasks masks = new SecretMasks();
        // The text itself, for a name that opens on the quote closing the value before it, which the patterns' own
        // whole-field search skips.
        View plain = new View(text, null);
        secretFieldMasks(text, plain, PLAIN_READING, masks);
        if (text.contains("\\\"")) {
            secretFieldMasks(text, plain, EMBEDDED_READING, masks);
        }
        readNestedLevels(text, (view, normal, depth, fresh) -> {
            masks.fresh = fresh;
            BitSet quotes = new BitSet();
            View flat = flattened(view, quotes, fresh);
            masks.flatQuotes = quotes;
            secretFieldMasks(text, normal, PLAIN_READING, masks);
            if (normal.text().contains("\\\"")) {
                secretFieldMasks(text, normal, EMBEDDED_READING, masks);
            }
            if (flat != null) {
                secretFieldMasks(text, flat, FLAT_READING, masks);
            }
        });
        return applyMasks(text, masks.list);
    }

    /**
     * The masks {@link #maskNestedSecretFields} finds, in the order its readings run: the text before the views, and
     * the views from the shallowest level down. Where readings of a secret object or value disagree on its bounds, the
     * union of their masks is masked (owner decision on #339, fail closed): a mask that starts where one taken before
     * does is another reading of that value, and is merged with every span it overlaps, so nothing a reading finds in
     * the value is kept; in text whose quotes are spelled more than one way some non-secret bytes may be masked with
     * it. A reading of the same value that masks nothing more is dropped, so a value found twice, an empty one included,
     * is masked once (review on c8d676f). Any other string or scalar value's mask that overlaps one taken before is
     * dropped; an object or array's is taken over the masks inside it, its members' values and objects (reviews on
     * 806a28c and 43b954a), unless an earlier object or array's mask reaches outside it. The readings keep valid JSON's
     * bounds, so the union does not reach past them there: each reads names at their own escape level
     * ({@link #opensAtItsLevel}) and, past depth 1, stops at a quote of the level above. The spans taken never
     * overlap, so each mask is checked against its neighbours only.
     */
    private static final class SecretMasks {

        private final List<Mask> list = new ArrayList<>();
        /** Each span taken, by where it starts. */
        private final TreeMap<Integer, Span> spans = new TreeMap<>();
        /** The quotes the flattened view being read turned bare ({@link #flattened}). */
        private BitSet flatQuotes;
        /** Where the quotes of the view being read start in the text that its level's unescaping made, or {@code null}. */
        private BitSet fresh;

        void add(Mask mask, boolean structure, boolean cut, int limit) {
            int start = mask.start();
            int end = mask.end();
            Span other = spans.get(start);
            if (!structure && other != null && !other.structure() && other.end() != end
                    && (end > other.end() ? cut : other.cut())) {
                // Readings of a string value disagree on where it ends, and the longer found no closing quote of its own:
                // its end is unknown, so it is masked to the end of the string holding it (review on 9593177: masked to
                // the next member's quote, the output read as a mask that stops short).
                end = Math.max(Math.max(limit, other.limit()), Math.max(end, other.end()));
                mask = new Mask(start, end, mask.replacement());
                cut = false;
                limit = end;
            }
            Integer from = spans.floorKey(start);
            boolean sameValue = spans.containsKey(start);
            List<Integer> overlapped = new ArrayList<>();
            int first = start;
            int union = end;
            boolean structureUnion = structure;
            for (Map.Entry<Integer, Span> span : spans.subMap(from == null ? start : from, true, Math.max(end, start + 1),
                    false).entrySet()) {
                int spanStart = span.getKey();
                Span taken = span.getValue();
                int spanEnd = taken.end();
                if (!overlaps(spanStart, spanEnd, start, end)) {
                    continue;
                }
                if (sameValue) {
                    if (spanStart == start && spanEnd >= end && (spanEnd > end || taken.structure() || !structure)) {
                        // This reading of the value masks nothing the other did not.
                        return;
                    }
                    structureUnion |= taken.structure();
                } else if (!structure || (taken.structure() && !(start < spanStart && spanEnd <= end))) {
                    return;
                }
                overlapped.add(spanStart);
                first = Math.min(first, spanStart);
                union = Math.max(union, spanEnd);
            }
            overlapped.forEach(spans::remove);
            spans.put(first, new Span(union, structureUnion, cut, Math.max(limit, union)));
            list.add(mask);
        }

        /**
         * A span taken: where it ends, whether it is an object or array's, whether it is a string value whose reading
         * found no closing quote of its own, and where the string holding the value ends.
         */
        private record Span(int end, boolean structure, boolean cut, int limit) {
        }

        /** Whether span {@code [a, b)} and span {@code [s, e)} overlap; an empty span counts at its position. */
        private static boolean overlaps(int a, int b, int s, int e) {
            if (a == b && s == e) {
                return a == s;
            }
            if (a == b) {
                return s <= a && a < e;
            }
            if (s == e) {
                return a <= s && s < b;
            }
            return a < e && s < b;
        }
    }

    /** {@link #secretFieldMasks}: a view read as plain JSON. */
    private static final int PLAIN_READING = 0;

    /** {@link #secretFieldMasks}: a view read as JSON embedded one level deep. */
    private static final int EMBEDDED_READING = 1;

    /**
     * {@link #secretFieldMasks}: a {@link #flattened} view read as plain JSON, for a value whose opening quote the text
     * spells {@code \\u0022} as its name's are (security round 2). The value keeps its own escapes there: the view of
     * {@code {\\u0022client_secret\\u0022:\\u0022\\"s3cr3t\\u0022}} is {@code {"client_secret":"\\"s3cr3t"}}, while the next
     * view would take an escape off it. A plain-quoted value is the other readings': this view would close it at a
     * {@code \\u0022} of its own. After a plain-quoted name no strict reading reads such a value, and it is masked from
     * the colon by {@link #maskUnconsumedSecretNames}.
     */
    private static final int FLAT_READING = 2;

    /**
     * Adds to {@code masks} the mask of every secret-named field's value in {@code view}, as positions in the text (see
     * {@link #maskNestedSecretFields}), as the {@code reading} reads the view: {@link #PLAIN_READING},
     * {@link #EMBEDDED_READING} or {@link #FLAT_READING}.
     * The names are found first, apart from the values ({@link #FIELD_NAME}, {@link #EMBEDDED_FIELD_NAME}), as {@link #everyPrivateMember} finds JWK names: in malformed text a value can end at
     * the quote that opens the next name ({@code "x":""client_secret":...}), and a search for whole fields would skip
     * that name. Each secret name's value is then matched from the name. A name inside a value already masked goes
     * with it, except one that opens on the quote that closed that value; so each value is read once, and the work
     * stays linear in the view's length.
     */
    private static void secretFieldMasks(String text, View view, int reading, SecretMasks masks) {
        String json = view.text();
        boolean embedded = reading == EMBEDDED_READING;
        Matcher name = READINGS[reading].name().matcher(json);
        Matcher structure = READINGS[reading].structure().matcher(json);
        Matcher field = READINGS[reading].field().matcher(json);
        // Past depth 1, a quote neither this level's unescaping made nor its decoding is the level above's: it ends the
        // string holding this JSON, and with it any name, value or structure read here (review on 22ff6ea: read past it,
        // a cut-off object balanced on the brace of the object around that string; review on 59b603d: a value ran on
        // through it, the outer string's closing quote reading as an escaped one here; review on 3c5ddac: a name opened at
        // a quote decoded inside a name of the level above and closed at that name's own quote).
        IntPredicate outer = masks.fresh == null ? k -> false : k -> !masks.fresh.get(view.at(k))
                && !(k > 0 && decodesQuote(view, k - 1)) && !(reading == FLAT_READING && masks.flatQuotes.get(k));
        int copied = 0;
        int[] limits = null;
        while (name.find()) {
            int at = name.start();
            int quote = json.charAt(at) == '\\' ? 2 : 1;
            int closing = json.charAt(name.end(1)) == '\\' ? name.end(1) + 1 : name.end(1);
            if (at < copied - 2 || !isSecretKey(decodeName(name.group(1))) || outer.test(closing)
                    || (!embedded && backslashesBefore(json, at) % 2 == 1)
                    || (embedded && backslashesBefore(json, at) % 4 != 0)
                    || !opensAtItsLevel(view, at, reading, masks)) {
                continue;
            }
            String spelled = quoteOf(text, view, at, quote);
            if (structure.region(at, json.length()).lookingAt()) {
                int end = reading == FLAT_READING ? endOfFlatStructure(json, structure.end(), masks.flatQuotes, outer)
                        : endOfStructure(json, structure.end(), embedded, outer);
                // An embedded object or array that a bare quote cuts off before its brackets close holds JSON quoted
                // at the level above ({\\"client_secret\\":{"x":...}}): masking up to that quote would keep the rest. It
                // is read as plain JSON here, where its strings keep their own escapes (review on 7a80b9c: the next
                // view takes one off, so "a\\"}b" closed the object at its brace), and is so read once (review on
                // 47c938e: reading each to one bare quote at the end made the work grow with the square of the names). In the
                // text itself the bare quote ends the string that holds the embedded JSON, as maskStructures reads it.
                if (embedded && view.origin() != null && end < json.length() && json.charAt(end) == '"') {
                    end = endOfStructure(json, structure.end(), false, outer);
                }
                copied = end;
                masks.add(new Mask(view.at(structure.end()), view.at(copied), spelled + MASK + spelled), true, false,
                        view.at(copied));
            } else if (field.region(at, json.length()).lookingAt()) {
                // A plain-quoted value is the other readings': the flattened view would close it at a quote of its own.
                if (reading == FLAT_READING && field.group(3) != null && !masks.flatQuotes.get(field.start(3) - 1)) {
                    continue;
                }
                copied = field.end();
                if (field.group(3) != null) {
                    int close = field.end(3);
                    boolean cut = embedded
                            ? !json.startsWith("\\\"", close) && !json.regionMatches(true, close, "\\u0022", 0, 6)
                            : close >= json.length() || json.charAt(close) != '"' || outer.test(close)
                            || !endsValue(json, close + 1);
                    if (limits == null) {
                        limits = stringEnds(json, embedded, outer);
                    }
                    int limit = limits[field.start(3)];
                    if (limit < close) {
                        close = limit;
                        cut = true;
                    }
                    masks.add(new Mask(view.at(field.start(3)), view.at(close),
                            masked(decodeName(field.group(1)), json.substring(field.start(3), close))), false, cut,
                            view.at(limit));
                    int escapedEnd = reading == FLAT_READING ? escapedQuoteEnd(json, close, limit, masks.flatQuotes) : -1;
                    if (escapedEnd > close) {
                        masks.add(new Mask(view.at(field.start(3)), view.at(escapedEnd), MASK), false,
                                escapedEnd >= limit || !endsValue(json, escapedEnd + 1), view.at(limit));
                        copied = Math.max(copied, escapedEnd);
                    }
                } else {
                    masks.add(new Mask(view.at(field.end(2)), view.at(copied), spelled + MASK + spelled), false, false,
                            view.at(copied));
                }
            }
        }
    }

    /**
     * Whether the name at {@code at} in {@code view} opens with a quote of the view's own level: past depth 1, one the
     * level's unescaping made of an escaped quote, or one it decoded from {@code \\u0022}. A quote that was already
     * bare a level up opens a name of that level, read there; this view, with one more escape taken off, would read
     * {@code client\\\\u005fsecret} as {@code client_secret} (review on 84afef7).
     */
    private static boolean opensAtItsLevel(View view, int at, int reading, SecretMasks masks) {
        if (masks.fresh == null) {
            return true;
        }
        String json = view.text();
        int quote = json.charAt(at) == '\\' ? at + 1 : at;
        return masks.fresh.get(view.at(quote)) || (quote > at && decodesQuote(view, at))
                || (reading == FLAT_READING && masks.flatQuotes.get(quote));
    }

    /**
     * Whether the escaped quote ({@code \\"}) at {@code at} in {@code view}, if one is there, is one {@link #normalized}
     * decoded from {@code \\u0022}: the only escape whose backslash and quote start at the same place in the text. Unlike
     * the text's spelling there, this tells a quote the view's level decodes from an escaped quote whose quote a level
     * above decoded (an escaped backslash before a {@code \\u0022}).
     */
    private static boolean decodesQuote(View view, int at) {
        String json = view.text();
        return at + 1 < json.length() && json.charAt(at) == '\\' && json.charAt(at + 1) == '"'
                && view.at(at) == view.at(at + 1);
    }

    /**
     * Whether every backslash still in {@code view} (an escape no level read) starts inside one of the
     * {@code strings}, as positions in the text.
     */
    private static boolean holdsEveryEscape(List<Mask> strings, View view) {
        List<Mask> sorted = new ArrayList<>(strings);
        sorted.sort((a, b) -> Integer.compare(a.start(), b.start()));
        String json = view.text();
        int next = 0;
        int coveredTo = -1;
        for (int i = json.indexOf('\\'); i >= 0; i = json.indexOf('\\', i + 1)) {
            int at = view.at(i);
            while (next < sorted.size() && sorted.get(next).start() <= at) {
                coveredTo = Math.max(coveredTo, sorted.get(next++).end());
            }
            if (at >= coveredTo) {
                return false;
            }
        }
        return true;
    }

    /**
     * Every JWK private member's value in the text, as masks on it: in plain JSON, in JSON embedded in a JSON
     * string, and nested deeper ({@link #maskNestedJwks(String, int)}).
     */
    private static List<Mask> jwkMasks(String text, Discovery discovery) {
        List<Mask> masks = new ArrayList<>();
        for (JwkValue value : discovery.read("plain", text, false, discovery.plain)) {
            masks.add(new Mask(value.start(), value.end(), "\"" + MASK + "\""));
        }
        // With a unicode escape, a quote may be spelled two ways; nestedJwkMasks reads that level decoded.
        if (!UNICODE_ESCAPE.matcher(text).find()) {
            for (JwkValue value : discovery.read("embedded", text, true, discovery.embedded)) {
                masks.add(new Mask(value.start(), value.end(), "\\\"" + MASK + "\\\""));
            }
        }
        masks.addAll(nestedJwkMasks(text, -1, discovery));
        return masks;
    }

    /** A read JWK discovery made at an escape level: how much of that level's budget was left before and after it. */
    record DiscoveryRead(String level, int before, int after) {
    }

    /**
     * What JWK discovery has left to read at each escape level: {@code 4n + 1024} characters for the plain and
     * the embedded JSON of a text of length {@code n}, and {@code 4m + 1024} for each nested level, whose view of
     * the text has length {@code m}, when it is first read. Reading the text again ({@link #readAgain}) spends what
     * is left, but no more than {@code 4m + 1024} for the text it reads then, of length {@code m}; a nested level the
     * first read never reached has nothing left, so its private member names are all masked.
     */
    private static final class Discovery {

        private final int[] plain;
        private final int[] embedded;
        private final List<int[]> nested = new ArrayList<>();
        private final List<DiscoveryRead> reads;
        private boolean again;

        Discovery(int length, List<DiscoveryRead> reads) {
            plain = new int[] {4 * length + 1024};
            embedded = new int[] {4 * length + 1024};
            this.reads = reads;
        }

        /** The budget of nested level {@code depth}, whose view has length {@code length}. */
        int[] nested(int depth, int length) {
            while (nested.size() < depth) {
                nested.add(null);
            }
            if (nested.get(depth - 1) == null) {
                nested.set(depth - 1, new int[] {again ? 0 : 4 * length + 1024});
            }
            return nested.get(depth - 1);
        }

        /** From now on the text is read again, so a nested level not read yet gets no budget of its own. */
        void readAgain() {
            again = true;
        }

        /**
         * {@link #jwkValues} at {@code level}, spending {@code budget}, recorded in the reads. A read gets no more
         * than {@code 4m + 1024} for a {@code text} of length {@code m}, however much the level has left: a second
         * read, of a text masking its key blocks has shortened, gets no more than a first read of that text would.
         */
        List<JwkValue> read(String level, String text, boolean embedded, int[] budget) {
            int before = budget[0];
            int allowance = Math.min(before, 4 * text.length() + 1024);
            int[] left = {allowance};
            List<JwkValue> values = jwkValues(text, embedded, left);
            budget[0] = left[0] < 0 ? left[0] : before - (allowance - left[0]);
            if (reads != null) {
                reads.add(new DiscoveryRead(level, before, budget[0]));
            }
            return values;
        }
    }

    /**
     * Every PEM block and PGP private key block in the text, as masks on it: a terminated block keeps its armor
     * around the mask; an unterminated private key header is masked to the end of the text, unless it is in a
     * terminated block or already masked.
     */
    private static List<Mask> pemMasks(String text) {
        List<Mask> masks = new ArrayList<>();
        Matcher block = PEM_BLOCK.matcher(text);
        List<int[]> blocks = new ArrayList<>();
        while (block.find()) {
            masks.add(new Mask(block.start(), block.end(),
                    "-----BEGIN " + block.group(1) + "-----\n" + MASK + "\n-----END " + block.group(1) + "-----"));
            blocks.add(new int[] {block.start(), block.end()});
        }
        // The blocks are in order and apart: one pointer walks them as the headers are found, and a header in a
        // block resumes the search after that block, so the text is read once.
        Matcher header = UNTERMINATED_PEM_KEY.matcher(text);
        int next = 0;
        while (header.find()) {
            int start = header.start();
            while (next < blocks.size() && blocks.get(next)[1] <= start) {
                next++;
            }
            if (next < blocks.size() && blocks.get(next)[0] <= start) {
                header.region(blocks.get(next)[1], text.length());
                continue;
            }
            masks.add(new Mask(start, text.length(), "-----BEGIN " + header.group(1) + "-----\n" + MASK));
            break;
        }
        return masks;
    }

    /**
     * {@code text} with each mask's stretch replaced: a mask inside another goes with it, and masks that only
     * overlap are masked as one, by the first one's replacement.
     */
    private static String applyMasks(String text, List<Mask> masks) {
        if (masks.isEmpty()) {
            return text;
        }
        masks.sort((a, b) -> a.start() != b.start() ? Integer.compare(a.start(), b.start()) : Integer.compare(b.end(), a.end()));
        StringBuilder out = new StringBuilder(text.length());
        int copied = 0;
        for (int i = 0; i < masks.size(); i++) {
            Mask mask = masks.get(i);
            int end = mask.end();
            while (i + 1 < masks.size() && masks.get(i + 1).start() < end) {
                end = Math.max(end, masks.get(++i).end());
            }
            out.append(text, copied, mask.start()).append(mask.replacement());
            copied = end;
        }
        return out.append(text, copied, text.length()).toString();
    }

    /** A stretch of the text to replace: where it starts and ends, and what replaces it. */
    private record Mask(int start, int end, String replacement) {
    }

    /**
     * A view of the text with some levels of escaping taken off or decoded, and where each of its characters
     * starts in the text ({@code origin}, one longer than the view so its end maps to the text's end;
     * {@code null}: each character at its own index).
     */
    private record View(String text, int[] origin) {

        /** Where character {@code i} of the view starts in the text. */
        int at(int i) {
            return origin == null ? i : origin[i];
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof View view && text.equals(view.text) && Arrays.equals(origin, view.origin);
        }

        @Override
        public int hashCode() {
            return 31 * text.hashCode() + Arrays.hashCode(origin);
        }

        @Override
        public String toString() {
            return "View[text=" + text + ", origin=" + Arrays.toString(origin) + "]";
        }
    }

    /**
     * Each string of the text itself whose content holds an escape, so JSON nested deeper than
     * {@link #NESTED_LEVELS} may be in it: its content masked whole. The strings are read in the text, not in a
     * view, where an escaped quote of the text has become a bare one and would shift which quotes bound them:
     * a backslash always takes the next character with it, a string cut off by the end of the text runs to it,
     * and a quote whose string is followed by something no string is (a stray one, in prose) is read again
     * from the character after it, without reopening strings at the escaped quotes its span held. The mask has
     * no quote or backslash, so it needs no escaping at any level.
     */
    private static List<Mask> stringsHoldingEscapes(String text) {
        List<Mask> masks = new ArrayList<>();
        int quotesFrom = 0;
        int i = 0;
        while (i < text.length()) {
            if (text.charAt(i) != '"' || i < quotesFrom) {
                i++;
                continue;
            }
            int close = i + 1;
            boolean escapes = false;
            while (close < text.length() && text.charAt(close) != '"') {
                if (text.charAt(close) == '\\') {
                    escapes = true;
                    close++;
                }
                close++;
            }
            int end = Math.min(close, text.length());
            if (escapes) {
                masks.add(new Mask(i + 1, end, MASK));
            }
            if (end == text.length()) {
                break;
            }
            int next = end + 1;
            while (next < text.length() && Character.isWhitespace(text.charAt(next))) {
                next++;
            }
            char after = next < text.length() ? text.charAt(next) : ',';
            if (after == ',' || after == ':' || after == '}' || after == ']') {
                i = end + 1;
            } else {
                quotesFrom = end;
                i++;
            }
        }
        return masks;
    }

    /**
     * {@code view} with each unicode escape of its outermost string decoded, so JSON embedded in it reads
     * as {@link #maskJwks} reads it, however the string spells it: a quote or backslash ({@code \\u0022},
     * {@code \\u005C}, as .NET's default encoder writes a quote) becomes {@code \"} or {@code \\}, any
     * other character (a colon, a brace, a space) itself. With nothing to decode, {@code view} itself is
     * returned.
     */
    private static View normalized(View view) {
        return decoded(view, null, null);
    }

    /**
     * {@code view} {@link #normalized}, but with each quote a unicode escape spells ({@code \\u0022}) a bare quote,
     * at the level of the view's own quotes; {@code null} when it spells none. Each such quote's index in the result is
     * set in {@code quotes}. {@code fresh} is where the quotes the view's level made start in the text ({@link
     * LevelReader}), or {@code null} at depth 1.
     */
    private static View flattened(View view, BitSet quotes, BitSet fresh) {
        return decoded(view, quotes, fresh);
    }

    /** {@link #normalized} or, with {@code quotes} to set, {@link #flattened}. */
    private static View decoded(View view, BitSet quotes, BitSet fresh) {
        boolean flat = quotes != null;
        String text = view.text();
        Matcher escape = UNICODE_ESCAPE.matcher(text);
        if (!escape.find()) {
            return flat ? null : view;
        }
        boolean flattenedAny = false;
        FlatContext context = flat ? new FlatContext() : null;
        int escaped = -1;
        StringBuilder out = new StringBuilder(text.length());
        int[] to = new int[text.length() + 1];
        int i = 0;
        while (i < text.length()) {
            if (text.charAt(i) != '\\') {
                if (flat && i != escaped) {
                    char c = text.charAt(i);
                    context.read(c, c == '"' && fresh != null && !fresh.get(view.at(i)), text, i);
                }
                to[out.length()] = view.at(i);
                out.append(text.charAt(i++));
                continue;
            }
            int run = i;
            while (run < text.length() && text.charAt(run) == '\\') {
                run++;
            }
            // Only an odd run ends in an escape of its own: an even one is escaped backslashes before a u.
            boolean unicode = (run - i) % 2 == 1 && escape.region(run - 1, text.length()).lookingAt();
            int copy = unicode ? run - 1 : run;
            for (int k = i; k < copy; k++) {
                to[out.length()] = view.at(k);
                out.append('\\');
            }
            if ((run - i) % 2 == 1 && !unicode) {
                escaped = run;
            }
            if (unicode) {
                char c = (char) Integer.parseInt(escape.group(1), 16);
                boolean flattens = flat && c == '"' && context.flattens(text, escape.end());
                if (flattens) {
                    flattenedAny = true;
                    quotes.set(out.length());
                } else if (flat && c != '"' && c != '\\') {
                    context.read(c, false, text, i);
                }
                if (c == '\\' || (c == '"' && !flattens)) {
                    to[out.length()] = view.at(run - 1);
                    out.append('\\');
                }
                to[out.length()] = view.at(run - 1);
                out.append(c);
                run = escape.end();
            }
            i = run;
        }
        to[out.length()] = view.at(text.length());
        if (flat && !flattenedAny) {
            return null;
        }
        return new View(out.toString(), to);
    }

    /**
     * Where {@link #flattened} is in the JSON it reads, to tell which quotes spelled {@code \\u0022} it turns bare: one
     * outside every string (opening a string, which a quote of either kind then closes), one closing such a string, and
     * one closing a name a plain quote opens, before its colon, unless that name closes with a plain quote and a colon
     * of its own ({@link #closesAsName}) and its part before that quote is no secret name. Inside a value a plain quote opens (after a colon, or an array item) such a
     * quote is that string's own, as anywhere else in such a name ({@code "pass\\u0022word"}): a
     * JSON string written with {@code \\u0022} for its quotes holds JSON one level deeper, not at this level (review on
     * 9593177: read at this level, {@code a\\\\\\u0022b} in it read as an escaped backslash and a closing quote).
     */
    private static final class FlatContext {

        private static final int OUTSIDE = 0;
        private static final int PLAIN_VALUE = 1;
        private static final int PLAIN_NAME = 2;
        private static final int FLAT_STRING = 3;

        private final BitSet arrays = new BitSet();
        private int state = OUTSIDE;
        private int depth;
        private char before;
        /** Whether the plain-quoted name being read closes with a plain quote and a colon: a valid name, read whole. */
        private boolean validName;
        /** Where the plain-quoted name being read starts, after its opening quote. */
        private int nameStart;

        /**
         * Reads one character that is not an escape, at {@code at} in {@code text}; {@code outer} for a quote of the level
         * above, which starts or ends the string holding this level's JSON.
         */
        void read(char c, boolean outer, String text, int at) {
            if (outer) {
                state = OUTSIDE;
                depth = 0;
                before = 0;
            } else if (c == '"') {
                boolean value = before == ':' || (arrays.get(depth) && (before == '[' || before == ','));
                state = state != OUTSIDE ? OUTSIDE : value ? PLAIN_VALUE : PLAIN_NAME;
                validName = state == PLAIN_NAME && closesAsName(text, at + 1);
                nameStart = at + 1;
                before = c;
            } else if (state == OUTSIDE) {
                if (c == '{' || c == '[') {
                    arrays.set(++depth, c == '[');
                } else if ((c == '}' || c == ']') && depth > 0) {
                    depth--;
                }
                if (!Character.isWhitespace(c)) {
                    before = c;
                }
            }
        }

        /**
         * Whether the part of the plain-quoted name being read before the quote spelled {@code \\u0022} that ends at
         * {@code after} is a secret name. Then a valid name is read both ways (owner decision on #339, fail closed): read
         * whole, {@code "private_key\\u0022:{\\u0022x"} is a name of its own; with that quote as its closing quote it is
         * {@code private_key} and an object (review on 9f45005).
         */
        private boolean secretBefore(String text, int after) {
            int escape = after - 6;
            // A secret name has at most 64 characters, each at most a six-character escape: a longer part is none, and
            // is not decoded, so a name holding many such quotes is read in linear time (review on 2b4b788).
            return escape >= nameStart && escape - nameStart <= 6 * 64
                    && isSecretKey(decodeName(text.substring(nameStart, escape)));
        }

        /** Whether the quote spelled {@code \\u0022} that ends at {@code after} in {@code text} is turned bare. */
        boolean flattens(String text, int after) {
            boolean flattens = state == OUTSIDE || state == FLAT_STRING
                    || (state == PLAIN_NAME && beforeColon(text, after) && (!validName || secretBefore(text, after)));
            if (flattens) {
                state = state == OUTSIDE ? FLAT_STRING : OUTSIDE;
                before = '"';
            }
            return flattens;
        }
    }

    /**
     * {@code view} with one level of JSON string escaping taken off: each {@code \\} becomes {@code \}
     * and each {@code \"} a quote; any other escape is kept as it is, so an escaped line break still reads
     * as whitespace and a name's {@code \\u} escape as an escape.
     */
    private static View unescaped(View view, BitSet fresh) {
        String text = view.text();
        StringBuilder out = new StringBuilder(text.length());
        int[] to = new int[text.length() + 1];
        int i = 0;
        while (i < text.length()) {
            if (text.charAt(i) != '\\') {
                to[out.length()] = view.at(i);
                out.append(text.charAt(i++));
                continue;
            }
            int run = i;
            while (run < text.length() && text.charAt(run) == '\\') {
                run++;
            }
            for (int k = i; k + 1 < run; k += 2) {
                to[out.length()] = view.at(k);
                out.append('\\');
            }
            if ((run - i) % 2 == 1) {
                to[out.length()] = view.at(run - 1);
                boolean quote = run < text.length() && text.charAt(run) == '"';
                if (quote) {
                    fresh.set(view.at(run - 1));
                }
                out.append(quote ? '"' : '\\');
                run += quote ? 1 : 0;
            }
            i = run;
        }
        to[out.length()] = view.at(text.length());
        return new View(out.toString(), to);
    }

    /** {@link #startOfObject}: no open bracket before the member, to the start of the text or the string. */
    private static final int NOT_IN_BRACKETS = -1;

    /** {@link #startOfObject}: the member is in an array, not an object. */
    private static final int IN_ARRAY = -2;

    /** {@link #startOfObject} and {@link #objects}: the budget is spent. */
    private static final int OUT_OF_TIME = -3;

    /**
     * Where the name of every {@link #JWK_PRIVATE_MEMBERS} field in the text starts, in a JWK or not. Only
     * the names are matched, not the values before them: in malformed text a value can end at the quote
     * that opens the next name ({@code "x":""d":}), and a search for whole fields would skip that name.
     */
    private static TreeSet<Integer> everyPrivateMember(String text, boolean embedded) {
        TreeSet<Integer> names = new TreeSet<>();
        Matcher m = (embedded ? EMBEDDED_JWK_PRIVATE_NAME : JWK_PRIVATE_NAME).matcher(text);
        while (m.find()) {
            names.add(m.start());
        }
        return names;
    }

    /**
     * Whether the quote at {@code member} opens a string rather than being escaped inside one: one
     * backslash before it in embedded JSON ({@code \"}, not {@code \\\"}), none in plain JSON. The
     * backslashes it reads are charged to the budget.
     */
    private static boolean opensName(String text, int member, boolean embedded, int[] budget) {
        int run = backslashesBefore(text, embedded ? member + 1 : member);
        budget[0] -= run;
        return embedded ? run % 4 == 1 : run % 2 == 0;
    }

    /** A JSON object found by {@link #objects}: where it starts and where each of its own members' names starts. */
    private record JsonObject(int start, List<Integer> names) {
    }

    /**
     * Where the JSON object that holds the member whose name starts at {@code member} starts, or
     * {@link #NOT_IN_BRACKETS} or {@link #IN_ARRAY} if it is not in an object, or {@link #OUT_OF_TIME}
     * once the searches have read {@code budget[0]} characters in all, a run of backslashes before a
     * quote included. Reads back from the member,
     * skipping strings and closed brackets, and jumping over each pair of brackets already matched, by
     * an earlier search (which adds each pair it matches to {@code matching}) or by {@link #objects}.
     * Reading back to {@code outside}, a member found not to be in an object (its search ended with
     * {@code outsideResult}), outside any string, ends the same way: at any bracket depth for
     * {@link #NOT_IN_BRACKETS}, outside any bracket for {@link #IN_ARRAY}. In
     * embedded JSON, where an inner quote is {@code \"} and an escaped one {@code \\\"}, an unescaped
     * quote is the start of the outer string, so the member is not in embedded JSON.
     */
    private static int startOfObject(String text, int member, boolean embedded, Map<Integer, Integer> matching,
            int outside, int outsideResult, int[] budget) {
        // The close brackets read back over and not yet matched, innermost last.
        List<Integer> closes = new ArrayList<>();
        boolean inString = false;
        for (int i = member - 1; i >= 0; i--) {
            if (--budget[0] < 0) {
                return OUT_OF_TIME;
            }
            char c = text.charAt(i);
            if (c == '"') {
                int run = backslashesBefore(text, i);
                budget[0] -= run;
                if (budget[0] < 0) {
                    return OUT_OF_TIME;
                }
                if (embedded && run % 2 == 0) {
                    return NOT_IN_BRACKETS;
                }
                if (run % (embedded ? 4 : 2) == (embedded ? 1 : 0)) {
                    inString = !inString;
                }
                i -= run;
                if (i == outside && !inString && (closes.isEmpty() || outsideResult == NOT_IN_BRACKETS)) {
                    return outsideResult;
                }
            } else if (!inString && (c == '}' || c == ']') && matching.containsKey(i)) {
                i = matching.get(i);
            } else if (!inString && (c == '}' || c == ']')) {
                closes.add(i);
            } else if (!inString && (c == '{' || c == '[')) {
                if (closes.isEmpty()) {
                    return c == '{' ? i : IN_ARRAY;
                }
                matching.put(closes.removeLast(), i);
            }
        }
        return NOT_IN_BRACKETS;
    }

    /**
     * Adds to {@code found} every JSON object from the one starting at {@code start} through its close
     * bracket, the ones inside it included, and returns where it stopped reading: after that bracket, or
     * at the end of the text or of the string holding embedded JSON. Each object comes with where each of
     * its own members' names starts: the
     * opening quote, or in embedded JSON the backslash before it. Reads the text as
     * {@link #endOfStructure} does. {@code matching} maps each bracket of an object read so far to the
     * other one: this adds the objects it closes, and skips an object read before. Returns
     * {@link #OUT_OF_TIME} once the budget is spent, as {@link #startOfObject} does.
     */
    private static int objects(String text, int start, boolean embedded, Map<Integer, Integer> matching,
            List<JsonObject> found, int[] budget) {
        // The open objects, innermost last, with null for an open array.
        List<JsonObject> open = new ArrayList<>();
        boolean inString = false;
        boolean escaped = false;
        boolean nameNext = false;
        int i = start;
        while (i < text.length()) {
            if (--budget[0] < 0) {
                return OUT_OF_TIME;
            }
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
        return i;
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
