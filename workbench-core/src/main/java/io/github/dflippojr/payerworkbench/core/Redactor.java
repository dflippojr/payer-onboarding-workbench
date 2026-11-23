package io.github.dflippojr.payerworkbench.core;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.IntPredicate;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Masks credential material in strings and HTTP headers before they are stored,
 * shown or written to a report.
 *
 * <p>Covers {@code Bearer}, {@code Basic}, {@code Token} and {@code DPoP} credentials (a
 * {@code Bearer} one also URL-encoded, {@code Bearer%20} or {@code Bearer+}), JWT signatures
 * (the header and payload stay readable because their claims are useful for diagnosis), PEM
 * blocks and PGP private key blocks (whole, their armor header and footer too), the private members of a JWK ({@link #JWK_PRIVATE_MEMBERS}
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

    /** Where an armor header starts: its label follows, then {@link #ARMOR_DASHES}. */
    private static final String ARMOR_BEGIN = "-----BEGIN ";
    /** Where an armor footer starts: the label of the header it closes follows, then {@link #ARMOR_DASHES}. */
    private static final String ARMOR_END = "-----END ";
    private static final String ARMOR_DASHES = "-----";

    /**
     * A private key header, PEM or PGP ({@code PRIVATE KEY BLOCK}), not already masked. One that is in no
     * {@link #keyBlocks} block has no matching footer (a truncated paste) and is masked to the end of the text.
     */
    private static final Pattern UNTERMINATED_PEM_KEY = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----(?!\\s*" + Pattern.quote(MASK) + ")");

    /**
     * Any armor header, of any label or none, as the replay scanner reads one: the Redactor writes none, so one left
     * after the blocks are masked (a header with no footer that opens no private key, or one already followed by the
     * mask) is masked itself.
     */
    private static final Pattern ARMOR_HEADER = Pattern.compile("-----BEGIN [A-Z0-9 ]*-----");

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
     * A JSON member name and its colon; group 1 is the name. Its whitespace may be escaped, as in
     * {@link #EMBEDDED_SPACE}, so a name in text copied from inside a JSON string reads too.
     */
    private static final Pattern FIELD_NAME = Pattern.compile("\"(" + NAME_CHAR + "{1,64})\"" + EMBEDDED_SPACE + ":");

    /** The same inside JSON embedded in a JSON string, as {@link #EMBEDDED_JSON_FIELD} starts; it starts at the backslash. */
    private static final Pattern EMBEDDED_FIELD_NAME = Pattern.compile(
            BACKSLASH + "\"(" + EMBEDDED_NAME_CHAR + "{1,64})" + BACKSLASH + "\"" + EMBEDDED_SPACE + ":");

    /** {@link #KTY_NAME} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_KTY_NAME = Pattern.compile(
            BACKSLASH + "\"" + spelled("kty", true) + BACKSLASH + "\"");

    /** {@link #JWK_TYPE} inside JSON embedded in a JSON string; it starts at the backslash. */
    private static final Pattern EMBEDDED_JWK_TYPE = Pattern.compile(EMBEDDED_KTY_NAME.pattern() + EMBEDDED_SPACE + ":");

    /** The name of a {@link #JWK_PRIVATE_MEMBERS} field, each letter also as a {@code \\u} escape, through its colon. */
    private static final Pattern JWK_PRIVATE_NAME = Pattern.compile("\"" + privateNames(false) + "\"\\s*:");

    /** Whitespace in JSON embedded in a JSON string ({@link #EMBEDDED_SPACE}), as a pattern of its own. */
    private static final Pattern SPACE_RUN = Pattern.compile(EMBEDDED_SPACE);

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

    /** A private key header, PEM or PGP; group 1 is its label, which the matching footer repeats. */
    private static final Pattern PRIVATE_KEY_HEADER = Pattern.compile("-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----");

    /** The footer that closes a {@link #PRIVATE_KEY_HEADER} of the same label (group 1). */
    private static final Pattern PRIVATE_KEY_FOOTER = Pattern.compile("-----END ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----");

    /**
     * The number of places in {@code text} where a private key header ({@link #PRIVATE_KEY_HEADER}) starts, counted at
     * every {@code -----BEGIN } however the headers overlap, so a header whose closing dashes open another is counted
     * too (#389). Linear in the text: the label after each start is a run of label characters, and no two runs share
     * a character.
     */
    static int privateKeyHeaderStarts(String text) {
        int count = 0;
        Matcher header = PRIVATE_KEY_HEADER.matcher(text);
        for (int at = text.indexOf(ARMOR_BEGIN); at >= 0; at = text.indexOf(ARMOR_BEGIN, at + 1)) {
            if (header.region(at, text.length()).lookingAt()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Whether a string in {@code text} opens a private key block it does not close: the one open-key predicate of the
     * structural path and its entry check (#389). {@code text} is read in pieces split at each quote, and a private key
     * header ({@link #PRIVATE_KEY_HEADER}) is open unless a footer of its own label ({@link #PRIVATE_KEY_FOOTER}) comes
     * after it in the same piece. Headers are found at every {@code -----BEGIN }, however they overlap, so a header
     * whose closing dashes open another is not hidden by the one before it.
     *
     * <p>A decoded JSON string holds no quote unless JSON held in it does, so for one string's text this is that
     * string's own block check, and for JSON held in it, or a decoding of a whole text at level {@code k}, it is the
     * check of each string at every level up to {@code k}, whose quotes bound it. In one string, the key material of an
     * open block may be in the strings after it, which the structural path reads one at a time ({@link JsonRedaction}),
     * so the whole text is masked.
     *
     * <p>Linear in the text: each piece that holds a header is read once for its footers and once for its headers, and
     * pieces that hold none are only skipped.
     */
    static boolean opensAnUnterminatedKey(String text) {
        if (!text.contains(ARMOR_BEGIN)) {
            return false;
        }
        // Each piece's footer labels, by their last footer, found in one pass and kept in a trie (#396): a label is
        // added and found in time linear in its length, with no hash of it taken, so the work stays linear however the
        // labels are chosen.
        ArmorLabels labels = null;
        int pieceEnd = -1;
        Matcher header = PRIVATE_KEY_HEADER.matcher(text);
        for (int at = text.indexOf(ARMOR_BEGIN); at >= 0; at = text.indexOf(ARMOR_BEGIN, at + 1)) {
            if (at > pieceEnd) {
                // The first header start in a new piece: index that piece's footers alone.
                int pieceStart = text.lastIndexOf('"', at) + 1;
                int quote = text.indexOf('"', at);
                pieceEnd = quote < 0 ? text.length() : quote;
                labels = new ArmorLabels();
                Matcher footer = PRIVATE_KEY_FOOTER.matcher(text).region(pieceStart, pieceEnd);
                while (footer.find()) {
                    labels.last.set(labels.add(text, footer.start(1), footer.end(1)), footer.start());
                }
            }
            if (!header.region(at, pieceEnd).lookingAt()) {
                continue;
            }
            int node = labels.find(text, header.start(1), header.end(1));
            if (node < 0 || labels.last.get(node) < header.end()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code text} with credential material masked, or {@code null} if
     * {@code text} is {@code null}.
     *
     * <p>Text that is one JSON object, array or string is read with a JSON parser, redacted on the tree and written
     * back with canonical escape spellings ({@link JsonRedaction}, #377); its whitespace, member order and numbers are
     * kept. JSON that path will not read (names that repeat in one object, nesting deeper than
     * {@link JsonRedaction#MAX_DEPTH}) is masked whole, and so is the text when anything on that path fails. Any other
     * text goes to the text engine. First, a text in which a decoding of its JSON escapes, at any depth, shows a private
     * key header the text does not spell plainly ({@link JsonRedaction#hidesAKey}) is masked whole.
     */
    public static String redact(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        try {
            if (JsonRedaction.hidesAKey(text, 0)) {
                // A key opener only a decoding shows (#389): no bound the structural path stops at can then rule out
                // key material in a later string, so the whole text is the mask.
                return MASK;
            }
            String out = redactAt(text, 0);
            // Settled (#377 stage 2): no decoding of the output's escapes may hold anything the text rules mask. Each
            // level reads its own strings; this reads them across their quotes, as the text rules once read every text.
            return ProseRedaction.settled(out) ? out : MASK;
        } catch (RuntimeException | StackOverflowError failed) {
            // Fail closed (#377): nothing of a text the structural path could not finish is kept.
            return MASK;
        }
    }

    /**
     * {@code text} redacted at JSON-in-string level {@code level}: on the tree if it is one JSON value and
     * {@code level} is below {@link JsonRedaction#MAX_LEVELS}, the mask if it is JSON that path will not read, and
     * otherwise by the text engine.
     */
    static String redactAt(String text, int level) {
        if (text.isEmpty()) {
            return text;
        }
        if (level < JsonRedaction.MAX_LEVELS && JsonRedaction.mayBeJson(text)) {
            try {
                String structural = JsonRedaction.redact(text, level);
                if (structural != null) {
                    return structural;
                }
            } catch (JsonRedaction.Unreadable unreadable) {
                return MASK;
            }
        }
        return ProseRedaction.redact(text, level);
    }

    /**
     * The text engine: {@code text} redacted by the patterns and readers below, adding to {@code reads}, unless it is
     * {@code null}, each read JWK discovery makes: at which escape level, and how much of that level's budget was left
     * before and after it.
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
        String out = applyMasks(text, masks);
        // A stray quote in a masked block may have hidden a JWK member from that read ({"kty":"RSA","note":
        // "-----BEGIN PRIVATE KEY-----"-----END PRIVATE KEY-----","d":...}): with the blocks masked, the JWKs are
        // found once more, spending what that read left of each level's budget, but never more than a first read of
        // the shortened text would get, with the same fallback once it is spent. This only adds masks.
        if (!pem.isEmpty()) {
            out = applyMasks(out, jwkMasks(out, discovery));
        }
        out = maskSchemeCredentials(out);
        out = JWT.matcher(out).replaceAll("$1.$2." + Matcher.quoteReplacement(MASK));
        // A JWK's private members in a fragment no object bounds (#377 stage 2): the text rules see no JSON value, so
        // any kty name in the text makes every private member name a secret one.
        boolean jwk = KTY_NAME.matcher(out).find() || EMBEDDED_KTY_NAME.matcher(out).find();
        out = maskStructures(out, JSON_FIELD_STRUCTURE, false, jwk);
        out = maskStructures(out, EMBEDDED_JSON_FIELD_STRUCTURE, true, jwk);
        out = JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecret(decodeName(m.group(1)), jwk)
                ? "\"" + m.group(1) + "\"" + m.group(2) + "\"" + masked(decodeName(m.group(1)), m.group(3)) + "\""
                : m.group()));
        out = EMBEDDED_JSON_FIELD.matcher(out).replaceAll(m -> Matcher.quoteReplacement(isSecret(decodeName(m.group(1)), jwk)
                ? "\\\"" + m.group(1) + "\\\"" + m.group(2) + "\\\"" + masked(decodeName(m.group(1)), m.group(3)) + "\\\""
                : m.group()));
        out = FORM_SECRET.matcher(out).replaceAll("$1=" + Matcher.quoteReplacement(MASK));
        out = HEADER_LINE.matcher(out).replaceAll(Redactor::maskHeaderLine);
        out = maskEscapedHeaderLines(out);
        return maskUnreadSecretNames(out, jwk);
    }

    /** Whether a member named {@code name} is masked by the text rules: a secret name, or with {@code jwk} a JWK private member. */
    private static boolean isSecret(String name, boolean jwk) {
        return isSecretKey(name) || (jwk && JWK_PRIVATE_MEMBERS.contains(name));
    }

    /** A secret value the rules left as the mask: the mask, after an {@code Authorization}-style scheme or not. */
    private static final Pattern MASKED_VALUE = Pattern.compile(
            "(?:[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*+ )?" + Pattern.quote(MASK));

    /**
     * Fail closed (owner decision on #339, kept through #377 stage 2): the first secret name, plain ({@code "name":}) or
     * in JSON held in a JSON string ({@code \"name\":}), whose value the rules before this left as anything but the
     * mask or {@code null} has its value masked from just after its colon to the end of the text. The text rules see no
     * JSON value ({@link ProseRedaction}), so such a name is in a fragment no reading can bound. A name spelled at a
     * deeper escape level is plain in some decoding of the text, which {@link ProseRedaction#settled} reads.
     */
    private static String maskUnreadSecretNames(String text, boolean jwk) {
        int cut = -1;
        String quote = null;
        for (boolean embedded : new boolean[] {false, true}) {
            Matcher m = (embedded ? EMBEDDED_FIELD_NAME : FIELD_NAME).matcher(text);
            while (m.find() && (cut < 0 || m.end() < cut)) {
                if (isSecret(decodeName(m.group(1)), jwk) && !readsAsMasked(text, m.end(), embedded)) {
                    cut = m.end();
                    quote = embedded ? "\\\"" : "\"";
                    break;
                }
            }
        }
        return cut < 0 ? text : text.substring(0, cut) + quote + MASK + quote;
    }

    /** Whether the value from {@code at}, after a secret name's colon, is the mask ({@link #MASKED_VALUE}) or null. */
    private static boolean readsAsMasked(String text, int at, boolean embedded) {
        Matcher space = SPACE_RUN.matcher(text);
        int i = space.region(at, text.length()).lookingAt() ? space.end() : at;
        if (text.startsWith("null", i) && (i + 4 == text.length() || !Character.isLetterOrDigit(text.charAt(i + 4)))) {
            return true;
        }
        String quote = embedded ? "\\\"" : "\"";
        if (!text.startsWith(quote, i)) {
            return false;
        }
        Matcher masked = MASKED_VALUE.matcher(text).region(i + quote.length(), text.length());
        return masked.lookingAt() && text.startsWith(quote, masked.end());
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
    static String masked(String name, String value) {
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
    private static String maskStructures(String text, Pattern fields, boolean embedded, boolean jwk) {
        Matcher m = fields.matcher(text);
        StringBuilder out = null;
        int copied = 0;
        int from = 0;
        while (from < text.length() && m.find(from)) {
            from = m.end();
            if (isSecret(decodeName(m.group(1)), jwk)) {
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
     * A private member whose value this reading does not consume and that opens with a quote of another level
     * ({@link #opensOtherQuote}) comes {@link JwkValue#unread}, from its value to the end of the string holding it or of
     * the text: fail closed (#352, security round 1), as {@link #maskUnreadSecretNames} masks a secret name's value.
     */
    private static List<JwkValue> jwkValues(String text, boolean embedded, int[] budget) {
        TreeSet<Integer> names = jwkNames(text, embedded, budget);
        List<JwkValue> values = new ArrayList<>();
        Matcher field = (embedded ? EMBEDDED_JSON_FIELD : JSON_FIELD).matcher(text);
        Matcher structure = (embedded ? EMBEDDED_JSON_FIELD_STRUCTURE : JSON_FIELD_STRUCTURE).matcher(text);
        Matcher member = (embedded ? EMBEDDED_JWK_PRIVATE_NAME : JWK_PRIVATE_NAME).matcher(text);
        int[] limits = null;
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
                values.add(new JwkValue(structure.end(), copied, name, false));
            } else if (field.region(name, text.length()).lookingAt() && field.end(2) >= copied
                    && JWK_PRIVATE_MEMBERS.contains(decodeName(field.group(1)))) {
                copied = field.end();
                values.add(new JwkValue(field.end(2), copied, name, false));
            } else if (member.region(name, text.length()).lookingAt() && member.end() >= copied) {
                int start = embedded ? afterSpace(text, member.end()) : afterJavaSpace(text, member.end());
                if (limits == null) {
                    limits = stringEnds(text, embedded, k -> false);
                }
                int limit = limits[start];
                if (start < limit && opensOtherQuote(text, start, embedded)) {
                    copied = limit;
                    values.add(new JwkValue(start, limit, name, true));
                }
            }
        }
        return values;
    }

    /**
     * Where the name of each {@link #JWK_PRIVATE_MEMBERS} member of a JWK in {@code text} starts, as {@link #jwkValues}
     * finds them. Once the budget is spent, every private member name in the text, in a JWK or not.
     */
    private static TreeSet<Integer> jwkNames(String text, boolean embedded, int[] budget) {
        Matcher type = (embedded ? EMBEDDED_JWK_TYPE : JWK_TYPE).matcher(text);
        Matcher kty = (embedded ? EMBEDDED_KTY_NAME : KTY_NAME).matcher(text);
        Pattern every = embedded ? EMBEDDED_JWK_PRIVATE_NAME : JWK_PRIVATE_NAME;
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
                return everyPrivateMember(text, every);
            }
            if (start < 0) {
                outside = member;
                outsideResult = start;
                continue;
            }
            List<JsonObject> objects = new ArrayList<>();
            int end = objects(text, start, embedded, matching, objects, budget);
            if (end == OUT_OF_TIME) {
                return everyPrivateMember(text, every);
            }
            readEnd = end;
            for (JsonObject object : objects) {
                if (object.names().stream().anyMatch(name -> kty.region(name, text.length()).lookingAt())) {
                    names.addAll(object.names());
                }
            }
        }
        return names;
    }

    /** Where whitespace as {@link #EMBEDDED_SPACE} reads it, from {@code from} in {@code text}, ends. */
    private static int afterSpace(String text, int from) {
        Matcher space = SPACE_RUN.matcher(text);
        return space.region(from, text.length()).lookingAt() ? space.end() : from;
    }

    /** Where Java's whitespace ({@code \s}, as {@link #JSON_FIELD} reads it), from {@code from} in {@code text}, ends. */
    private static int afterJavaSpace(String text, int from) {
        int i = from;
        while (i < text.length() && " \t\n\013\f\r".indexOf(text.charAt(i)) >= 0) {
            i++;
        }
        return i;
    }

    /**
     * Whether a member's value from {@code at} in {@code text} opens with a quote of another escape level than the
     * reading's own ({@code "} in plain JSON, {@code \"} in {@code embedded} JSON): a quote after another number of
     * backslashes, or a unicode escape of one after an odd number (in embedded JSON, three or more). No reading of this
     * level consumes such a value, and it may be the member's own value quoted as the level below spells it, so it is
     * masked (#352, security round 1). Any other value no reading consumes (a bare word, a second colon, a string cut
     * short) is kept, as the leak scanner keeps it.
     */
    private static boolean opensOtherQuote(String text, int at, boolean embedded) {
        int i = at;
        while (i < text.length() && text.charAt(i) == '\\') {
            i++;
        }
        int run = i - at;
        if (i >= text.length()) {
            return false;
        }
        if (text.charAt(i) == '"') {
            return run != (embedded ? 1 : 0);
        }
        return run % 2 == 1 && run >= (embedded ? 3 : 1) && text.regionMatches(true, i, "u0022", 0, 5);
    }

    /**
     * A JWK private member's value found by {@link #jwkValues}: where it starts and ends, and where its name starts.
     * {@code unread}: a value the reading does not consume, from its start to the end of the string holding it; it is
     * masked only where no other reading masks a value from there ({@link #withUnread}).
     */
    private record JwkValue(int start, int end, int name, boolean unread) {
    }

    /**
     * {@code masks} and each of the {@code unread} masks that starts where no mask in {@code masks} covers: a value one
     * reading does not consume and another reads whole is masked as that one reads it, so a value quoted with unicode
     * escapes in plain JSON keeps the rest of the text; a value no reading consumes is masked to the end of the string
     * holding it.
     */
    private static List<Mask> withUnread(List<Mask> masks, List<Mask> unread) {
        if (unread.isEmpty()) {
            return masks;
        }
        Coverage coverage = new Coverage(masks);
        List<Mask> all = new ArrayList<>(masks);
        for (Mask mask : unread) {
            if (!coverage.startsAt(mask.start()) && coverage.reach(mask.start()) <= mask.start()) {
                all.add(mask);
            }
        }
        return all;
    }

    /** Where masks start, in order, and the furthest any mask starting up to each place reaches. */
    private static final class Coverage {

        private final int[] starts;
        private final int[] reach;

        Coverage(List<Mask> masks) {
            List<Mask> sorted = new ArrayList<>(masks);
            sorted.sort((a, b) -> Integer.compare(a.start(), b.start()));
            starts = new int[sorted.size()];
            reach = new int[sorted.size()];
            for (int i = 0; i < sorted.size(); i++) {
                starts[i] = sorted.get(i).start();
                reach[i] = Math.max(i > 0 ? reach[i - 1] : 0, sorted.get(i).end());
            }
        }

        /** Whether a mask starts at {@code position}. */
        boolean startsAt(int position) {
            return Arrays.binarySearch(starts, position) >= 0;
        }

        /** The furthest any mask starting at or before {@code position} reaches, or -1 with none. */
        int reach(int position) {
            int at = Arrays.binarySearch(starts, position);
            if (at < 0) {
                at = -at - 2;
            } else {
                while (at + 1 < starts.length && starts[at + 1] == position) {
                    at++;
                }
            }
            return at < 0 ? -1 : reach[at];
        }
    }

    /** What a {@link Decoder} reads at the end of its level: the end of the text, or the quote closing the string. */
    private static final int END = -1;






    /**
     * Every JWK private member's value in the text, as masks on it: in plain JSON and in JSON embedded in a JSON
     * string. Deeper escape levels are read by {@link ProseRedaction#settled}, on every decoding of the output.
     */
    private static List<Mask> jwkMasks(String text, Discovery discovery) {
        List<Mask> masks = new ArrayList<>();
        List<Mask> unread = new ArrayList<>();
        for (JwkValue value : discovery.read("plain", text, false, discovery.plain)) {
            (value.unread() ? unread : masks).add(new Mask(value.start(), value.end(), "\"" + MASK + "\""));
        }
        // With a unicode escape, a quote may be spelled two ways; a decoding of the text reads that level
        // (ProseRedaction.settled).
        if (!UNICODE_ESCAPE.matcher(text).find()) {
            for (JwkValue value : discovery.read("embedded", text, true, discovery.embedded)) {
                (value.unread() ? unread : masks).add(new Mask(value.start(), value.end(), "\\\"" + MASK + "\\\""));
            }
        }
        return withUnread(masks, unread);
    }

    /** A read JWK discovery made at an escape level: how much of that level's budget was left before and after it. */
    record DiscoveryRead(String level, int before, int after) {
    }

    /**
     * What JWK discovery has left to read at each escape level: {@code 4n + 1024} characters for the plain and
     * the embedded JSON of a text of length {@code n}. Reading the text again (after its key blocks are masked) spends
     * what is left, but no more than {@code 4m + 1024} for the text it reads then, of length {@code m}.
     */
    private static final class Discovery {

        private final int[] plain;
        private final int[] embedded;
        private final List<DiscoveryRead> reads;

        Discovery(int length, List<DiscoveryRead> reads) {
            plain = new int[] {4 * length + 1024};
            embedded = new int[] {4 * length + 1024};
            this.reads = reads;
        }

        /**
         * {@link #jwkValues} at {@code level}, spending {@code budget}, recorded in the reads. A read gets no more
         * than {@code 4m + 1024} for a {@code text} of length {@code m}, however much the level has left: a second
         * read, of a text masking its key blocks has shortened, gets no more than a first read of that text would.
         */
        List<JwkValue> read(String level, String text, boolean embedded, int[] budget) {
            return spend(level, text, budget, left -> jwkValues(text, embedded, left));
        }

        private <T> T spend(String level, String text, int[] budget, java.util.function.Function<int[], T> search) {
            int before = budget[0];
            int allowance = Math.min(before, 4 * text.length() + 1024);
            int[] left = {allowance};
            T found = search.apply(left);
            budget[0] = left[0] < 0 ? left[0] : before - (allowance - left[0]);
            if (reads != null) {
                reads.add(new DiscoveryRead(level, before, budget[0]));
            }
            return found;
        }
    }

    /**
     * Every PEM block and PGP private key block in the text, as masks on it: a terminated block is masked whole, its
     * armor header and footer too (#377: the replay scanner reads any armor header in the Redactor's output as a leak);
     * an unterminated private key header is masked to the end of the text, unless it is in a terminated block or already
     * masked; and any other armor header is masked itself, so no header is left in the output.
     */
    private static List<Mask> pemMasks(String text) {
        List<Mask> masks = new ArrayList<>();
        List<int[]> blocks = keyBlocks(text);
        for (int[] block : blocks) {
            masks.add(new Mask(block[0], block[1], MASK));
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
            masks.add(new Mask(start, text.length(), MASK));
            break;
        }
        // A header in a mask above goes with that mask (applyMasks).
        Matcher armor = ARMOR_HEADER.matcher(text);
        while (armor.find()) {
            masks.add(new Mask(armor.start(), armor.end(), MASK));
        }
        return masks;
    }

    /**
     * Every terminated armor block in the text, in order, as {@code {start, end}}: an armor header of a label of
     * capital letters, digits and spaces, up to the first footer of the same label after it, and the next block
     * searched for after that footer. A header with no such footer opens no block. This is what the regular expression
     * {@code -----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----} (DOTALL) finds in turn, found in one linear pass (#390).
     *
     * <p>A label is the whole run of label characters after the armor word, as the dashes after it are not label
     * characters, so each header and footer has one label. The footers are listed by label first, in
     * {@link ArmorLabels}. The headers are then read in order, and a header's end is past every earlier header's, so a
     * footer that starts before it can close no later header either and is dropped: each footer is passed once.
     */
    static List<int[]> keyBlocks(String text) {
        ArmorLabels labels = new ArmorLabels();
        // Footer i starts at footerAt[i] and ends at footerEnd[i]; the footers of one label are chained in order by
        // nextFooter, from labels.first to labels.last of that label's node.
        IntList footerAt = new IntList();
        IntList footerEnd = new IntList();
        IntList nextFooter = new IntList();
        for (int at = text.indexOf(ARMOR_END); at >= 0; at = text.indexOf(ARMOR_END, at + 1)) {
            int labelStart = at + ARMOR_END.length();
            int labelEnd = armorLabelEnd(text, labelStart);
            if (labelEnd > labelStart && text.startsWith(ARMOR_DASHES, labelEnd)) {
                int footer = footerAt.size();
                footerAt.add(at);
                footerEnd.add(labelEnd + ARMOR_DASHES.length());
                nextFooter.add(-1);
                int node = labels.add(text, labelStart, labelEnd);
                int last = labels.last.get(node);
                if (last < 0) {
                    labels.first.set(node, footer);
                } else {
                    nextFooter.set(last, footer);
                }
                labels.last.set(node, footer);
            }
        }
        List<int[]> blocks = new ArrayList<>();
        int from = 0;
        for (int at = text.indexOf(ARMOR_BEGIN); at >= 0; at = text.indexOf(ARMOR_BEGIN, Math.max(at + 1, from))) {
            int labelStart = at + ARMOR_BEGIN.length();
            int labelEnd = armorLabelEnd(text, labelStart);
            if (labelEnd == labelStart || !text.startsWith(ARMOR_DASHES, labelEnd)) {
                continue;
            }
            int node = labels.find(text, labelStart, labelEnd);
            if (node < 0) {
                continue;
            }
            int headerEnd = labelEnd + ARMOR_DASHES.length();
            int footer = labels.first.get(node);
            while (footer >= 0 && footerAt.get(footer) < headerEnd) {
                footer = nextFooter.get(footer);
            }
            if (footer >= 0) {
                blocks.add(new int[] {at, footerEnd.get(footer)});
                from = footerEnd.get(footer);
                footer = nextFooter.get(footer);
            }
            labels.first.set(node, footer);
        }
        return blocks;
    }

    /**
     * The footer labels of {@link #keyBlocks} and of {@link #opensAnUnterminatedKey}, in a trie over the
     * {@value #ARMOR_LABEL_CHARS} armor label characters, a node per distinct prefix. A node's children are chained as
     * siblings, so finding a child reads at most that many nodes, and a label is added or found in time linear in its
     * length: no hash of the label is taken, which labels could be chosen to collide on (automated review on #395, #396).
     */
    private static final class ArmorLabels {
        private final IntList firstChild = new IntList();
        private final IntList nextSibling = new IntList();
        private final StringBuilder edge = new StringBuilder();
        /**
         * Per node, -1 until set: in {@link #keyBlocks}, the first footer of its label not yet passed and its label's
         * last footer; in {@link #opensAnUnterminatedKey}, {@code last} is where its label's last footer starts.
         */
        final IntList first = new IntList();
        final IntList last = new IntList();

        ArmorLabels() {
            node('\0');
        }

        /** The node of the label {@code text[start, end)}, added with its prefixes if new. */
        int add(String text, int start, int end) {
            int node = 0;
            for (int i = start; i < end; i++) {
                char c = text.charAt(i);
                int child = child(node, c);
                if (child < 0) {
                    child = node(c);
                    nextSibling.set(child, firstChild.get(node));
                    firstChild.set(node, child);
                }
                node = child;
            }
            return node;
        }

        /** The node of the label {@code text[start, end)}, or -1 if no footer label starts with it. */
        int find(String text, int start, int end) {
            int node = 0;
            for (int i = start; i < end && node >= 0; i++) {
                node = child(node, text.charAt(i));
            }
            return node;
        }

        private int child(int node, char c) {
            int child = firstChild.get(node);
            while (child >= 0 && edge.charAt(child) != c) {
                child = nextSibling.get(child);
            }
            return child;
        }

        private int node(char c) {
            edge.append(c);
            firstChild.add(-1);
            nextSibling.add(-1);
            first.add(-1);
            last.add(-1);
            return edge.length() - 1;
        }
    }

    /** A growable list of ints, without boxing. */
    private static final class IntList {
        private int[] values = new int[16];
        private int size;

        void add(int value) {
            if (size == values.length) {
                values = Arrays.copyOf(values, 2 * size);
            }
            values[size++] = value;
        }

        int get(int i) {
            return values[i];
        }

        void set(int i, int value) {
            values[i] = value;
        }

        int size() {
            return size;
        }
    }

    /** Where the run of armor label characters (capital letters, digits and spaces) that starts at {@code at} ends. */
    private static int armorLabelEnd(String text, int at) {
        int end = at;
        while (end < text.length() && isArmorLabelChar(text.charAt(end))) {
            end++;
        }
        return end;
    }

    private static boolean isArmorLabelChar(char c) {
        return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ';
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
    private static TreeSet<Integer> everyPrivateMember(String text, Pattern names) {
        TreeSet<Integer> found = new TreeSet<>();
        Matcher m = names.matcher(text);
        while (m.find()) {
            found.add(m.start());
        }
        return found;
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
     * Returns JSON-shaped plain data redacted by the same rules as a JSON text ({@link #redact(String)}), as new plain
     * data, or {@code null} if {@code value} is {@code null}.
     *
     * <p>{@code value} may hold only {@code null}, strings, booleans, the JDK's own number types ({@code Integer},
     * {@code Long}, {@code Short}, {@code Byte}, {@code Double}, {@code Float}, {@code BigInteger} and
     * {@code BigDecimal}), maps whose keys are all strings, and lists, holding only the same (#377, typed tree). Any
     * other value anywhere in it (a record, an enum, a set, an array, a map with a key that is not a string, a Jackson
     * tree) is rejected, and the whole result is the mask: a caller converts such values to plain data first.
     *
     * <p>The tree is read once into the JSON path's own nodes and redacted there ({@link JsonRedaction#redactTree}), so
     * each string, member name and secret-named or JWK member is redacted exactly as it is in the same tree written as
     * JSON text. Maps keep their order, and numbers and booleans are returned as they are. A tree that weighs more than
     * {@link JsonRedaction#MAX_WEIGHT}, nests deeper than {@link JsonRedaction#MAX_DEPTH}, or that the JSON path would
     * mask whole as a text, is the mask, as is any failure while it is read.
     */
    public static Object redactTree(Object value) {
        try {
            return JsonRedaction.redactTree(value);
        } catch (Exception | LinkageError | AssertionError | StackOverflowError failed) {
            // Fail closed (#360, #377): a caller value that cannot be read or redacted is not kept, nor is its error.
            return MASK;
        }
    }

    /** Whether a field with this name holds a secret or a credential header's value. */
    static boolean isSecretKey(String key) {
        return isSecretField(key) || isSensitiveHeader(key);
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
