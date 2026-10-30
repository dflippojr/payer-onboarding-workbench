package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.RecordComponent;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import tools.jackson.databind.json.JsonMapper;

/**
 * Class-level check (#160): generates secrets of every shape {@link Redactor} promises to mask
 * (random tokens after Bearer, Token or DPoP, Basic {@code user:pass}, colon-split bearers, numeric
 * secrets, PEM and PGP private keys,
 * values full of JSON escapes), raw or URL-encoded, places them where a payer echoes credentials
 * (headers, bodies, query strings, bodies cut off at any position in a JSON value), with or without
 * the whole text quoted inside a JSON string (also by a serializer that escapes {@code /} or
 * {@code +}), and
 * asserts that no piece of the secret survives: through {@link Redactor} itself, and through every
 * text field of the run model, {@link StepResult} and {@link Finding} (#211).
 * {@code replay/test/leaks.test.mjs} runs the same generator against the leak scanner. Everything
 * is generated; nothing secret-shaped is committed.
 */
class RedactorPropertyTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** Characters of an RFC 6750 b64token, without the {@code =} padding. */
    private static final String TOKEN_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/";

    /** A secret leaks if any run of this many of its characters is still in the output. */
    private static final int PIECE = 8;

    private static final List<String> BEFORE =
            List.of("", " ", "\n", "\r\n", "\t", "(", "\"", "Authorization: ", "debug=");
    private static final List<String> AFTER =
            List.of("", " ", "\n", ",", ";", ")", ".", "\"", "'", "&next=1", " and more text");

    private static final List<String> JSON_FIELDS = List.of(
            "client_secret", "clientSecret", "client-secret", "access_token", "accessToken", "ACCESS_TOKEN",
            "refresh_token", "id_token", "password", "api_key", "apiKey", "private_key", "secret",
            "client_assertion", "assertion");
    private static final List<String> FORM_KEYS = List.of(
            "client_secret", "Client_Secret", "access_token", "ACCESS_TOKEN", "refresh_token", "id_token",
            "password", "api_key", "apikey", "private_key");
    private static final List<String> PEM_KEYS = List.of("private_key", "privateKey", "Private-Key");
    private static final List<String> CREDENTIAL_HEADERS = List.of(
            "X-Api-Key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-client-secret", "Cookie", "Set-Cookie");
    private static final List<String> AUTHORIZATION_HEADERS = List.of("Authorization", "authorization", "Proxy-Authorization");
    /** Schemes a token-shaped secret follows: Token and DPoP are masked as Bearer is (#262). */
    private static final List<String> BEARER_SCHEMES = List.of("Bearer", "bearer", "BEARER", "Token", "token", "DPoP", "dpop");
    private static final List<String> PEM_LABELS = List.of(
            "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK");

    enum Shape { TOKEN, BASIC_USER_PASS, COLON_BEARER, NUMERIC, PEM, ESCAPED }

    enum Encoding { RAW, URL }

    enum Slot {
        /** {@code Authorization: <scheme> <secret>}, through {@link Redactor#redactHeaders}. */
        AUTHORIZATION_HEADER,
        /** A credential header such as {@code X-Api-Key}, through {@link Redactor#redactHeaders}. */
        CREDENTIAL_HEADER,
        /** {@code <scheme> <secret>} in free text. */
        AUTH_TEXT,
        /** An httpbin-style echo: {@code {"headers":{"Authorization":"<scheme> <secret>"}}}. */
        HEADERS_ECHO,
        /**
         * A secret-named JSON field, also with a number value and in a body cut off at any position
         * in the value, inside an escape too.
         */
        JSON_FIELD,
        /** A secret key in a form body. */
        FORM_BODY,
        /** A secret key in a request line's query string. */
        QUERY_STRING,
        /** A PEM block in free text. */
        PEM_TEXT
    }

    /** Where a text slot ends up: a response body, or the value of a header that is not a credential. */
    enum Carrier { BODY, HEADER }

    /**
     * Whether the whole text is quoted inside a JSON string, and if so whether by a serializer that
     * escapes {@code /} as {@code \/} (PHP's {@code json_encode}, for one), or {@code +} and {@code /}
     * as six-character unicode escapes ({@code System.Text.Json} escapes {@code +}), as a payer that
     * echoes a token into an {@code error_description} may (#211).
     */
    enum Wrap { NONE, JSON, JSON_ESCAPED_SLASHES, JSON_UNICODE_ESCAPED }

    /**
     * A generated secret: its text, and for a PEM block the base64 lines that are the secret
     * (Redactor keeps the armor lines so the key type stays readable).
     */
    record Secret(Shape shape, String value, List<String> pemLines) {
    }

    record Case(Secret secret, Slot slot, Encoding encoding, int variant, String before, String after,
                Wrap wrap, Carrier carrier, int cut) {

        String placed() {
            return encoding == Encoding.URL ? URLEncoder.encode(secret.value(), StandardCharsets.UTF_8) : secret.value();
        }

        private String pick(List<String> options) {
            return options.get(variant % options.size());
        }

        private String scheme() {
            return pick(secret.shape() == Shape.BASIC_USER_PASS ? List.of("Basic", "basic", "BASIC") : BEARER_SCHEMES);
        }

        String text() {
            if (slot == Slot.JSON_FIELD && variant % 3 == 2) {
                return cutJsonField();
            }
            String text = switch (slot) {
                case AUTH_TEXT -> before + scheme() + " " + placed() + after;
                case HEADERS_ECHO -> "{\"headers\":{\"Host\":\"payer.example.test\",\"Authorization\":"
                        + JSON.writeValueAsString(scheme() + " " + placed()) + "}}";
                case JSON_FIELD -> jsonField();
                case FORM_BODY -> "grant_type=client_credentials&" + pick(keys(FORM_KEYS)) + "=" + placed()
                        + (variant % 2 == 0 ? "&scope=system%2F*.read" : "");
                case QUERY_STRING -> "GET https://payer.example.test/token?" + pick(keys(FORM_KEYS)) + "=" + placed()
                        + List.of(" HTTP/1.1", "&state=af0ifjsldkj HTTP/1.1", "", "#frag").get(variant % 4);
                case PEM_TEXT -> before + placed() + after;
                default -> throw new IllegalStateException(slot + " is not a text slot");
            };
            return wrap == Wrap.NONE ? text : "{\"debug\":" + quote(text) + "}";
        }

        boolean textSlot() {
            return slot != Slot.AUTHORIZATION_HEADER && slot != Slot.CREDENTIAL_HEADER;
        }

        /** {@code text} as a JSON string, as the {@link #wrap} serializer writes it. */
        private String quote(String text) {
            String quoted = JSON.writeValueAsString(text);
            return switch (wrap) {
                case JSON_ESCAPED_SLASHES -> quoted.replace("/", "\\/");
                case JSON_UNICODE_ESCAPED -> unicodeEscaped(quoted);
                default -> quoted;
            };
        }

        /** {@code +} as {@code System.Text.Json} escapes it, and {@code /} with lower-case hex. */
        private static String unicodeEscaped(String text) {
            return text.replace("+", "\\u002B").replace("/", "\\u002f");
        }

        /**
         * {@code out} as the pieces are looked for in it: with the unicode escapes the wrap wrote, also
         * escaped again, read back as {@code +} and {@code /}, so an escaped piece of the secret counts.
         * (Escaped pieces would also match the escapes of ordinary text such as {@code https://}.)
         */
        String seen(String out) {
            return wrap != Wrap.JSON_UNICODE_ESCAPED ? out : out + "\n"
                    + out.replaceAll("\\\\++u002B", "+").replaceAll("\\\\++u002f", "/");
        }

        private List<String> keys(List<String> keys) {
            return secret.shape() == Shape.PEM ? List.of("private_key") : keys;
        }

        /** A secret field after a harmless one; the body continues or closes after the value. */
        private String jsonField() {
            return variant % 3 == 0
                    ? jsonFieldStart() + jsonValue() + ",\"error_description\":\"Client authentication failed\"}"
                    : jsonFieldStart() + jsonValue() + "}";
        }

        private String jsonFieldStart() {
            return "{\"error\":\"invalid_client\",\"" + pick(secret.shape() == Shape.PEM ? PEM_KEYS : JSON_FIELDS) + "\":";
        }

        private boolean numberValue() {
            return secret.shape() == Shape.NUMERIC && encoding == Encoding.RAW && variant % 2 == 1;
        }

        private String jsonValue() {
            return numberValue() ? placed() : JSON.writeValueAsString(placed());
        }

        /**
         * A body cut off at any position in the secret's value, inside an escape too, which keeps at
         * least the value's opening quote or first digit. Quoted inside a JSON string, the cut comes
         * before the JSON was quoted or after. The note the workbench appends to a cut body may follow.
         */
        private String cutJsonField() {
            String field = jsonFieldStart();
            String value = jsonValue();
            String note = variant / 3 % 2 == 0 ? "" : "\n[not parsed: more JSON values than the limit]";
            String inner = field + value.substring(0, 1 + cut % (value.length() - 1));
            if (wrap == Wrap.NONE) {
                return inner + note;
            }
            if (variant / 6 % 2 == 0) {
                return "{\"debug\":" + quote(inner) + "}" + note;
            }
            String quoted = quote(field + value);
            int start = JSON.writeValueAsString(field).length() - 1 + (numberValue() ? 1 : 2);
            int end = quoted.length() - 1;
            return "{\"debug\":" + quoted.substring(0, start + cut % (end - start)) + note;
        }

        String redacted() {
            return switch (slot) {
                case AUTHORIZATION_HEADER -> redactHeader(pick(AUTHORIZATION_HEADERS), scheme() + " " + placed());
                case CREDENTIAL_HEADER -> redactHeader(pick(CREDENTIAL_HEADERS), placed());
                default -> carrier == Carrier.BODY ? Redactor.redact(text()) : redactHeader("X-Debug-Echo", text());
            };
        }

        private static String redactHeader(String name, String value) {
            return Redactor.redactHeaders(Map.of(name, List.of(value))).get(name).get(0);
        }

        /**
         * Every {@link #PIECE}-character run of the secret as placed: of the base64 lines of a raw
         * PEM block, otherwise of the whole (encoded) value, and with {@code /} escaped too where the
         * wrap escapes it. A shorter secret is one piece. See {@link #seen(String)} for unicode escapes.
         */
        List<String> pieces() {
            List<String> chunks = secret.shape() == Shape.PEM && encoding == Encoding.RAW ? secret.pemLines() : List.of(placed());
            if (wrap == Wrap.JSON_ESCAPED_SLASHES) {
                chunks = Stream.concat(chunks.stream(), chunks.stream().map(c -> c.replace("/", "\\/"))).toList();
            }
            return chunks.stream()
                    .flatMap(c -> c.length() <= PIECE
                            ? Stream.of(c)
                            : IntStream.rangeClosed(0, c.length() - PIECE).mapToObj(i -> c.substring(i, i + PIECE)))
                    .toList();
        }
    }

    @Property(tries = 3000)
    void noGeneratedSecretSurvives(@ForAll("cases") Case c) {
        String out = c.seen(c.redacted());

        for (String piece : c.pieces()) {
            assertFalse(out.contains(piece), () -> "'" + piece + "' survived in: " + out);
        }
        assertTrue(out.contains(Redactor.MASK), () -> "no mask in: " + out);
    }

    /** Identifiers the workbench sets itself, never text from the payer. */
    private static final Set<String> NOT_PAYER_TEXT = Set.of("stepId", "checkId");

    /** A typed value in step details, as {@code ExchangeView} or {@code RedactedConnection} is. */
    record Echo(String body, List<String> notes, Map<String, List<String>> headers) {
    }

    /**
     * Class-level check (#211): the run model redacts everything it holds, so the live run API, the
     * stored run and the reports agree. Each generated case goes into every text component of
     * {@link StepResult} and {@link Finding} (found by reflection, so a component added later is
     * covered too) and into step details at every depth: a map value and key, a list and array entry,
     * a record component and a recorded header. No piece of the secret may survive.
     */
    @Property(tries = 1000)
    void noGeneratedSecretSurvivesInAStepOrFinding(@ForAll("cases") Case c) throws ReflectiveOperationException {
        Map<String, Object> details = new LinkedHashMap<>();
        String text;
        if (c.textSlot()) {
            text = c.text();
            details.put("summary", text);
            details.put("cards", List.of(Map.of("source", text)));
            details.put("exchange", new Echo(text, List.of(text), Map.of("X-Debug-Echo", List.of(text))));
            details.put("array", new Object[] {text, new String[] {text}});
            details.put("keyed", Map.of(text, "value"));
        } else {
            text = "ok";
            String value = c.slot() == Slot.AUTHORIZATION_HEADER ? c.scheme() + " " + c.placed() : c.placed();
            String name = c.pick(c.slot() == Slot.AUTHORIZATION_HEADER ? AUTHORIZATION_HEADERS : CREDENTIAL_HEADERS);
            details.put("exchanges", List.of(Map.of("requestHeaders", Map.of(name, List.of(value)))));
        }
        StepResult step = construct(StepResult.class, text, details);
        Finding finding = construct(Finding.class, text, details);
        // The JSON form shows what an array holds, which its toString does not.
        List<String> surfaces = List.of(step.toString(), finding.toString(), JSON.writeValueAsString(step.details()));

        for (String surface : surfaces.stream().map(c::seen).toList()) {
            for (String piece : c.pieces()) {
                assertFalse(surface.contains(piece), () -> "'" + piece + "' survived in: " + surface);
            }
        }
    }

    /** A {@code type} whose every text component holds {@code text} and whose map holds {@code details}. */
    private static <R extends Record> R construct(Class<R> type, String text, Map<String, Object> details)
            throws ReflectiveOperationException {
        RecordComponent[] components = type.getRecordComponents();
        Object[] args = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            String name = components[i].getName();
            Class<?> t = components[i].getType();
            args[i] = NOT_PAYER_TEXT.contains(name) ? "synthetic-id"
                    : t == String.class ? text
                    : t == Map.class ? details
                    : t == Instant.class ? Instant.EPOCH
                    : t == Duration.class ? Duration.ZERO
                    : t == boolean.class ? Boolean.FALSE
                    : t == Severity.class ? Severity.FAIL
                    : fail(type.getSimpleName() + "." + name + " is a " + t.getSimpleName()
                            + "; give it a value here, with the secret if it can hold payer text");
        }
        return type.getDeclaredConstructor(Arrays.stream(components).map(RecordComponent::getType)
                .toArray(Class<?>[]::new)).newInstance(args);
    }

    @Provide
    Arbitrary<Case> cases() {
        return secrets().flatMap(secret -> Combinators.combine(
                        Arbitraries.of(slotsFor(secret.shape())),
                        Arbitraries.of(Encoding.values()),
                        Arbitraries.integers().between(0, 59),
                        Arbitraries.of(BEFORE),
                        Arbitraries.of(AFTER),
                        Arbitraries.of(Wrap.values()),
                        Arbitraries.of(Carrier.values()),
                        Arbitraries.integers().between(0, 1_000_000))
                .as((slot, encoding, variant, before, after, wrap, carrier, cut) -> new Case(secret, slot,
                        // Outside a secret-named key, a PEM block is found by its armor, which URL encoding
                        // removes; URL encoding would remove the escapes of an escaped value.
                        slot == Slot.PEM_TEXT || secret.shape() == Shape.ESCAPED ? Encoding.RAW : encoding,
                        variant, before, after, wrap, carrier, cut)));
    }

    private static List<Slot> slotsFor(Shape shape) {
        return switch (shape) {
            case PEM -> List.of(Slot.CREDENTIAL_HEADER, Slot.JSON_FIELD, Slot.FORM_BODY, Slot.QUERY_STRING, Slot.PEM_TEXT);
            case ESCAPED -> List.of(Slot.JSON_FIELD);
            default -> Arrays.stream(Slot.values()).filter(s -> s != Slot.PEM_TEXT).toList();
        };
    }

    private static Arbitrary<Secret> secrets() {
        return Arbitraries.oneOf(tokens(), basicUserPass(), colonBearers(), numbers(), pemBlocks(), escaped());
    }

    /**
     * A value whose JSON string holds many escapes: {@code \\}, {@code \"}, {@code \n}, {@code \t}
     * and the six-character escape of a control character.
     */
    private static Arbitrary<Secret> escaped() {
        return Arbitraries.strings().withChars(TOKEN_CHARS + "\\\"\n\t\u0001").ofMinLength(PIECE).ofMaxLength(64)
                .map(v -> new Secret(Shape.ESCAPED, v, List.of()));
    }

    /**
     * One short all-letter word after a scheme, perhaps ending a sentence, is prose by design (#160),
     * so a token is never one.
     */
    private static Arbitrary<Secret> tokens() {
        return Combinators.combine(
                        Arbitraries.strings().withChars(TOKEN_CHARS).ofMinLength(PIECE).ofMaxLength(64),
                        Arbitraries.integers().between(0, 2))
                .as((body, padding) -> body + "=".repeat(padding))
                .filter(t -> !t.matches("[A-Za-z]{1,15}\\.*"))
                .map(t -> new Secret(Shape.TOKEN, t, List.of()));
    }

    /** The base64 of an RFC 7617 {@code user:pass} pair; the password may hold a colon or non-ASCII letters. */
    private static Arbitrary<Secret> basicUserPass() {
        Arbitrary<String> user = Arbitraries.strings().withCharRange('!', '~').excludeChars(':').ofMinLength(3).ofMaxLength(20);
        Arbitrary<String> pass = Arbitraries.strings().withCharRange(' ', '~').withChars("éüß€").ofMinLength(3).ofMaxLength(30);
        return Combinators.combine(user, pass).as((u, p) -> new Secret(Shape.BASIC_USER_PASS,
                Base64.getEncoder().encodeToString((u + ":" + p).getBytes(StandardCharsets.UTF_8)), List.of()));
    }

    private static Arbitrary<Secret> colonBearers() {
        return Combinators.combine(
                        Arbitraries.strings().withChars(TOKEN_CHARS).ofMinLength(4).ofMaxLength(32),
                        Arbitraries.strings().withChars(TOKEN_CHARS + ":").ofMinLength(4).ofMaxLength(32))
                .as((token, suffix) -> new Secret(Shape.COLON_BEARER, token + ":" + suffix, List.of()));
    }

    private static Arbitrary<Secret> numbers() {
        return Arbitraries.longs().between(100_000L, Long.MAX_VALUE)
                .map(n -> new Secret(Shape.NUMERIC, String.valueOf(n), List.of()));
    }

    /** A private key, sometimes cut off before its footer (a truncated paste). */
    private static Arbitrary<Secret> pemBlocks() {
        return Combinators.combine(
                        Arbitraries.of(PEM_LABELS),
                        Arbitraries.bytes().array(byte[].class).ofMinSize(48).ofMaxSize(1200),
                        Arbitraries.of("\n", "\r\n"),
                        Arbitraries.of(false, true))
                .as((label, key, newline, truncated) -> {
                    String body = Base64.getMimeEncoder(64, newline.getBytes(StandardCharsets.US_ASCII)).encodeToString(key);
                    String pem = "-----BEGIN " + label + "-----" + newline + body + newline
                            + (truncated ? "" : "-----END " + label + "-----");
                    List<String> lines = Arrays.stream(body.split(newline)).filter(l -> l.length() >= PIECE).toList();
                    return new Secret(Shape.PEM, pem, lines);
                });
    }
}
