package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Keys and tokens are generated at runtime; nothing secret-shaped is committed. */
class RedactorTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void bearerChallengeParametersSurviveRedaction() {
        String challenge = "Bearer error=\"invalid_token\", error_description=\"Expired\", scope=\"system/*.read\"";
        assertEquals(challenge, Redactor.redact(challenge));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer a-long-secret-token"));
    }

    @Test
    void masksBearerHeaderButKeepsScheme() {
        String token = randomToken();
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Content-Type", List.of("application/json"));
        headers.put("Authorization", List.of("Bearer " + token));

        Map<String, List<String>> out = Redactor.redactHeaders(headers);

        assertEquals(List.of("Bearer " + Redactor.MASK), out.get("Authorization"));
        assertEquals(List.of("application/json"), out.get("Content-Type"));
        assertEquals(List.of("Content-Type", "Authorization"), List.copyOf(out.keySet()));
    }

    @Test
    void masksBearerTokenInFreeText() {
        String token = randomToken();
        String out = Redactor.redact("curl -H \"Authorization: Bearer " + token + "\" https://payer.example.test");

        assertFalse(out.contains(token));
        assertTrue(out.contains("Bearer " + Redactor.MASK));
    }

    @Test
    void masksOtherCredentialHeadersEntirely() {
        String key = randomToken();
        Map<String, List<String>> out = Redactor.redactHeaders(Map.of("x-api-key", List.of(key)));

        assertEquals(List.of(Redactor.MASK), out.get("x-api-key"));
    }

    @Test
    void masksClientAssertionJwtWhole() {
        String header = b64url("{\"alg\":\"RS384\",\"typ\":\"JWT\"}");
        String payload = b64url("{\"iss\":\"synthetic-client\",\"aud\":\"https://payer.example.test/token\"}");
        byte[] sig = new byte[256];
        RANDOM.nextBytes(sig);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        String jwt = header + "." + payload + "." + signature;

        String out = Redactor.redact("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                + "&client_assertion=" + jwt);

        // A client_assertion JWT is masked whole, claims included (DECISIONS.md:71, issue #260).
        assertFalse(out.contains(signature));
        assertFalse(out.contains(header));
        assertEquals("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                + "&client_assertion=" + Redactor.MASK, out);
    }

    @Test
    void masksPemPrivateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----";

        String out = Redactor.redact("credential file contents:\n" + pem + "\ntrailing text");

        assertFalse(out.contains(body.substring(0, 40)));
        assertTrue(out.contains("-----BEGIN PRIVATE KEY-----\n" + Redactor.MASK + "\n-----END PRIVATE KEY-----"));
        assertTrue(out.endsWith("trailing text"));
    }

    @Test
    void masksTruncatedPemPrivateKey() {
        String body = randomToken() + randomToken();
        String out = Redactor.redact("-----BEGIN EC PRIVATE KEY-----\n" + body);

        assertFalse(out.contains(body));
        assertEquals("-----BEGIN EC PRIVATE KEY-----\n" + Redactor.MASK, out);
    }

    @Test
    void masksClientSecretInFormBody() {
        String secret = randomToken();
        String out = Redactor.redact("grant_type=client_credentials&client_id=synthetic-client&client_secret="
                + secret + "&scope=system%2F*.read");

        assertEquals("grant_type=client_credentials&client_id=synthetic-client&client_secret="
                + Redactor.MASK + "&scope=system%2F*.read", out);
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_assertion", "clientAssertion", "client-assertion", "assertion", "secret",
            "clientSecret", "client-secret", "accessToken", "refresh-token", "privateKey", "api-key"})
    void masksSecretKeyInFormBody(String key) {
        assertEquals("a=1&" + key + "=" + Redactor.MASK + "&b=2",
                Redactor.redact("a=1&" + key + "=PHNhbWw6QXNz&b=2"));
    }

    @Test
    void everySecretFieldIsMaskedAsAFormKey() {
        for (String name : Redactor.SECRET_FIELDS) {
            int half = name.length() / 2;
            String split = name.substring(0, half) + "_" + name.substring(half);
            for (String key : List.of(name, name.toUpperCase(Locale.ROOT), split, split.replace('_', '-'))) {
                assertEquals(key + "=" + Redactor.MASK + "&x=1", Redactor.redact(key + "=PHNhbWw6QXNz&x=1"), key);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Cookie", "Set-Cookie", "X-Api-Key", "Api-Key", "X-Auth-Token", "X-Access-Token",
            "x-client-secret", "Proxy-Authorization"})
    void masksSensitiveHeaderLine(String name) {
        assertEquals("HTTP/1.1 401\n" + name + ": " + Redactor.MASK + "\nContent-Length: 0",
                Redactor.redact("HTTP/1.1 401\n" + name + ": sid=abc; Path=/\nContent-Length: 0"));
    }

    @Test
    void masksSensitiveHeaderLineToTheEndOfTheLine() {
        assertEquals("Set-Cookie: " + Redactor.MASK, Redactor.redact("Set-Cookie: sid=\"a b\"; Path=/; HttpOnly"));
        assertEquals("Cookie: " + Redactor.MASK + "\r\nAccept: */*", Redactor.redact("Cookie: a=1; b=2\r\nAccept: */*"));
        assertEquals("  x-api-key:" + Redactor.MASK, Redactor.redact("  x-api-key:k1"));
        // Only a lower-case \n or \r is a JSON line-break escape; \N and \R are part of the value.
        assertEquals("X-Client-Secret: " + Redactor.MASK, Redactor.redact("X-Client-Secret: abc\\Ndef0001"));
        assertEquals("X-Client-Secret: " + Redactor.MASK, Redactor.redact("X-Client-Secret: abc\\Rdef0002"));
        // Quoted inside a JSON string: the value ends at the next escaped line break or the closing quote.
        assertEquals("{\"debug\":\"echo:\\nCookie: " + Redactor.MASK + "\\nAccept: */*\"}",
                Redactor.redact("{\"debug\":\"echo:\\nCookie: sid=\\\"q\\\"; a=1\\nAccept: */*\"}"));
        assertEquals("{\"debug\":\"echo:\\nX-Auth-Token: " + Redactor.MASK + "\"}",
                Redactor.redact("{\"debug\":\"echo:\\nX-Auth-Token: tok\"}"));
    }

    @Test
    void masksSensitiveHeaderLineInJsonEmbeddedInAJsonString() {
        // The inner string's line break is \\n and its closing quote \"; an escaped quote in it is \\\".
        String masked = "{\"body\":\"{\\\"m\\\":\\\"x\\\\nCookie: " + Redactor.MASK + "\\\\nAccept: a\\\"}\"}";
        assertEquals(masked,
                Redactor.redact("{\"body\":\"{\\\"m\\\":\\\"x\\\\nCookie: sid=\\\\\\\"q\\\\\\\"\\\\nAccept: a\\\"}\"}"));
        assertEquals(masked, Redactor.redact(masked));
        assertEquals("{\"body\":\"{\\\"m\\\":\\\"x\\\\nCookie: " + Redactor.MASK + "\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"m\\\":\\\"x\\\\nCookie: sid=1\\\"}\"}"));
        // An indent quoted inside the string: an escaped tab, also in embedded JSON.
        assertEquals("{\"m\":\"x\\n\\tCookie: " + Redactor.MASK + "\\nend\"}", Redactor.redact("{\"m\":\"x\\n\\tCookie: sid=1\\nend\"}"));
        assertEquals("{\"body\":\"{\\\"m\\\":\\\"x\\\\n\\\\t X-Api-Key: " + Redactor.MASK + "\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"m\\\":\\\"x\\\\n\\\\t X-Api-Key: k1\\\"}\"}"));
        // A string cut off inside the value: masked to the end.
        assertEquals("{\"m\":\"x\\nCookie: " + Redactor.MASK, Redactor.redact("{\"m\":\"x\\nCookie: sid=1; a=\\"));
    }

    @Test
    void sensitiveHeaderLineKeepsTheAuthorizationScheme() {
        assertEquals("Authorization: Bearer " + Redactor.MASK, Redactor.redact("Authorization: Bearer abc.def"));
        assertEquals("Proxy-Authorization: Basic " + Redactor.MASK, Redactor.redact("Proxy-Authorization: Basic YWJjOmRl"));
        assertEquals("Authorization: Bearer " + Redactor.MASK, Redactor.redact("Authorization: Bearer abc123, more"));
        assertEquals("Authorization: " + Redactor.MASK, Redactor.redact("Authorization: sid=abc; x"));
        assertEquals("Authorization: Token " + Redactor.MASK, Redactor.redact("Authorization: Token abc"));
        assertEquals("Authorization: Bearer " + Redactor.MASK, Redactor.redact("Authorization: Bearer \"abc\""));
        assertEquals("Authorization: SCRAM-SHA-256 " + Redactor.MASK, Redactor.redact("Authorization: SCRAM-SHA-256 c=biws"));
        // A first word that is not an authentication scheme may be the credential itself: masked too.
        assertEquals("Proxy-Authorization: " + Redactor.MASK, Redactor.redact("Proxy-Authorization: k3yMat3rial0001 note"));
        assertEquals("{\"authorization\":\"" + Redactor.MASK + "\"}", Redactor.redact("{\"authorization\":\"k3yMat3rial0002 note\"}"));
        for (String masked : List.of("Authorization: Bearer [REDACTED]", "Cookie: [REDACTED]", "Authorization: [REDACTED]")) {
            assertEquals(masked, Redactor.redact(masked));
        }
    }

    @Test
    void leavesHeaderNamesInProseAlone() {
        for (String text : List.of("see the Cookie: header docs", "Cookie:", "Cookie: \nnext", "the X-Api-Key: header",
                "Accept: application/fhir+json", "Cookies: none", "Authorization: Bearer access token required",
                "Proxy-Authorization: Basic authentication is required")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void masksSensitiveHeaderKeysInJson() {
        assertEquals("{\"headers\":{\"X-Api-Key\":\"" + Redactor.MASK + "\"}}",
                Redactor.redact("{\"headers\":{\"X-Api-Key\":\"k\"}}"));
        assertEquals("{\"headers\":{\"X-Api-Key\":\"" + Redactor.MASK + "\",\"Cookie\":\"" + Redactor.MASK
                        + "\",\"Accept\":\"x\"}}",
                Redactor.redact("{\"headers\":{\"X-Api-Key\":\"k\",\"Cookie\":\"sid=1\",\"Accept\":\"x\"}}"));
        assertEquals("{\"headers\":{\"authorization\":\"Bearer " + Redactor.MASK + "\",\"cookie\":\"" + Redactor.MASK + "\"}}",
                Redactor.redact("{\"headers\":{\"authorization\":\"Bearer abc\",\"cookie\":[\"a=1\",\"b=2\"]}}"));
    }

    @Test
    void everySensitiveHeaderIsMaskedAsALineAndAJsonField() {
        for (String header : Redactor.SENSITIVE_HEADERS) {
            for (String name : List.of(header, header.toUpperCase(Locale.ROOT), titleCase(header))) {
                assertTrue(Redactor.isSensitiveHeader(name), name);
                assertEquals("a\n" + name + ": " + Redactor.MASK + "\nb", Redactor.redact("a\n" + name + ": sid=abc; x=1\nb"), name);
                assertEquals("{\"m\":\"a\\n" + name + ": " + Redactor.MASK + "\\nb\"}",
                        Redactor.redact("{\"m\":\"a\\n" + name + ": sid=abc; x=1\\nb\"}"), name);
                for (String value : List.of("\"sid=abc\"", "42", "true", "{\"v\":\"sid\"}", "[\"sid\"]")) {
                    assertEquals("{\"" + name + "\":\"" + Redactor.MASK + "\",\"k\":1}",
                            Redactor.redact("{\"" + name + "\":" + value + ",\"k\":1}"), name + " " + value);
                    String embedded = value.replace("\"", "\\\"");
                    assertEquals("{\"body\":\"{\\\"" + name + "\\\":\\\"" + Redactor.MASK + "\\\",\\\"k\\\":1}\"}",
                            Redactor.redact("{\"body\":\"{\\\"" + name + "\\\":" + embedded + ",\\\"k\\\":1}\"}"),
                            name + " " + embedded);
                }
            }
        }
    }

    private static String titleCase(String header) {
        StringBuilder out = new StringBuilder(header.length());
        for (int i = 0; i < header.length(); i++) {
            char c = header.charAt(i);
            out.append(i == 0 || header.charAt(i - 1) == '-' ? Character.toUpperCase(c) : c);
        }
        return out.toString();
    }

    @Test
    void masksTokenValuesInJsonBody() {
        String token = randomToken();
        String out = Redactor.redact("{\"access_token\": \"" + token + "\", \"token_type\": \"Bearer\", \"expires_in\": 300}");

        assertEquals("{\"access_token\": \"" + Redactor.MASK + "\", \"token_type\": \"Bearer\", \"expires_in\": 300}", out);
    }

    @Test
    void masksVeryLongJsonSecretWithoutOverflowing() {
        // 120 KB including escaped quotes, which used to overflow the regex engine's stack.
        String secret = "s3cr3t\\\"".repeat(15_000);
        String out = Redactor.redact("{\"client_secret\": \"" + secret + "\", \"client_id\": \"synthetic-client\"}");

        assertEquals("{\"client_secret\": \"" + Redactor.MASK + "\", \"client_id\": \"synthetic-client\"}", out);
    }

    @Test
    void leavesOrdinaryTextAlone() {
        String text = "{\"error\":\"invalid_client\",\"error_description\":\"Missing bearer token\"}";
        assertEquals(text, Redactor.redact(text));
        assertNull(Redactor.redact(null));
        assertEquals(Map.of(), Redactor.redactHeaders(null));
    }

    @Test
    void masksAllLetterBasicCredentialThatDecodesToUserPass() {
        // base64 of the synthetic pair "user:pass": all letters, so it used to pass as prose.
        assertEquals("{\"headers\":{\"authorization\":\"Basic [REDACTED]\"}}",
                Redactor.redact("{\"headers\":{\"authorization\":\"Basic dXNlcjpwYXNz\"}}"));
        assertEquals("Authorization: Basic [REDACTED]\\nnext line", Redactor.redact("Authorization: Basic YWJjOmRl\\nnext line"));
    }

    @Test
    void masksCredentialThroughToTheNextSeparator() {
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer abc123:SECRETPART"));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer abc:def/ghi"));
        assertEquals("Bearer [REDACTED], next", Redactor.redact("Bearer abc:def, next"));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer abcdefghijklmno:"));
    }

    @Test
    void keepsShortWordsAfterTheSchemeOnlyWhenTheyEndThere() {
        for (String prose : List.of("Missing bearer token", "Missing bearer token.", "Basic authentication is required",
                "(no bearer token)", "Bearer abcdefghijklmno is missing", "\"Missing bearer token\"",
                "Bearer realm=\"synthetic-payer\"", "Basic realm=\"synthetic-payer\", charset=\"UTF-8\"")) {
            assertEquals(prose, Redactor.redact(prose));
        }
    }

    @Test
    void masksNonStringJsonSecretValues() {
        assertEquals("{\"access_token\":\"[REDACTED]\"}", Redactor.redact("{\"access_token\":123456789}"));
        assertEquals("{\"client_secret\": \"[REDACTED]\", \"expires_in\": 300}",
                Redactor.redact("{\"client_secret\": 12345, \"expires_in\": 300}"));
        assertEquals("{\"password\":\"[REDACTED]\",\"active\":true}", Redactor.redact("{\"password\":false,\"active\":true}"));
        assertEquals("{\"api_key\":null}", Redactor.redact("{\"api_key\":null}"));
    }

    @Test
    void masksPrivateKeyAndEveryReportSecretField() {
        assertEquals("{\"private_key\":\"[REDACTED]\"}", Redactor.redact("{\"private_key\":\"MIIEvSyntheticOnly123\"}"));
        for (String key : List.of("privateKey", "secret", "clientSecret", "client-secret", "client_assertion",
                "assertion", "ACCESS_TOKEN")) {
            assertEquals("{\"" + key + "\":\"[REDACTED]\"}", Redactor.redact("{\"" + key + "\":\"synthetic-value\"}"), key);
            assertTrue(Redactor.isSecretField(key), key);
        }
        assertFalse(Redactor.isSecretField("token_type"));
        assertEquals("private_key=[REDACTED]", Redactor.redact("private_key=synthetic"));
    }

    @Test
    void masksSecretsInJsonEmbeddedInAJsonString() {
        String in = "{\"debug\":\"{\\\"access_token\\\":123456789}\\n{\\\"private_key\\\":\\\"MIIEvSynthetic\\\"}\"}";
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"}\\n{\\\"private_key\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact(in));
    }

    @Test
    void masksSecretStringCutOffByTheEndOfTheText() {
        assertEquals("{\"cards\":[],\"access_token\":\"[REDACTED]\"",
                Redactor.redact("{\"cards\":[],\"access_token\":\"synthetic-cut-tok"));
    }

    @Test
    void masksSecretStringCutInsideAnEscape() {
        // A lone backslash at the end, or before the line break that starts a note on a cut body.
        assertEquals("{\"access_token\":\"[REDACTED]\"", Redactor.redact("{\"access_token\":\"FAKE-CREDENTIAL-1\\"));
        assertEquals("{\"access_token\":\"[REDACTED]\"\n[note]",
                Redactor.redact("{\"access_token\":\"FAKE-CREDENTIAL-1\\\n[note]"));
        // Embedded JSON: one or three backslashes left, or an inner escape cut before the JSON was quoted.
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"",
                Redactor.redact("{\"debug\":\"{\\\"access_token\\\":\\\"FAKE-CREDENTIAL-1\\"));
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"\n[note]",
                Redactor.redact("{\"debug\":\"{\\\"access_token\\\":\\\"FAKE-CREDENTIAL-1\\\\\\\n[note]"));
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"\"}",
                Redactor.redact("{\"debug\":\"{\\\"access_token\\\":\\\"FAKE-CREDENTIAL-1\\\\\"}"));
    }

    /**
     * A body cut at every position of a secret value full of escapes ({@code \\}, {@code \"},
     * {@code \n} and a control character's six-character escape), raw or embedded in a JSON string,
     * cut before or after it was quoted, with or without a note after the cut, keeps nothing of it.
     */
    @Test
    void masksSecretCutAtEveryPositionOfAnEscapedValue() {
        String secret = "FAKE\\CRED\"ENTIAL\nSYNTH\u0001ETIC\\";
        String field = "{\"error\":\"invalid_client\",\"access_token\":";
        String value = JSON.writeValueAsString(secret);
        String masked = field + "\"" + Redactor.MASK + "\"";
        for (int cut = 1; cut < value.length(); cut++) {
            String raw = field + value.substring(0, cut);
            assertCutMasked(raw, masked);
            assertCutMasked(embedded(raw) + "\"}", embedded(masked) + "\"}");
        }
        String quoted = embedded(field + value);
        for (int cut = embedded(field).length() + 2; cut < quoted.length(); cut++) {
            assertCutMasked(quoted.substring(0, cut), embedded(masked));
        }
    }

    /** {@code text} quoted as the value of a {@code debug} field, without the closing {@code "}}. */
    private static String embedded(String text) {
        String quoted = JSON.writeValueAsString(text);
        return "{\"debug\":" + quoted.substring(0, quoted.length() - 1);
    }

    private static void assertCutMasked(String cut, String masked) {
        for (String note : List.of("", "\n[not parsed: more than 100000 JSON values; kept the first 8192 characters]")) {
            String out = Redactor.redact(cut + note);
            // A note after a cut that is not inside an escape is masked along with the value.
            assertTrue(out.equals(masked + note) || out.equals(masked), () -> cut + note + "\n became " + out);
        }
    }

    @Test
    void masksBasicUserPassAtTheEndOfASentence() {
        assertEquals("Received Authorization: Basic [REDACTED]",
                Redactor.redact("Received Authorization: Basic dXNlcjpwYXNz."));
        assertEquals("Basic [REDACTED]", Redactor.redact("Basic dXNlcjpwYXNz..."));
        assertEquals("Basic authentication is required.", Redactor.redact("Basic authentication is required."));
    }

    @Test
    void masksFormSecretsThroughABackslash() {
        assertEquals("client_secret=[REDACTED]&x=1", Redactor.redact("client_secret=abc\\xyzTAIL&x=1"));
        // A form body quoted in JSON: \\ is an escaped backslash in the value, \" and \n end it.
        assertEquals("{\"body\":\"password=[REDACTED]\\nnext\"}", Redactor.redact("{\"body\":\"password=pa\\\\ssTAIL\\nnext\"}"));
        assertEquals("{\"body\":\"api_key=[REDACTED]\"}", Redactor.redact("{\"body\":\"api_key=k\\\\\\\\TAIL\"}"));
    }

    @Test
    void masksEmbeddedJsonSecretCutOffOrHoldingAnEscapedQuote() {
        assertEquals("{\"result\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"",
                Redactor.redact("{\"result\":\"{\\\"access_token\\\":\\\"SECRETPARTIAL"));
        assertEquals("{\"result\":\"{\\\"password\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"result\":\"{\\\"password\\\":\\\"pa\\\\\\\"ssTAIL\\\"}\"}"));
        assertEquals("{\"result\":\"{\\\"password\\\":\\\"[REDACTED]\\\",\\\"user\\\":\\\"u\\\"}\"}",
                Redactor.redact("{\"result\":\"{\\\"password\\\":\\\"pa\\\\\\\\\\\",\\\"user\\\":\\\"u\\\"}\"}"));
    }

    @Test
    void masksSecretFieldsHoldingAnObjectOrArray() {
        assertEquals("{\"private_key\":\"[REDACTED]\",\"kid\":\"k1\"}",
                Redactor.redact("{\"private_key\":{\"kty\":\"RSA\",\"d\":\"PRIVATED\",\"n\":\"a}]\\\"b\"},\"kid\":\"k1\"}"));
        assertEquals("{\"access_token\": \"[REDACTED]\"}", Redactor.redact("{\"access_token\": [\"ARRSECRET\", [1]]}"));
        assertEquals("{\"secret\":\"[REDACTED]\"", Redactor.redact("{\"secret\":{\"d\":\"CUTOFF"));
        assertEquals("{\"result\":\"{\\\"private_key\\\":\\\"[REDACTED]\\\",\\\"kid\\\":\\\"k1\\\"}\"}",
                Redactor.redact("{\"result\":\"{\\\"private_key\\\":{\\\"d\\\":\\\"PRIV}D\\\"},\\\"kid\\\":\\\"k1\\\"}\"}"));
        assertEquals("{\"result\":\"{\\\"private_key\\\":\\\"[REDACTED]\\\"\"}",
                Redactor.redact("{\"result\":\"{\\\"private_key\\\":{\\\"d\\\":\\\"PRIVD\"}"));
        String ordinary = "{\"cards\":[{\"summary\":\"s\"}],\"token\":{\"type\":\"Bearer\"}}";
        assertEquals(ordinary, Redactor.redact(ordinary));
    }

    @Test
    void leavesOrdinaryJsonFieldsAlone() {
        String text = "{\"token_type\":\"Bearer\",\"expires_in\":300,\"active\":true,\"note\":\"say \\\"hi\\\"\"}";
        assertEquals(text, Redactor.redact(text));
    }

    @Test
    void masksAJsonEscapedSlashTokenWhole() {
        // A serializer that escapes "/" leaves the token's first part an all-letter word (#211).
        assertEquals("{\"error_description\":\"rejected Bearer [REDACTED]\"}",
                Redactor.redact("{\"error_description\":\"rejected Bearer EchoTok\\/abc+x\\/y==\"}"));
        assertEquals("{\"debug\":\"Bearer [REDACTED]\"}", Redactor.redact("{\"debug\":\"Bearer abc:SE\\/CRET\"}"));
        assertEquals("rejected Bearer [REDACTED]", Redactor.redact("rejected Bearer EchoTok\\\\/abc"));
    }

    @Test
    void masksAUnicodeEscapedTokenWhole() {
        // .NET's System.Text.Json writes "+" as +; some serializers write "/" as / or "=" as =.
        assertEquals("{\"error_description\":\"rejected Bearer [REDACTED]\"}", Redactor.redact(
                "{\"error_description\":\"rejected Bearer SynthTokAAAA/BBBB\\u002BCCCCDDDDEEEE\\u002BFFFF==\"}"));
        assertEquals("{\"error_description\":\"rejected Bearer [REDACTED]\"}",
                Redactor.redact("{\"error_description\":\"rejected Bearer SynthTok\\u002FAAAABBBB\"}"));
        // Escaped and unescaped mixed, lower-case hex, escaped padding, and escaped again in embedded JSON.
        assertEquals("{\"debug\":\"Bearer [REDACTED]\"}", Redactor.redact(
                "{\"debug\":\"Bearer Synth\\u002bTok/AAAA\\/BBBB+CC\\u002fDD\\u003D\\u003d\"}"));
        assertEquals("{\"debug\":\"{\\\"e\\\":\\\"Bearer [REDACTED]\\\"}\"}",
                Redactor.redact("{\"debug\":\"{\\\"e\\\":\\\"Bearer SynthTok\\\\u002BAAAA\\\\u002FBBBB\\\"}\"}"));
        assertEquals("Basic [REDACTED]", Redactor.redact("Basic dXNlcjpw\\u002BYXNz"));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer abc:SE\\u002BCRET"));
        // An escaped quote, space or backslash still ends the token.
        assertEquals("Bearer [REDACTED]\\u0022 and Bearer [REDACTED]\\u0020more",
                Redactor.redact("Bearer abc123\\u0022 and Bearer abc123\\u0020more"));
    }

    @Test
    void masksThePrivateMembersOfAJwk() {
        assertEquals("{\"kty\":\"RSA\",\"d\":\"[REDACTED]\",\"p\":\"[REDACTED]\"}",
                Redactor.redact("{\"kty\":\"RSA\",\"d\":\"PRIVATEDVALUE\",\"p\":\"PRIMEP\"}"));
        assertEquals("{\"kty\":\"oct\",\"k\":\"[REDACTED]\"}", Redactor.redact("{\"kty\":\"oct\",\"k\":\"SYMKEY123\"}"));
        // Every private member, including the other primes (RFC 7518 6.3.2.7); the public ones stay.
        String pub = "\"kty\":\"RSA\",\"kid\":\"k1\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"MODULUS\",\"e\":\"AQAB\"";
        assertEquals("{" + pub + ",\"d\":\"[REDACTED]\",\"p\":\"[REDACTED]\",\"q\":\"[REDACTED]\",\"dp\":\"[REDACTED]\","
                        + "\"dq\":\"[REDACTED]\",\"qi\":\"[REDACTED]\",\"oth\":\"[REDACTED]\"}",
                Redactor.redact("{" + pub + ",\"d\":\"PRIVD\",\"p\":\"PRIVP\",\"q\":\"PRIVQ\",\"dp\":\"PRIVDP\","
                        + "\"dq\":\"PRIVDQ\",\"qi\":\"PRIVQI\",\"oth\":[{\"r\":\"PRIVR\",\"d\":\"PRIVOD\",\"t\":\"PRIVT\"}]}"));
        // kty after the private member, and a value that is not a string.
        assertEquals("{\"crv\":\"P-256\",\"x\":\"X1\",\"y\":\"Y1\",\"d\":\"[REDACTED]\",\"kty\":\"EC\"}",
                Redactor.redact("{\"crv\":\"P-256\",\"x\":\"X1\",\"y\":\"Y1\",\"d\":\"PRIVECD\",\"kty\":\"EC\"}"));
        assertEquals("{\"kty\":\"oct\",\"k\":\"[REDACTED]\"}", Redactor.redact("{\"kty\":\"oct\",\"k\":12345678}"));
        // Each key of a JWKS, also pretty-printed, and a key with braces and quotes in a string.
        assertEquals("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"X1\",\"d\":\"[REDACTED]\"},\n"
                        + "  {\"kid\":\"a}{\\\"b\",\n   \"k\" : \"[REDACTED]\",\n   \"kty\" : \"oct\"}]}",
                Redactor.redact("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"X1\",\"d\":\"PRIVOKPD\"},\n"
                        + "  {\"kid\":\"a}{\\\"b\",\n   \"k\" : \"PRIVK\",\n   \"kty\" : \"oct\"}]}"));
        // In JSON embedded in a JSON string, and in a body cut off at the size limit.
        assertEquals("{\"body\":\"{\\\"kty\\\":\\\"RSA\\\",\\\"n\\\":\\\"N1\\\",\\\"d\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"kty\\\":\\\"RSA\\\",\\\"n\\\":\\\"N1\\\",\\\"d\\\":\\\"PRIVEMBD\\\"}\"}"));
        assertEquals("{\"body\":\"{\\\"keys\\\":[{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"[REDACTED]\\\"}]}\"}",
                Redactor.redact("{\"body\":\"{\\\"keys\\\":[{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"PRIVEMBK\\\"}]}\"}"));
        assertEquals("{\"kty\":\"RSA\",\"d\":\"[REDACTED]\"", Redactor.redact("{\"kty\":\"RSA\",\"d\":\"PRIVCUTOFF"));
        // Pretty-printed JSON embedded in a JSON string: its line breaks are escaped.
        assertEquals("{\"body\":\"{\\n \\\"kty\\\" :\\n \\\"RSA\\\",\\n \\\"d\\\":\\n\\t\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\n \\\"kty\\\" :\\n \\\"RSA\\\",\\n \\\"d\\\":\\n\\t\\\"PRIVEMBNL\\\"}\"}"));
        assertEquals("{\"body\":\"{\\\"password\\\":\\n\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"password\\\":\\n\\\"PRIVPW\\\"}\"}"));
        // A JWK inside a JWK: each one's own members, the inner one read before the outer.
        assertEquals("{\"a\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"},\"kty\":\"oct\",\"k\":\"[REDACTED]\"}",
                Redactor.redact("{\"a\":{\"kty\":\"oct\",\"k\":\"PRIVK1\"},\"kty\":\"oct\",\"k\":\"PRIVK2\"}"));
        // kty after nested objects and arrays; a JWK inside a masked member goes with it.
        assertEquals("{\"x5c\":[\"c1\",\"c2\"],\"meta\":{\"x\":[1,{\"y\":2}]},\"d\":\"[REDACTED]\",\"kty\":\"RSA\"}",
                Redactor.redact("{\"x5c\":[\"c1\",\"c2\"],\"meta\":{\"x\":[1,{\"y\":2}]},\"d\":\"PRIVD\",\"kty\":\"RSA\"}"));
        assertEquals("{\"kty\":\"RSA\",\"oth\":\"[REDACTED]\"}",
                Redactor.redact("{\"kty\":\"RSA\",\"oth\":[{\"kty\":\"oct\",\"k\":\"PRIVK\"}]}"));
        // Embedded JSON cut off before its object closes.
        assertEquals("{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"[REDACTED]\\\"\",\"n\":1}",
                Redactor.redact("{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"PRIVK\\\"\",\"n\":1}"));
    }

    @Test
    void leavesJwkMemberNamesOutsideAJwkAlone() {
        for (String text : List.of(
                "{\"d\":\"x\"}",
                "{\"d\":\"2026-10-29\",\"p\":0.05,\"q\":\"query\",\"k\":[1,2]}",
                // A public key keeps every member.
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"X1\",\"y\":\"Y1\",\"kid\":\"k1\",\"use\":\"sig\",\"alg\":\"ES256\"}",
                // Only the JWK's own members: not a sibling of a nested JWK, nor a member of an object inside one.
                "{\"jwk\":{\"kty\":\"RSA\",\"n\":\"N1\"},\"d\":\"x\"}",
                "{\"kty\":\"RSA\",\"meta\":{\"d\":\"x\"},\"n\":\"N1\"}",
                // kty quoted in a string is not a member.
                "{\"note\":\"the \\\"kty\\\": member\",\"d\":\"x\"}",
                "{\"note\":\"\\\"kty\\\":\",\"d\":\"x\"}",
                "{\"note\":\"\\\"kty\\\": a, \\\"kty\\\": b\",\"d\":\"x\"}",
                // A name that only ends in kty ("\"kty"), and kty that is not the member of an object.
                "[{\"\\\"kty\":0,\"d\":\"x\"}]",
                "{\"b\":\"{\\\"\\\\\\\"kty\\\":0,\\\"d\\\":\\\"x\\\"}\"}",
                "\"kty\": \"RSA\", \"d\": \"x\"",
                "[\"kty\": \"RSA\", \"d\": \"x\"]",
                "[\"kty\": 1, \"kty\": 2, \"d\": \"x\"]")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void masksJwkMembersWhoseNamesAreSpelledWithEscapes() {
        // JSON may spell any character of a member name as a \\u escape, in either hex case: "kt\\u0079" is
        // kty and "\\u0064" is d.
        assertEquals("{\"kt\\u0079\":\"RSA\",\"n\":\"N1\",\"d\":\"[REDACTED]\"}",
                Redactor.redact("{\"kt\\u0079\":\"RSA\",\"n\":\"N1\",\"d\":\"PRIVD\"}"));
        assertEquals("{\"kty\":\"RSA\",\"\\u0064\":\"[REDACTED]\",\"\\u0064p\":\"[REDACTED]\",\"n\":\"N1\"}",
                Redactor.redact("{\"kty\":\"RSA\",\"\\u0064\":\"PRIVD\",\"\\u0064p\":\"PRIVDP\",\"n\":\"N1\"}"));
        assertEquals("{\"\\u006B\\u0074\\u0079\":\"oct\",\"\\u006b\":\"[REDACTED]\"}",
                Redactor.redact("{\"\\u006B\\u0074\\u0079\":\"oct\",\"\\u006b\":\"PRIVK\"}"));
        assertEquals("{\"kty\":\"RSA\",\"\\u006fth\":\"[REDACTED]\"}",
                Redactor.redact("{\"kty\":\"RSA\",\"\\u006fth\":[{\"r\":\"PRIVR\"}]}"));
        assertEquals("{\"keys\":[{\"k\\u0074y\":\"oct\",\"\\u006B\":\"[REDACTED]\"}]}",
                Redactor.redact("{\"keys\":[{\"k\\u0074y\":\"oct\",\"\\u006B\":\"PRIVK\"}]}"));
        // In JSON embedded in a JSON string the inner escape's backslash is escaped (\\\\u0064), or the
        // outer string spells the letter itself (\\u0064).
        assertEquals("{\"body\":\"{\\\"kt\\\\u0079\\\":\\\"RSA\\\",\\\"\\\\u0064\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"kt\\\\u0079\\\":\\\"RSA\\\",\\\"\\\\u0064\\\":\\\"PRIVD\\\"}\"}"));
        assertEquals("{\"body\":\"{\\\"kt\\u0079\\\":\\\"RSA\\\",\\\"\\u0064\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"kt\\u0079\\\":\\\"RSA\\\",\\\"\\u0064\\\":\\\"PRIVD\\\"}\"}"));
        // Once the budget is spent, every private member name is found, also spelled with escapes.
        assertEquals("{\"\\u0064\":\"[REDACTED]\",\"kty\":\"RSA\"}",
                Redactor.maskJwks("{\"\\u0064\":\"PRIVD\",\"kty\":\"RSA\"}", false, 0));
        assertEquals("{\\\"\\\\u0064\\\":\\\"[REDACTED]\\\",\\\"kty\\\":\\\"RSA\\\"}",
                Redactor.maskJwks("{\\\"\\\\u0064\\\":\\\"PRIVD\\\",\\\"kty\\\":\\\"RSA\\\"}", true, 0));
        // Without kty the names stay, and an escaped backslash is not an escape: "\\\\u0064" is not d.
        for (String text : List.of("{\"\\u0064\":\"x\"}", "{\"kty\":\"RSA\",\"\\\\u0064\":\"x\"}",
                "{\"\\\\u006bty\":\"RSA\",\"d\":\"x\"}")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void masksSecretFieldsWhoseNamesAreSpelledWithEscapes() {
        assertEquals("{\"client_s\\u0065cret\":\"[REDACTED]\"}", Redactor.redact("{\"client_s\\u0065cret\":\"PRIVS\"}"));
        assertEquals("{\"body\":\"{\\\"client_s\\\\u0065cret\\\":\\\"[REDACTED]\\\"}\"}",
                Redactor.redact("{\"body\":\"{\\\"client_s\\\\u0065cret\\\":\\\"PRIVS\\\"}\"}"));
        assertEquals("{\"private_k\\u0065y\":\"[REDACTED]\"}", Redactor.redact("{\"private_k\\u0065y\":{\"kty\":\"oct\"}}"));
        // An Authorization-style name keeps the scheme, also spelled with an escape.
        assertEquals("{\"\\u0041uthorization\":\"SCRAM-SHA-256 [REDACTED]\"}",
                Redactor.redact("{\"\\u0041uthorization\":\"SCRAM-SHA-256 PRIVSCRAM\"}"));
    }

    @Test
    void findsJwksInLinearTime() {
        // About 1 MB each: linear time takes well under a second, quadratic time minutes.
        int n = 80_000;
        List<String> texts = List.of(
                "[" + "{\"\\\"kty\":0},".repeat(n) + "{}]",
                "]\"kty\":".repeat(n),
                "{\"b\":\"" + "]\\\"kty\\\":".repeat(n) + "\"}",
                "{\"kty\":1,".repeat(n),
                "{\"x\":\"" + "\\\"kty\\\": ".repeat(n) + "\"}",
                "{\"a\":".repeat(n / 2) + "{\"kty\":1}" + ",\"kty\":1,\"d\":\"y\"}".repeat(n / 2),
                "{" + "\"kty\":1,".repeat(n) + "\"d\":\"y\"}",
                "[".repeat(n / 2) + "\"kty\":1],".repeat(n / 2),
                "{" + "\"x\":\"kty\":1,".repeat(n) + "\"d\":\"y\"}",
                "\"kty\":\"".repeat(n),
                "\"kty\":\"".repeat(n / 2) + "\"x\":\"\"d\":\"y\",".repeat(n / 2),
                "{\"b\":\"" + "[".repeat(n / 2) + "\\\"kty\\\":1],".repeat(n / 2) + "\"}",
                // JWK shapes nested two and three escape levels deep, and one long run of backslashes before kty,
                // which every level reads again: there are at most log2 of its length levels.
                nested(nested("{\"kty\":1,".repeat(n / 2))),
                nested(nested(nested("{" + "\"kty\":1,".repeat(n / 4) + "\"d\":\"y\"}"))),
                "{\"b\":\"" + "\\".repeat(1 << 20) + "\\\"kty\\\":1\"}");
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(Redactor::redact));
    }

    @Test
    void masksJwksEmbeddedAtAnyDepth() {
        // The security review's shape: a JWK in a JSON string in a JSON string.
        String review = nested(nested("{\"kty\":\"oct\",\"k\":\"FAKE_PRIVATE_KEY_293\"}"));
        assertFalse(Redactor.redact(review).contains("FAKE_PRIVATE_KEY_293"), Redactor.redact(review));
        // Masking a JWK nested k levels deep gives the nested masked JWK: the mask comes with the quotes of its level.
        for (String jwk : List.of(
                "{\"kty\":\"RSA\",\"n\":\"N1\",\"e\":\"AQAB\",\"d\":\"PRIVD\",\"p\":\"PRIVP\",\"q\":\"PRIVQ\","
                        + "\"dp\":\"PRIVDP\",\"dq\":\"PRIVDQ\",\"qi\":\"PRIVQI\",\"oth\":[{\"r\":\"PRIVR\",\"d\":\"PRIVOD\"}]}",
                "{\"keys\":[{\"kty\":\"oct\",\"k\":\"PRIVK\"},{\"crv\":\"P-256\",\"x\":\"X1\",\"d\":\"PRIVEC\",\"kty\":\"EC\"}]}",
                "{\n  \"kty\" : \"oct\",\n  \"k\" :\n\t\"PRIVK\"\n}",
                "{\"kt\\u0079\":\"RSA\",\"\\u0064\":\"PRIVD\",\"\\u006B\":{\"x\":\"PRIVKOBJ\"}}",
                "{\"a\":{\"kty\":\"oct\",\"k\":\"PRIVK1\"},\"kty\":\"oct\",\"k\":\"PRIVK2\"}",
                "{\"kty\":\"RSA\",\"meta\":{\"d\":\"keep\"},\"n\":\"N1\",\"d\":\"PRIVCUTOFF",
                "{\"d\":\"keep\",\"note\":\"the \\\"kty\\\": member\"}",
                // A JWK in a JSON string that is itself a private member: masked with it, one level up.
                "{\"kty\":\"oct\",\"k\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"PRIVINNER\\\"}\",\"kid\":\"k1\"}")) {
            String masked = Redactor.redact(jwk);
            String in = jwk;
            String out = masked;
            for (int depth = 1; depth <= 4; depth++) {
                in = nested(in);
                out = nested(out);
                assertEquals(out, Redactor.redact(in), "depth " + depth + ": " + jwk);
            }
        }
        // Once a level's budget is spent, every private member name at that level is masked.
        String tangled = nested(nested("{\"jwk\":{\"kty\":\"oct\",\"k\":\"PRIVK\"},\"d\":\"x\"}"));
        assertEquals(nested(nested("{\"jwk\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"},\"d\":\"[REDACTED]\"}")),
                Redactor.maskNestedJwks(tangled, 0));
        assertEquals(nested(nested("{\"jwk\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"},\"d\":\"x\"}")),
                Redactor.maskNestedJwks(tangled, 1000));
        // Text with no JSON nested two levels deep is returned as it is.
        String plain = "{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"PRIVK\\\"}\"}";
        assertTrue(plain == Redactor.maskNestedJwks(plain, 0));
    }

    @Test
    void masksJwksWhoseEmbeddedJsonIsSpelledWithUnicodeEscapes() {
        // The review's shape: a serializer that escapes a quote in a string as \\u0022 (as .NET's default encoder
        // does), also mixed with \". The mask is quoted as its member's name is.
        assertEquals("{\"body\":\"{\\u0022kty\\u0022:\\u0022oct\\u0022,\\u0022k\\u0022:\\u0022[REDACTED]\\u0022}\"}",
                Redactor.redact("{\"body\":\"{\\u0022kty\\u0022:\\u0022oct\\u0022,\\u0022k\\u0022:\\u0022PRIVK\\u0022}\"}"));
        assertEquals("{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\u0022k\\u0022:\\u0022[REDACTED]\\u0022}\"}",
                Redactor.redact("{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\u0022k\\u0022:\\u0022PRIVK\\u0022}\"}"));
        // Any character of the embedded JSON may be a unicode escape: the space after a colon, the colon itself
        // (the review's shapes), a brace, a comma, a line break.
        for (String in : List.of(
                "{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\u0020\\\"PRIVK\\\"}\"}",
                "{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\"\\u003A\\\"PRIVK\\\"}\"}",
                "{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\"\\u003a\\u0020\\\"PRIVK\\\"}\"}")) {
            String out = Redactor.redact(in);
            assertFalse(out.contains("PRIVK"), out);
            assertEquals(Redactor.redact(unnested(in)), unnested(out), in);
        }
        String spelled = "{\"body\":\"\\u007B\\\"kty\\\":\\\"oct\\\"\\u002C\\u000A\\\"k\\\":\\\"PRIVK\\\"\\u007D\"}";
        assertFalse(Redactor.redact(spelled).contains("PRIVK"), Redactor.redact(spelled));
        // Every mix of escapes one to three levels deep reads back as the masked JWK, whichever way each level
        // escapes its quotes (\" or \\u0022) and backslashes (\\\\ or \\u005c), or spells every character as
        // a unicode escape.
        List<UnaryOperator<String>> levels = List.of(RedactorTest::nested, RedactorTest::nestedEscapingQuotes,
                RedactorTest::nestedEscapingBackslashes, RedactorTest::nestedEscapingEverything);
        for (String jwk : List.of(
                "{\"kty\":\"RSA\",\"n\":\"N1\",\"d\":\"PRIVD\",\"oth\":[{\"r\":\"PRIVR\"}],\"qi\":\"PRIVQI\"}",
                "{\"keys\":[{\"k\":\"PRIVK\",\"kty\":\"oct\"}]}",
                "{\"kty\":\"oct\",\"note\":\"a \\\"quoted\\\" \\\\ word\",\"k\":\"PRIVK\"}")) {
            String masked = Redactor.redact(jwk);
            for (UnaryOperator<String> a : levels) {
                for (UnaryOperator<String> b : levels) {
                    for (String in : List.of(a.apply(jwk), b.apply(a.apply(jwk)), a.apply(b.apply(a.apply(jwk))))) {
                        String out = Redactor.redact(in);
                        assertFalse(out.contains("PRIV"), out);
                        assertEquals(masked, unnested(out), in);
                    }
                }
            }
        }
        // Without kty the names stay.
        String plain = "{\"body\":\"{\\u0022d\\u0022:\\u0022x\\u0022,\\u0022k\\u0022:[1,2]}\"}";
        assertEquals(plain, Redactor.redact(plain));
    }

    @Test
    void masksEscapeChainsWithoutBlowingUp() {
        // The review's shape: each quote of a JWK in a JSON string spelled \\u005c, then u005c again and again,
        // then u0022, so every level decoded shows one more escape. Shallow or deep, the private value goes,
        // the output is no longer than the input, and the text stays valid JSON.
        for (int links : List.of(1, 8, 40, 400)) {
            String quote = "\\u005c" + "u005c".repeat(links) + "u0022";
            String jwk = "{" + quote + "kty" + quote + ":" + quote + "oct" + quote + "," + quote + "k" + quote + ":" + quote
                    + "PRIVATECHAINVALUE" + quote + "}";
            String in = "{\"body\":\"" + jwk + "\"}";
            String out = assertTimeout(Duration.ofSeconds(5), () -> Redactor.redact(in));
            assertFalse(out.contains("PRIVATECHAINVALUE"), () -> links + ": " + out);
            assertTrue(out.length() <= in.length(), () -> links + ": " + out.length() + " > " + in.length());
            assertTrue(JSON.readTree(out).has("body"), out);
        }
        // About 1 MB of chain: a fixed number of levels is read, so time stays linear.
        String quote = "\\u005c" + "u005c".repeat(40_000) + "u0022";
        String in = "{\"body\":\"{" + quote + "kty" + quote + ":" + quote + "oct" + quote + "," + quote + "k" + quote + ":"
                + quote + "PRIVATECHAINVALUE" + quote + "}\"}";
        String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(in));
        assertFalse(out.contains("PRIVATECHAINVALUE"));
        assertTrue(out.length() <= in.length());
        // Embedded JSON after prose in a string is read as well.
        String prose = "{\"evidence\":\"payer said: {\\u0022kty\\u0022:\\u0022oct\\u0022,\\u0022k\\u0022:\\u0022PRIVK\\u0022}\"}";
        assertFalse(Redactor.redact(prose).contains("PRIVK"), Redactor.redact(prose));
    }

    /** {@link #nested}, with each quote in the string escaped as {@code \\u0022}. */
    private static String nestedEscapingQuotes(String text) {
        return "{\"body\":\"" + text.replace("\\", "\\\\").replace("\"", "\\u0022") + "\"}";
    }

    /** {@link #nested}, with each backslash in the string escaped as {@code \\u005C}. */
    private static String nestedEscapingBackslashes(String text) {
        return "{\"body\":\"" + text.replace("\\", "\\u005C").replace("\"", "\\\"") + "\"}";
    }

    /** {@link #nested}, with every character in the string written as a unicode escape. */
    private static String nestedEscapingEverything(String text) {
        StringBuilder out = new StringBuilder("{\"body\":\"");
        text.chars().forEach(c -> out.append(String.format("\\u%04x", c)));
        return out.append("\"}").toString();
    }

    /** The JSON text innermost in {@code text}: the {@code body} string, read as JSON, until it is not JSON with one. */
    private static String unnested(String text) {
        String json = text;
        while (true) {
            JsonNode body = JSON.readTree(json).get("body");
            if (body == null || !body.isString()) {
                return json;
            }
            json = body.asString();
            if (!json.startsWith("{\"body\"")) {
                return json;
            }
        }
    }

    /** {@code text} as the value of a JSON string member, escaped as a serializer escapes it. */
    private static String nested(String text) {
        return "{\"body\":" + JSON.writeValueAsString(text) + "}";
    }

    @Test
    void masksOnlyJwksInLargeOrdinaryJson() {
        // About 1 MB: within the time budget, so ordinary fields are kept, also in JSON embedded in a string.
        StringBuilder jwks = new StringBuilder("{\"keys\": [\n");
        for (int i = 0; i < 2000; i++) {
            jwks.append("  {\"kid\": \"k").append(i).append("\", \"n\": \"").append("N".repeat(300))
                    .append("\", \"e\": \"AQAB\",\n   \"d\": \"PRIVD").append(i).append("\", \"kty\": \"RSA\"},\n")
                    .append("  {\"d\": \"keep\", \"p\": 0.05, \"items\": [{\"q\": \"keep\"}]},\n");
        }
        String text = jwks.append("  {}\n]}").toString();
        for (String json : List.of(text, "{\"body\":" + JSON.writeValueAsString(text) + "}")) {
            String out = Redactor.redact(json);
            assertFalse(out.contains("PRIVD"));
            assertEquals(4000, out.split("keep", -1).length - 1);
            assertEquals(2000, out.split("0\\.05", -1).length - 1);
        }
    }

    @Test
    void masksJwkPrivateMembersInTextTooTangledToReadInLinearTime() {
        // Past its time budget the search gives up on finding each JWK and masks every private member.
        String out = Redactor.redact("\"kty\":\"".repeat(80_000) + "{\"kty\":\"oct\",\"k\":\"PRIVK\"}");
        assertFalse(out.contains("PRIVK"));
        assertTrue(out.endsWith("\"k\":\"[REDACTED]\"}"), out.substring(out.length() - 40));
        String embedded = Redactor.redact("{\"b\":\"" + "\\\"kty\\\":\\\"".repeat(80_000)
                + "{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"PRIVK\\\"}\"}");
        assertFalse(embedded.contains("PRIVK"));
        assertTrue(embedded.endsWith("\\\"k\\\":\\\"[REDACTED]\\\"}\"}"), embedded.substring(embedded.length() - 40));
    }

    @Test
    void masksEveryPrivateMemberOnceTheBudgetIsSpent() {
        String text = "{\"jwk\":{\"kty\":\"oct\",\"k\":\"PRIVK\"},\"d\":\"x\"}";
        assertEquals("{\"jwk\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"},\"d\":\"x\"}", Redactor.maskJwks(text, false, 100));
        // Spent searching back for the object, or reading it.
        for (int budget : List.of(0, 3)) {
            assertEquals("{\"jwk\":{\"kty\":\"oct\",\"k\":\"[REDACTED]\"},\"d\":\"[REDACTED]\"}",
                    Redactor.maskJwks(text, false, budget));
        }
        // A run of backslashes skipped at once costs what reading it does: three searches back over 1000
        // of them spend 3000, not 1021.
        String run = "{\"d\":\"x\"}" + "\\".repeat(1000) + "\"kty\":\"".repeat(3);
        assertTrue(Redactor.maskJwks(run, false, 1200).startsWith("{\"d\":\"[REDACTED]\"}"));
    }

    @Test
    void masksAPrivateMemberRightAfterAMalformedValueOnceTheBudgetIsSpent() {
        // The empty value's closing quote is also the quote that opens "d": the names are found on their own.
        assertEquals("{\"x\":\"\"d\":\"[REDACTED]\",\"kty\":\"RSA\"}",
                Redactor.maskJwks("{\"x\":\"\"d\":\"PRIVD\",\"kty\":\"RSA\"}", false, 0));
        assertEquals("{\\\"x\\\":\\\"\\\"d\\\":\\\"[REDACTED]\\\",\\\"kty\\\":\\\"RSA\\\"}",
                Redactor.maskJwks("{\\\"x\\\":\\\"\\\"d\\\":\\\"PRIVD\\\",\\\"kty\\\":\\\"RSA\\\"}", true, 0));
        // The review's shape: the repeated kty members spend the budget, and the last one's value ends at "d".
        String out = Redactor.redact("\"kty\":\"".repeat(63) + "{\"d\":\"PRIVD\",\"e\":\"AQAB\",\"kty\":\"RSA\"}");
        assertFalse(out.contains("PRIVD"), out);
    }

    @Test
    void masksJwkPrivateMembersInATree() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", "N1");
        jwk.put("d", "PRIVD");
        jwk.put("oth", List.of(Map.of("r", "PRIVR")));
        assertEquals(Map.of("kty", "RSA", "n", "N1", "d", "[REDACTED]", "oth", "[REDACTED]"), Redactor.redactTree(jwk));
        assertEquals(Map.of("d", "x"), Redactor.redactTree(Map.of("d", "x")));
    }

    @Test
    void masksShortPunctuationCredentials() {
        // The security review's inputs: a credential of token punctuation is still a credential.
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer -._~+/="));
        assertEquals("Token [REDACTED]", Redactor.redact("Token -._~+/="));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer%20-._~+/="));
        assertEquals("Authorization: Bearer [REDACTED]", Redactor.redact("Authorization: Bearer -._~+/="));
        // One to seven characters after every scheme and separator; the property tests read 8-character pieces.
        String punctuation = "-._~+/";
        for (int length = 1; length <= 7; length++) {
            StringBuilder credential = new StringBuilder();
            for (int i = 0; i < length; i++) {
                credential.append(punctuation.charAt(i % punctuation.length()));
            }
            for (String prefix : List.of("Bearer ", "Basic ", "Token ", "DPoP ", "Bearer%20", "Bearer+",
                    "Authorization: Bearer ", "Authorization: Basic ")) {
                String text = prefix + credential;
                String out = Redactor.redact(text);
                assertTrue(out.endsWith(Redactor.MASK), () -> text + " became " + out);
            }
        }
        // The arrow after a token URL in the app's own log lines stays prose; after any other scheme it does not.
        assertEquals("POST https://payer.example/oauth/token -> HTTP 401 in 12 ms",
                Redactor.redact("POST https://payer.example/oauth/token -> HTTP 401 in 12 ms"));
        assertEquals("Bearer [REDACTED] HTTP 401", Redactor.redact("Bearer -> HTTP 401"));
        assertEquals("Authorization: Bearer [REDACTED]", Redactor.redact("Authorization: Bearer ->"));
    }

    @Test
    void masksTokenAndDPoPCredentials() {
        assertEquals("Token [REDACTED]", Redactor.redact("Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"));
        assertEquals("DPoP " + Redactor.MASK, Redactor.redact("DPoP PHNhbWw6QXNz"));
        assertEquals("{\"error_description\":\"rejected token [REDACTED]\"}",
                Redactor.redact("{\"error_description\":\"rejected token gho_SynthTok123:x\"}"));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer --------"));
        // Eight characters count before a prose colon is dropped.
        assertEquals("Token [REDACTED]", Redactor.redact("Token -------:"));
        // A scheme kept as prose does not hide the scheme after it.
        assertEquals("received token DPoP [REDACTED]", Redactor.redact("received token DPoP PHNhbWw6QXNzZXJ0aW9u"));
        assertEquals("the token Bearer [REDACTED] expired", Redactor.redact("the token Bearer abc123def expired"));
        assertEquals("a bearer token\neyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.[REDACTED]",
                Redactor.redact("a bearer token\neyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.SIGNATURE1"));
        assertEquals("Token [REDACTED]", Redactor.redact("Token\t9944b09199c62bcf"));
        assertEquals("sent dpop [REDACTED], twice", Redactor.redact("sent dpop eyJhbGciOiJFUzI1NiJ9.e30.SIG, twice"));
        // Prose, as after Bearer; after Token a word may end with a colon (token endpoint: <url>).
        for (String text : List.of("Token expired.", "DPoP proof required", "the access token was revoked",
                "token endpoint: https://payer.example/token\ntoken response: error=invalid_client",
                "POST https://payer.example/oauth/token -> HTTP 401 in 12 ms",
                // The next line is not the credential of an ordinary word.
                "issue a token\n2 times per hour", "DPoP\r\nproof-v2 required")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void masksAUrlEncodedBearerCredential() {
        assertEquals("Bearer " + Redactor.MASK, Redactor.redact("Bearer%20abc123def"));
        // One encoded space: a + after it is part of the token.
        assertEquals("Bearer " + Redactor.MASK, Redactor.redact("Bearer%20++++++++"));
        assertEquals("Bearer " + Redactor.MASK, Redactor.redact("Bearer+++++++++"));
        // As after a space, the credential runs to the next whitespace, quote, comma, semicolon or backslash.
        assertEquals("cb?auth=Bearer [REDACTED]", Redactor.redact("cb?auth=Bearer+abc123def&x=1"));
        assertEquals("cb?h=Authorization%3A%20Bearer [REDACTED]", Redactor.redact("cb?h=Authorization%3A%20Bearer%20abc123def"));
        assertEquals("q=missing+bearer+token", Redactor.redact("q=missing+bearer+token"));
    }

    @Test
    void masksAnUnterminatedPgpPrivateKeyBlock() {
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + Redactor.MASK,
                Redactor.redact("-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFAKEKEYMATERIAL\n=abcd"));
        String terminated = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFAKE\n-----END PGP PRIVATE KEY BLOCK-----";
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED]\n-----END PGP PRIVATE KEY BLOCK-----",
                Redactor.redact(terminated));
        String publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENBFAKEPUBLIC";
        assertEquals(publicKey, Redactor.redact(publicKey));
    }

    record Echoed(String summary, String clientSecret, Integer apiKey, int password, List<String> notes) {
    }

    @Test
    void redactsEveryStringOfATreeAndMasksSecretFields() {
        String token = randomToken();
        Map<Object, Object> tree = new LinkedHashMap<>();
        tree.put("summary", "Echo: Bearer " + token);
        tree.put("requestHeaders", Map.of("Authorization", List.of("Bearer " + token), "Cookie", List.of("c=" + token)));
        tree.put("tags", new LinkedHashSet<>(List.of("Bearer " + token)));
        tree.put("card", new Echoed("Bearer " + token, token, 918273645, 918273646, List.of("Bearer " + token)));
        tree.put("count", 3);
        tree.put(Severity.FAIL, 1L);
        tree.put("missing", null);

        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);

        assertEquals(List.copyOf(tree.keySet()), List.copyOf(out.keySet()));
        assertEquals("Echo: Bearer [REDACTED]", out.get("summary"));
        assertEquals(Map.of("Authorization", List.of("Bearer [REDACTED]"), "Cookie", List.of("[REDACTED]")),
                out.get("requestHeaders"));
        assertEquals(Set.of("Bearer [REDACTED]"), out.get("tags"));
        // A record keeps its type; a secret-named component that cannot hold the mask is emptied.
        assertEquals(new Echoed("Bearer [REDACTED]", "[REDACTED]", null, 0, List.of("Bearer [REDACTED]")),
                out.get("card"));
        assertEquals(3, out.get("count"));
        assertEquals(1L, out.get(Severity.FAIL));
        assertTrue(out.containsKey("missing"));
        assertNull(out.get("missing"));
        assertNull(Redactor.redactTree(null));
        assertEquals(Map.of("access_token", List.of("[REDACTED]", "[REDACTED]"),
                        "Proxy-Authorization", List.of("[REDACTED]", "Basic [REDACTED]")),
                Redactor.redactTree(Map.of("access_token", List.of("x", "Basic dXNlcjpwYXNz"),
                        "Proxy-Authorization", List.of("x", "Basic dXNlcjpwYXNz"))));
    }

    @Test
    void redactsMapKeysArraysOptionalsAndValuesOfOtherTypesInATree() {
        String token = randomToken();
        String echo = "Bearer " + token;
        Map<Object, Object> tree = new LinkedHashMap<>();
        tree.put("key: " + echo, "v");
        tree.put("array", new String[] {echo});
        tree.put("nested", new Object[] {List.of(echo), 7});
        tree.put("queue", new ArrayDeque<>(List.of(echo)));
        tree.put("optional", Optional.of(echo));
        tree.put("builder", new StringBuilder(echo));
        tree.put("node", JSON.readTree("{\"echo\":\"" + echo + "\"}"));
        tree.put("at", Instant.EPOCH);
        tree.put("took", Duration.ofSeconds(3));
        tree.put("letter", 'x');

        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);

        assertEquals("v", out.get("key: Bearer [REDACTED]"));
        assertEquals(List.of("Bearer [REDACTED]"), out.get("array"));
        assertEquals(List.of(List.of("Bearer [REDACTED]"), 7), out.get("nested"));
        assertEquals(List.of("Bearer [REDACTED]"), out.get("queue"));
        assertEquals(Optional.of("Bearer [REDACTED]"), out.get("optional"));
        assertEquals(Optional.empty(), Redactor.redactTree(Optional.empty()));
        // Any other type becomes its redacted string form.
        assertEquals("Bearer [REDACTED]", out.get("builder"));
        assertEquals("{\"echo\":\"Bearer [REDACTED]\"}", out.get("node"));
        assertEquals(Instant.EPOCH, out.get("at"));
        assertEquals(Duration.ofSeconds(3), out.get("took"));
        assertEquals('x', out.get("letter"));
        assertFalse(String.valueOf(out).contains(token), String.valueOf(out));
    }

    /** #310: a payer's body can be megabytes of this, and no HTTP timeout bounds the matching. */
    @ParameterizedTest
    @ValueSource(strings = {"", ".", ".x", ".x."})
    void aLongRunOfJwtStartsIsRedactedInLinearTime(String tail) {
        String input = "eyJ-".repeat(40_000) + tail;

        String out = assertTimeout(Duration.ofSeconds(1), () -> Redactor.redact(input));

        assertEquals(input, out);
    }

    /** Same shape, but it is a JWT: the first start in the run wins, and what it masks is only the signature. */
    @Test
    void aLongRunOfJwtStartsThatEndsAsAJwtHasItsSignatureMasked() {
        String input = "eyJ-".repeat(40_000) + ".claims.signature";

        String out = assertTimeout(Duration.ofSeconds(1), () -> Redactor.redact(input));

        assertEquals("eyJ-".repeat(40_000) + ".claims." + Redactor.MASK, out);
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String b64url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
