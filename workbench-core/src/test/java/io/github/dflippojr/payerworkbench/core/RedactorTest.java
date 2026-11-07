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
    void masksACredentialAfterAJsonEscapedSeparator() {
        // A serializer writes a tab or line break after the scheme as an escape, which is still the separator, as an
        // escaped token character is still that character (#212); also escaped again, and several in a row.
        for (String separator : List.of("\\t", "\\n", "\\r", "\\u0020", "\\u0009", "\\u000A", "\\u000D", "\\u000a",
                "\\u000d", "\\\\t", "\\\\n", "\\\\r", "\\\\u0020", "\\\\u0009", "\\r\\n", " \\t", "\\t ", "\\n\\u0020")) {
            assertEquals("{\"echo\":\"Bearer [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Bearer" + separator + "SecretTokenValue99\"}"), separator);
            assertEquals("{\"echo\":\"Basic [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Basic" + separator + "c3ludGhjbGllbnQ6U3ludGg\"}"), separator);
            assertEquals("{\"echo\":\"Authorization: Bearer [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Authorization: Bearer" + separator + "SecretTokenValue99\"}"), separator);
            assertEquals("{\"echo\":\"rejected bearer [REDACTED], twice\"}",
                    Redactor.redact("{\"echo\":\"rejected bearer" + separator + "Ab12\\/SecretRemainder99, twice\"}"), separator);
        }
        // In JSON quoted inside a JSON string.
        assertEquals("{\"debug\":\"{\\\"e\\\":\\\"Bearer [REDACTED]\\\"}\"}",
                Redactor.redact("{\"debug\":\"{\\\"e\\\":\\\"Bearer\\\\tSecretTokenValue99\\\"}\"}"));
        // After Token and DPoP, only an escaped space or tab, as only a real space or tab is.
        for (String separator : List.of("\\t", "\\u0020", "\\u0009", "\\\\t", "\\\\u0020", " \\t")) {
            assertEquals("{\"echo\":\"Token [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Token" + separator + "9944b09199c62bcf9418\"}"), separator);
            assertEquals("{\"echo\":\"rejected DPoP [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"rejected DPoP" + separator + "PHNhbWw6QXNzZXJ0aW9u\"}"), separator);
        }
        for (String separator : List.of("\\n", "\\r", "\\u000A", "\\u000D", "\\r\\n", "\\\\n")) {
            String text = "{\"m\":\"issue a token" + separator + "2 times per hour; DPoP" + separator + "proof-v2 required\"}";
            assertEquals(text, Redactor.redact(text), separator);
        }
    }

    @Test
    void masksACredentialAfterAJsonEscapedFormFeedOrVerticalTab() {
        // Java's \s also takes a form feed and a vertical tab after Bearer or Basic, so their JSON escapes are the
        // separator too: \f, and the six-character escapes 000C and 000B in either case; also escaped again, and
        // mixed with other separators (#212, Codex round 1).
        for (String separator : List.of("\\f", "\\u000C", "\\u000c", "\\u000B", "\\u000b", "\\\\f", "\\\\u000C",
                "\\t\\f", "\\f\\n", " \\f", "\\u000b\\u0020")) {
            assertEquals("{\"echo\":\"Bearer [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Bearer" + separator + "SecretTokenValue99\"}"), separator);
            assertEquals("{\"echo\":\"Basic [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Basic" + separator + "c3ludGhjbGllbnQ6U3ludGg\"}"), separator);
            assertEquals("{\"echo\":\"Authorization: Bearer [REDACTED]\"}",
                    Redactor.redact("{\"echo\":\"Authorization: Bearer" + separator + "SecretTokenValue99\"}"), separator);
            assertEquals("{\"echo\":\"rejected bearer [REDACTED], twice\"}",
                    Redactor.redact("{\"echo\":\"rejected bearer" + separator + "Ab12\\/SecretRemainder99, twice\"}"), separator);
            assertEquals("{\"echo\":\"rejected bearer [REDACTED], twice\"}",
                    Redactor.redact("{\"echo\":\"rejected bearer" + separator + "Ab12\\u002BSecretRemainder99, twice\"}"), separator);
        }
        // In JSON quoted inside a JSON string.
        assertEquals("{\"debug\":\"{\\\"e\\\":\\\"Bearer [REDACTED]\\\"}\"}",
                Redactor.redact("{\"debug\":\"{\\\"e\\\":\\\"Bearer\\\\fSecretTokenValue99\\\"}\"}"));
        // After Token and DPoP only a space or tab separates, so an escaped form feed or vertical tab does not.
        for (String separator : List.of("\\f", "\\u000C", "\\u000b")) {
            String text = "{\"m\":\"issue a token" + separator + "2 times per hour; DPoP" + separator + "proof-v2 required\"}";
            assertEquals(text, Redactor.redact(text), separator);
        }
        // Prose and challenge parameters after one stay as they are.
        for (String text : List.of("{\"m\":\"Missing bearer\\ftoken\"}", "{\"m\":\"Basic\\u000Cplan\"}",
                "{\"h\":\"Bearer\\frealm=\\\"synthetic\\\", error=\\\"invalid_token\\\"\"}")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void readsJsonEscapedSeparatorsInLinearTime() {
        // About 1 MB each: long runs of escapes and backslashes after a scheme, once and repeated.
        List<String> texts = List.of(
                "Bearer" + "\\t".repeat(500_000) + "\"",
                "Bearer" + "\\u0020".repeat(170_000) + "\"",
                "Token" + " \\t".repeat(330_000) + "\\n",
                "Bearer" + "\\".repeat(1_000_000) + "x",
                ("Bearer" + "\\".repeat(1_000) + "x").repeat(1_000),
                ("Basic\\n" + "\\".repeat(1_000) + "t").repeat(1_000),
                "Bearer\\t".repeat(125_000),
                "DPoP\\u0009".repeat(100_000));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(Redactor::redact));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer" + "\\t".repeat(100_000) + "SecretTokenValue99"));
    }

    @Test
    void keepsProseAndChallengeParametersAfterAJsonEscapedSeparator() {
        for (String text : List.of("{\"m\":\"Missing bearer\\ntoken\"}", "{\"m\":\"Basic\\nplan\"}",
                "{\"m\":\"Missing bearer\\u0020token.\"}", "{\"m\":\"Basic\\tauthentication is required\"}",
                "{\"m\":\"Missing bearer\\\\ntoken\"}",
                // The challenge parameters a 401 names after the scheme are not a credential.
                "{\"h\":\"Bearer\\trealm=\\\"synthetic\\\", error=\\\"invalid_token\\\"\"}",
                "{\"h\":\"Bearer\\nerror=\\\"invalid_token\\\", error_description=\\\"Expired\\\"\"}",
                "{\"h\":\"Bearer\\u0020error_description=\\\"Expired\\\"\"}",
                "{\"h\":\"Basic\\u0020realm=\\\"synthetic-payer\\\"\"}",
                "{\"h\":\"Bearer\\r\\nscope=\\\"system/*.read\\\"\"}")) {
            assertEquals(text, Redactor.redact(text));
        }
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
                "{\"b\":\"" + "\\".repeat(1 << 20) + "\\\"kty\\\":1\"}",
                // Members each quoted with a different number of backslashes after a kty (Codex security round 2),
                // bare and as a recorded body in a report: every search is charged to its level's budget.
                distinctBackslashCounts(1000), nested(distinctBackslashCounts(1000)));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(Redactor::redact));
    }

    /** A JWK whose members after kty are each quoted with a different number of backslashes, 1 to {@code n}. */
    private static String distinctBackslashCounts(int n) {
        StringBuilder text = new StringBuilder("{\"kty\":\"oct\"");
        for (int run = 1; run <= n; run++) {
            String quote = "\\".repeat(run) + "\"";
            text.append(',').append(quote).append('k').append(quote).append(":\"PRIVK").append(run).append('"');
        }
        return text.append('}').toString();
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
        // A value opened with \" and closed with \\u0022, before a private member or after a secret field: the
        // members after it are read as JSON reads them.
        for (String in : List.of(
                "{\"body\":\"{\\\"kty\\\":\\\"RSA\\\",\\\"d\\\":\\\"PRIVD\\u0022,\\\"p\\\":\\\"PRIVP\\\"}\"}",
                "{\"body\":\"{\\\"kty\\\":\\\"RSA\\\",\\\"password\\\":\\\"PRIVPW\\u0022,\\\"d\\\":\\\"PRIVD\\\"}\"}")) {
            String out = Redactor.redact(in);
            assertFalse(out.contains("PRIV"), out);
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
        // A sibling holding an escaped quote, or a stray quote in prose before the JSON, must not shift which quotes
        // bound the string that holds the chain (the review on 2334a77).
        String chain = "\\u005c" + "u005c".repeat(40) + "u0022";
        String chainJwk = "{" + chain + "kty" + chain + ":" + chain + "oct" + chain + "," + chain + "k" + chain + ":" + chain
                + "PRIVATECHAINVALUE" + chain + "}";
        for (String in : List.of("{\"label\":\"a\\\"b\",\"body\":\"" + chainJwk + "\"}",
                "payer said 5\" screen: {\"body\":\"" + chainJwk + "\"}")) {
            String out = Redactor.redact(in);
            assertFalse(out.contains("PRIVATECHAINVALUE"), out);
            assertTrue(out.length() <= in.length(), out);
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

    @Test
    void masksSecretFieldsNestedTwoOrMoreLevelsDeep() {
        // #339: the issue's shape, two levels deep with \\\" quotes.
        assertEquals("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_secret\\\\\\\":\\\\\\\"[REDACTED]\\\\\\\"}\\\"}\"}",
                Redactor.redact("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_secret\\\\\\\":\\\\\\\"s3cr3t\\\\\\\"}\\\"}\"}"));
        // Three levels deep, \\\\\\\" quotes.
        assertEquals("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"c\\\\\\\":\\\\\\\"{\\\\\\\\\\\\\\\"client_secret\\\\\\\\\\\\\\\":"
                        + "\\\\\\\\\\\\\\\"[REDACTED]\\\\\\\\\\\\\\\"}\\\\\\\"}\\\"}\"}",
                Redactor.redact("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"c\\\\\\\":\\\\\\\"{\\\\\\\\\\\\\\\"client_secret\\\\\\\\\\\\\\\":"
                        + "\\\\\\\\\\\\\\\"s3cr3t\\\\\\\\\\\\\\\"}\\\\\\\"}\\\"}\"}"));
        // Every spelling isSecretField accepts, a name spelled with a \\u escape, a number and an object value, with
        // other members around them: only the secret values change, at every depth.
        // The expected outputs are written out, so a change to the unnested redaction fails here too (review on 84afef7).
        for (String[] pair : List.of(
                new String[] {"{\"client_id\":\"app\",\"client_secret\":\"s3cr3t\",\"scope\":\"x\"}",
                        "{\"client_id\":\"app\",\"client_secret\":\"[REDACTED]\",\"scope\":\"x\"}"},
                new String[] {"{\"clientSecret\":\"s3cr3t\",\"n\":1}",
                        "{\"clientSecret\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"grant\":\"x\",\"client-secret\":\"s3cr3t\"}",
                        "{\"grant\":\"x\",\"client-secret\":\"[REDACTED]\"}"},
                new String[] {"{\"client\\u005fsecret\":\"s3cr3t\",\"client_id\":\"app\"}",
                        "{\"client\\u005fsecret\":\"[REDACTED]\",\"client_id\":\"app\"}"},
                new String[] {"{\"password\":123456,\"user\":\"u\"}",
                        "{\"password\":\"[REDACTED]\",\"user\":\"u\"}"},
                new String[] {"{\"private_key\":{\"x\":\"s3cr3t\",\"y\":[1,2]},\"kid\":\"k1\"}",
                        "{\"private_key\":\"[REDACTED]\",\"kid\":\"k1\"}"},
                new String[] {"{\"note\":\"a \\\"quoted\\\" \\\\ word\",\"access_token\":\"s3cr3t\"}",
                        "{\"note\":\"a \\\"quoted\\\" \\\\ word\",\"access_token\":\"[REDACTED]\"}"})) {
            String json = pair[0];
            String masked = pair[1];
            assertEquals(masked, Redactor.redact(json));
            String in = json;
            String out = masked;
            for (int depth = 1; depth <= 4; depth++) {
                in = nested(in);
                out = nested(out);
                assertEquals(out, Redactor.redact(in), "depth " + depth + ": " + json);
            }
        }
    }

    @Test
    void masksSecretFieldsWhoseEmbeddedJsonIsSpelledWithUnicodeEscapes() {
        // #339: quotes spelled \\u0022, in a JSON string and at the top level (text copied from inside a string).
        assertEquals("{\"a\":\"{\\u0022client_secret\\u0022:\\u0022[REDACTED]\\u0022}\"}",
                Redactor.redact("{\"a\":\"{\\u0022client_secret\\u0022:\\u0022s3cr3t\\u0022}\"}"));
        assertEquals("{\\u0022client_secret\\u0022:\\u0022[REDACTED]\\u0022}",
                Redactor.redact("{\\u0022client_secret\\u0022:\\u0022s3cr3t\\u0022}"));
        // A level written with \" inside a level written with \\u0022, and the reverse.
        assertEquals("{\"a\":\"{\\u0022b\\u0022:\\u0022{\\\\\\\"client_secret\\\\\\\":\\\\\\\"[REDACTED]\\\\\\\"}\\u0022}\"}",
                Redactor.redact("{\"a\":\"{\\u0022b\\u0022:\\u0022{\\\\\\\"client_secret\\\\\\\":\\\\\\\"s3cr3t\\\\\\\"}\\u0022}\"}"));
        assertEquals("{\"a\":\"{\\\"b\\\":\\\"{\\\\u0022client_secret\\\\u0022:\\\\u0022[REDACTED]\\\\u0022}\\\"}\"}",
                Redactor.redact("{\"a\":\"{\\\"b\\\":\\\"{\\\\u0022client_secret\\\\u0022:\\\\u0022s3cr3t\\\\u0022}\\\"}\"}"));
        // Every mix of escapes one to three levels deep keeps all but the secret values byte for byte.
        List<UnaryOperator<String>> levels = List.of(RedactorTest::nested, RedactorTest::nestedEscapingQuotes);
        for (String[] shape : List.of(
                new String[] {"{\"client_id\":\"app\",\"client_secret\":\"s3cr3t\",\"scope\":\"x\"}",
                        "{\"client_id\":\"app\",\"client_secret\":\"[REDACTED]\",\"scope\":\"x\"}"},
                new String[] {"{\"clientSecret\":\"s3cr3t\"}",
                        "{\"clientSecret\":\"[REDACTED]\"}"},
                new String[] {"{\"client-secret\":\"s3cr3t\",\"n\":1}",
                        "{\"client-secret\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"client\\u005fsecret\":\"s3cr3t\"}",
                        "{\"client\\u005fsecret\":\"[REDACTED]\"}"})) {
            String json = shape[0];
            String masked = shape[1];
            assertEquals(masked, Redactor.redact(json));
            for (UnaryOperator<String> a : levels) {
                for (UnaryOperator<String> b : levels) {
                    for (UnaryOperator<String> c : levels) {
                        for (String[] pair : List.of(new String[] {a.apply(json), a.apply(masked)},
                                new String[] {b.apply(a.apply(json)), b.apply(a.apply(masked))},
                                new String[] {c.apply(b.apply(a.apply(json))), c.apply(b.apply(a.apply(masked)))})) {
                            assertEquals(pair[1], Redactor.redact(pair[0]), pair[0]);
                        }
                    }
                }
            }
        }
    }

    @Test
    void leavesNonSecretFieldsNestedDeepOrSpelledWithUnicodeEscapesAlone() {
        for (String in : List.of(
                "{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_id\\\\\\\":\\\\\\\"app\\\\\\\"}\\\"}\"}",
                "{\"a\":\"{\\u0022client_id\\u0022:\\u0022app\\u0022}\"}",
                "{\\u0022client_id\\u0022:\\u0022app\\u0022,\\u0022token_type\\u0022:\\u0022Bearer\\u0022}",
                nested(nested(nested("{\"client_id\":\"app\",\"secretary\":\"s\",\"n\":1,\"obj\":{\"x\":[1]}}"))),
                nestedEscapingQuotes(nested("{\"client_id\":\"app\",\"scope\":\"a b\"}")))) {
            assertEquals(in, Redactor.redact(in));
        }
    }

    @Test
    void masksSecretFieldsWhoseNameAndValueQuotesAreSpelledDifferently() {
        // #339 security round 1, finding 1: \\u0022 on only the name's quotes, only the value's, or on single
        // delimiters. Each quote keeps its spelling, and only the value's content becomes the mask.
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":\\u0022s3cr3t\\u0022}", "{\"client_secret\":\\u0022[REDACTED]\\u0022}"},
                new String[] {"{\\u0022client_secret\\u0022:\"s3cr3t\"}", "{\\u0022client_secret\\u0022:\"[REDACTED]\"}"},
                new String[] {"{\"client_secret\\u0022:\"s3cr3t\"}", "{\"client_secret\\u0022:\"[REDACTED]\"}"},
                new String[] {"{\\u0022client_secret\":\"s3cr3t\"}", "{\\u0022client_secret\":\"[REDACTED]\"}"},
                new String[] {"{\"client_secret\":\\u0022s3cr3t\"}", "{\"client_secret\":\\u0022[REDACTED]\"}"},
                new String[] {"{\"n\":1,\"clientSecret\":\\u0022s3cr3t\\u0022,\"scope\":\"x\"}",
                        "{\"n\":1,\"clientSecret\":\\u0022[REDACTED]\\u0022,\"scope\":\"x\"}"},
                new String[] {"{\\u0022password\\u0022:123456}", "{\\u0022password\\u0022:\\u0022[REDACTED]\\u0022}"})) {
            assertEquals(pair[1], Redactor.redact(pair[0]), pair[0]);
            // Wrapped: the same text in a JSON string, one and two levels deep, whichever way each level escapes.
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(RedactorTest::nested,
                    RedactorTest::nestedEscapingQuotes, t -> nested(nested(t)), t -> nestedEscapingQuotes(nested(t)),
                    t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(pair[1]), Redactor.redact(wrap.apply(pair[0])), wrap.apply(pair[0]));
            }
        }
        // A value opened with a plain quote is a JSON string, where \\u0022 is a character of it: masked through its
        // plain closing quote, as JSON_FIELD masks it on main (review on 47c938e), so no part of the value is kept.
        assertEquals("{\"client_secret\":\"[REDACTED]\"client_id\":\"app\"}",
                Redactor.redact("{\"client_secret\":\"s3cr3t\\u0022,\"client_id\":\"app\"}"));
        assertEquals("{\"password\":\"[REDACTED]\"}", Redactor.redact("{\"password\":\"ab\\u0022cd\"}"));
        // Non-secret names spelled the same way stay byte for byte.
        for (String in : List.of("{\"client_id\":\\u0022app\\u0022}", "{\\u0022client_id\\u0022:\"app\"}",
                nested("{\"client_id\":\\u0022app\\u0022,\\u0022scope\\u0022:\"a b\"}"))) {
            assertEquals(in, Redactor.redact(in));
        }
    }

    @Test
    void masksASecretFieldWhoseNameOpensOnTheQuoteThatClosesTheValueBeforeIt() {
        // #339 security round 1, finding 2: in malformed recorded text the quote that closes one value ("x":"") is also
        // the one that opens the next name; a search for whole fields consumed it with x and skipped client_secret.
        // Masked at every depth, also with quotes spelled \\u0022, and the structure kept byte for byte.
        for (String[] pair : List.of(
                new String[] {"{\"x\":\"\"client_secret\":\"s3cr3t\"}", "{\"x\":\"\"client_secret\":\"[REDACTED]\"}"},
                new String[] {"{\"x\":\"a\"password\":\"s3cr3t\",\"n\":1}", "{\"x\":\"a\"password\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"x\":\"\"private_key\":{\"d\":\"s3cr3t\"},\"kid\":\"k1\"}",
                        "{\"x\":\"\"private_key\":\"[REDACTED]\",\"kid\":\"k1\"}"})) {
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes,
                    t -> nestedEscapingQuotes(nested(t)), t -> nested(nestedEscapingQuotes(t)),
                    t -> nested(nested(nestedEscapingQuotes(t))))) {
                assertEquals(wrap.apply(pair[1]), Redactor.redact(wrap.apply(pair[0])), wrap.apply(pair[0]));
            }
        }
        // The same with every quote of the text spelled \\u0022.
        assertEquals("{QxQ:QQclient_secretQ:Q[REDACTED]Q}".replace("Q", "\\u0022"),
                Redactor.redact("{QxQ:QQclient_secretQ:Qs3cr3tQ}".replace("Q", "\\u0022")));
        // A non-secret name in the same place is kept.
        String kept = nested(nested("{\"x\":\"\"client_id\":\"app\"}"));
        assertEquals(kept, Redactor.redact(kept));
    }

    @Test
    void masksEmptyAndEscapedSecretValuesOnceAndKeepsTheSeparatorsAfterThem() {
        // Review on c8d676f: an empty value was masked twice ([REDACTED][REDACTED]), once by each reading that found
        // it, and a view unescaped past the JSON's own level read a value ending in an escaped backslash as running on
        // through the next member, dropping the separator. Each value becomes one mask and the rest stays byte for
        // byte, at every depth and however each level spells its quotes.
        List<UnaryOperator<String>> wraps = List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                t -> nested(nested(t)), t -> nested(nested(nested(t))), t -> nested(nested(nested(nested(t)))),
                RedactorTest::nestedEscapingQuotes, t -> nestedEscapingQuotes(nested(t)), t -> nested(nestedEscapingQuotes(t)),
                t -> nested(nested(nestedEscapingQuotes(t))));
        for (String value : List.of("", "s3cr3t\\\\", "s3\\\"cr3t", "\\\\\\\\", "s3\\\\\\\"cr3t", "s3\\ncr3t", "\\\\s3cr3t")) {
            String in = "{\"client_secret\":\"" + value + "\",\"client_id\":\"app\",\"password\":\"" + value + "\"}";
            String out = "{\"client_secret\":\"[REDACTED]\",\"client_id\":\"app\",\"password\":\"[REDACTED]\"}";
            for (UnaryOperator<String> wrap : wraps) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
        assertEquals("{QpasswordQ:Q[REDACTED]Q}".replace("Q", "\\u0022"), Redactor.redact("{QpasswordQ:QQ}".replace("Q", "\\u0022")));
    }

    @Test
    void masksASecretObjectWholeWhoseMembersAnEarlierReadingMasked() {
        // Review on 806a28c: a secret-named object whose own members a shallower reading masked first
        // ({\\u0022private_key\\u0022:{"password":"",...}}) lost its whole-object mask, keeping its other members.
        for (String[] pair : List.of(
                new String[] {"{QprivateKeyQ:{\"password\":\"\",\"other\":42}}", "{QprivateKeyQ:Q[REDACTED]Q}"},
                new String[] {"{Qprivate_keyQ:{\"password\":\"pw\",\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{Qprivate_keyQ:Q[REDACTED]Q,\"kid\":\"k1\"}"},
                new String[] {"{Qclient_secretQ:[\"a\",{\"access_token\":\"t\"},\"PRIVITEM\"]}", "{Qclient_secretQ:Q[REDACTED]Q}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes)) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void masksASecretObjectWholeOverTheSecretObjectsInsideItButNotPastItsEnd() {
        // Review on 43b954a: an earlier reading's mask of a secret object inside a secret object
        // ({Qprivate_keyQ:{Qpassword":{},...}}) made the enclosing mask drop, keeping "other":42. A mask that starts
        // where an earlier one does is a competing reading of the same value, and still loses: a view unescaped past
        // the JSON's own level must not run an object on past its close bracket.
        for (String[] pair : List.of(
                new String[] {"{Qprivate_keyQ:{Qpassword\":{},\"other\":42}}", "{Qprivate_keyQ:Q[REDACTED]Q}"},
                new String[] {"{QprivateKeyQ:{\"a\":1,Qclient_secret\":[1,2],\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{QprivateKeyQ:Q[REDACTED]Q,\"kid\":\"k1\"}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes)) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
        String in = "{\"private_key\":{\"a\":\"x\\\\\",\"b\":[\"]\\\\\"]},\"client_id\":\"app\",\"n\":[1]}";
        String out = "{\"private_key\":\"[REDACTED]\",\"client_id\":\"app\",\"n\":[1]}";
        UnaryOperator<String> wrap = UnaryOperator.identity();
        for (int depth = 0; depth <= 4; depth++, wrap = compose(wrap)) {
            assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
        }
    }

    @Test
    void masksAMixedQuotedSecretObjectWholeThroughEscapedQuotesInItsStrings() {
        // Review on 7a80b9c: a secret object whose name is quoted one level deeper than its members was masked in the
        // next view, which also takes an escape off the members' strings, so "a\"}b" read as closing the object at its
        // brace. It is read in its own view instead, its strings at their own level.
        for (String[] pair : List.of(
                new String[] {"{Qprivate_keyQ:{\"note\":\"a\\\"}b\",\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{Qprivate_keyQ:Q[REDACTED]Q,\"kid\":\"k1\"}"},
                new String[] {"{Qclient_secretQ:[\"x\\\"]\",\"PRIVITEM\"],\"n\":1}", "{Qclient_secretQ:Q[REDACTED]Q,\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAPlainQuotedValueAfterAMixedQuotedNameAtItsOwnEscapeLevel() {
        // Review on 5b051eb: after a name whose quotes are spelled \\u0022 (one or both), a plain-quoted string value was
        // read only in the next view, which takes an escape off it: an escaped quote in it closed it early, keeping the
        // rest, and an escaped backslash at its end ran it through the next member. It is read in its own view.
        for (String[] pair : List.of(
                new String[] {"{Qclient_secretQ:\"s3\\\"cr3t\",\"n\":1}", "{Qclient_secretQ:\"[REDACTED]\",\"n\":1}"},
                new String[] {"{Qclient_secretQ:\"s3cr3t\\\\\",\"n\":1}", "{Qclient_secretQ:\"[REDACTED]\",\"n\":1}"},
                new String[] {"{Qpassword\":\"a\\\\\\\"b\",\"n\":1}", "{Qpassword\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"client_secretQ:\"s3\\\"cr3t\"}", "{\"client_secretQ:\"[REDACTED]\"}"},
                new String[] {"{Qprivate_key\":{\"note\":\"a\\\"}b\",\"other\":\"PRIVOTHER\"},\"n\":1}",
                        "{Qprivate_key\":Q[REDACTED]Q,\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAValueOpenedByAUnicodeQuoteAtItsOwnEscapeLevel() {
        // Security round 2: a string value whose opening quote is spelled \\u0022 after a plain or mixed-quoted name
        // was read only in the next view, which takes an escape off it: an escaped quote at its start closed it there,
        // so an empty string was masked and the rest kept, and an escaped backslash at its end ran it on. It is read in
        // its own view, with its own escapes, and masked whole.
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":Q\\\"s3cr3tQ}", "{\"client_secret\":Q[REDACTED]Q}"},
                new String[] {"{\"client_secret\":Q\\\"s3cr3t\"}", "{\"client_secret\":Q[REDACTED]\"}"},
                new String[] {"{\"client_secret\":Q\\\\\\\"s3cr3tQ,\"n\":1}", "{\"client_secret\":Q[REDACTED]Q,\"n\":1}"},
                new String[] {"{\"client_secret\":Qs3cr3t\\\\Q,\"n\":1}", "{\"client_secret\":Q[REDACTED]Q,\"n\":1}"},
                new String[] {"{\"password\":Qs3\\\"cr3t\\\\\\\\Q,\"client_id\":\"app\"}",
                        "{\"password\":Q[REDACTED]Q,\"client_id\":\"app\"}"},
                new String[] {"{Qclient_secretQ:Q\\\"s3cr3tQ}", "{Qclient_secretQ:Q[REDACTED]Q}"},
                new String[] {"{Qclient_secret\":Qs3\\\"cr3t\"}", "{Qclient_secret\":Q[REDACTED]\"}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
        // A non-secret value so quoted keeps every byte.
        for (String text : List.of("{\"client_id\":Q\\\"appQ,\"n\":1}".replace("Q", "\\u0022"),
                nested(nested("{\"scope\":Qa\\\\Q,\"n\":1}".replace("Q", "\\u0022"))))) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void keepsTheUnicodeQuotesInAPlainQuotedValueAfterANameQuotedWithThem() {
        // Review on 96428f9: the flattened view reads every quote a level decodes from \\u0022 as a bare one, so a
        // plain-quoted value after a name so quoted closed at a \\u0022 of its own and kept the rest. A plain-quoted
        // value is read in the decoded view, where such a quote stays an escape, as a7a971d read it.
        for (String[] pair : List.of(
                new String[] {"{Qclient_secretQ:\"preQTAIL\"}", "{Qclient_secretQ:\"[REDACTED]\"}"},
                new String[] {"{Qclient_secretQ:\"Q,TAIL\"}", "{Qclient_secretQ:\"[REDACTED]\"}"},
                new String[] {"{\"client_secretQ:\"preQ,TAIL\"}", "{\"client_secretQ:\"[REDACTED]\"}"},
                new String[] {"{Qclient_secret\":\"preQTAIL\",\"n\":1}", "{Qclient_secret\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{QpasswordQ:\"a\\\"bQ\\\\c\",\"client_id\":\"app\"}",
                        "{QpasswordQ:\"[REDACTED]\",\"client_id\":\"app\"}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void masksASecretObjectWholeThroughAQuoteEscapedInsideItsUnicodeQuotedStrings() {
        // Review on ef4a81b: in a secret object or array whose strings are quoted with \\u0022 and hold an escaped quote
        // of their own, the embedded reading closed the string at that quote and the object at the brace after it,
        // keeping the members after it. The flattened view reads the object whole, and its mask takes the shorter one.
        for (String[] pair : List.of(
                new String[] {"{Qprivate_keyQ:{QnoteQ:Q\\\"}Q,QotherQ:42}}",
                        "{Qprivate_keyQ:Q[REDACTED]Q}"},
                new String[] {"{Qprivate_keyQ:{QnoteQ:Q\\\"}Q,QotherQ:\"PRIVOTHER\"},\"n\":1}",
                        "{Qprivate_keyQ:Q[REDACTED]Q,\"n\":1}"},
                new String[] {"{QsecretQ:[Q\\\"]Q,QPRIVOTHERQ]}",
                        "{QsecretQ:Q[REDACTED]Q}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void masksASecretObjectWholeThroughABracketInsideAUnicodeQuotedString() {
        // Review on 9de277d, P1: the plain structure pass ran first and closed the object at a bracket inside a string
        // quoted with \\u0022, keeping the members after it, before the flattened view could read the object whole.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"note\":Q}Q,\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":{\"note\":Q}Q,\"other\":\"PRIVOTHER\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":[Q]Q,\"PRIVOTHER\"],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void keepsTheDelimitersAfterAUnicodeQuotedValueEndingInAnEscapedBackslash() {
        // Review on 9de277d, P2: the embedded reading read the value's escaped backslash and closing \\u0022 as an
        // escaped quote, ran it on to the next bare quote and masked the closing quote and comma with it. The flattened
        // reading, which closes the value there, takes that reading's place.
        for (String[] pair : List.of(
                new String[] {"{QpasswordQ:Qx\\\\Q,\"n\":1}",
                        "{QpasswordQ:Q[REDACTED]Q,\"n\":1}"},
                new String[] {"{Qclient_secretQ:Qs3\\\\Q,\"client_id\":\"app\"}",
                        "{Qclient_secretQ:Q[REDACTED]Q,\"client_id\":\"app\"}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void keepsTheUnicodeQuotesInsideAPlainQuotedStringOfASecretObject() {
        // Review on 84afef7: the flattened view read a \\u0022 inside a plain-quoted string of a secret object as a
        // quote, so the object ran on to the end of the text and took the members after it.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"note\":\"aQ{\",\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":[\"aQ[\",1],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{QpasswordQ:{\"note\":\"aQ}\",\"other\":\"PRIVOTHER\"},\"n\":1}",
                        "{QpasswordQ:Q[REDACTED]Q,\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void readsANameAtItsOwnEscapeLevelOnly() {
        // Review on 84afef7: a deeper view took one more escape off a member's name, so client\\\\u005fsecret (an
        // escaped backslash before u005f, not client_secret) was read as client_secret and its value masked.
        for (String text : List.of(
                "{\"client\\\\u005fsecret\":42}",
                "{\"client\\\\u005fsecret\":\"x\",\"n\":1}",
                "{Qclient\\\\u005fsecretQ:42,\"n\":1}",
                "{\"a\":{\"pass\\\\u0077ord\":\"x\"}}")) {
            String in = text.replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrap.apply(in), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    private static UnaryOperator<String> compose(UnaryOperator<String> wrap) {
        return t -> nested(wrap.apply(t));
    }

    @Test
    void masksNestedSecretFieldsInLinearTime() {
        // About 1 MB each of openers that never close, nested two levels deep and spelled with \\u0022: a fixed
        // number of levels, each read once, so time stays linear (quadratic time takes minutes).
        int n = 60_000;
        List<String> texts = List.of(
                "{\"a\":\"{\\\"b\\\":\\\"" + "\\\\\\\"client_secret\\\\\\\":".repeat(n) + "\\\"}\"}",
                "{\"a\":\"{\\\"b\\\":\\\"" + "\\\\\\\"client_secret\\\\\\\":\\\\\\\"".repeat(n) + "\\\"}\"}",
                "{\"a\":\"" + "\\u0022client_secret\\u0022:".repeat(n) + "\"}",
                "\\u0022client_secret\\u0022:\\u0022".repeat(n),
                "{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_secret\\\\\\\":{" + "\\\\\\\"x\\\\\\\":[".repeat(n) + "\\\"}\"}",
                nested(nested(nested("{\"client_secret\":\"" + "x".repeat(20 * n)))));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(text -> {
            String out = Redactor.redact(text);
            // Empty values in the malformed openers ({\"client_secret\":\"\"}) get the mask, so the text may grow,
            // but only by a bounded factor.
            assertTrue(out.length() <= 2 * text.length(), () -> out.length() + " > 2 * " + text.length());
        }));
        String cut = nested(nested(nested("{\"client_secret\":\"s3cr3t" + "x".repeat(20 * n))));
        assertFalse(Redactor.redact(cut).contains("s3cr3t"));
    }

    @Test
    void findsSecretNamesApartFromTheirValuesInLinearTime() {
        // About 1 MB each (security round 1): names that each open on the quote closing the value before them, plain
        // and embedded, and names and values quoted differently. Every name is found apart from its value and each
        // value is read once, so time stays linear.
        int n = 60_000;
        List<String> texts = List.of(
                "\"x\":\"\"password\":\"".repeat(n),
                "{\"a\":\"" + "\\\"x\\\":\\\"\\\"client_secret\\\":\\\"".repeat(n) + "\"}",
                ("\"client_secret\":" + "\\" + "u0022").repeat(n),
                // Review on 47c938e: embedded structures that one bare quote at the end cuts off, each read to it.
                ("\\u0022client_secret\\u0022:{").repeat(n) + "\"",
                // Security round 2: values the flattened view reads past the empty string another reading found.
                ("\\u0022client_secret\\u0022:\\u0022\\\"s3\\u0022,").repeat(n));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(text -> {
            String out = Redactor.redact(text);
            assertTrue(out.length() <= 2 * text.length(), () -> out.length() + " > 2 * " + text.length());
        }));
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

    /** Every character of {@code text} written as a unicode escape. */
    private static String escapedEverything(String text) {
        StringBuilder out = new StringBuilder();
        text.chars().forEach(c -> out.append(String.format("\\u%04x", c)));
        return out.toString();
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

    /** {@code text} as the content of a JSON string, escaped as a serializer escapes it, without its quotes. */
    private static String escapedForJson(String text) {
        String quoted = JSON.writeValueAsString(text);
        return quoted.substring(1, quoted.length() - 1);
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
    void masksAJwkWhoseKtyComesAfterAnUnterminatedPrivateKeyBlock() {
        // The review's ordering: d, then a member holding an unterminated private key header, then kty. Masking the
        // block to the end of the text must not hide kty from the JWK pass first.
        String plain = "{\"d\":\"PRIVD\",\"note\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\nlQOY\",\"kty\":\"RSA\"}";
        assertFalse(Redactor.redact(plain).contains("PRIVD"), Redactor.redact(plain));
        String embedded = nested(plain.replace("PGP PRIVATE KEY BLOCK", "RSA PRIVATE KEY"));
        assertFalse(Redactor.redact(embedded).contains("PRIVD"), Redactor.redact(embedded));
    }

    @Test
    void masksAPrivateKeyBlockThatStartsInsideAJwkMember() {
        // Codex security round 5: masking the JWK first must not erase a block's header before the block is masked.
        // 6304ec0 left none of the key material in any of these; neither may the JWK-first order.
        String terminated = "{\"kty\":\"RSA\",\"d\":\"-----BEGIN PRIVATE KEY-----\",\"note\":\"FAKEKEYMATERIAL_293\\n-----END PRIVATE KEY-----\"}";
        String unterminated = "{\"kty\":\"RSA\",\"d\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\",\"note\":\"FAKEKEYMATERIAL_293\"}";
        String rawAfter = "{\"kty\":\"RSA\",\"d\":\"-----BEGIN PRIVATE KEY-----\"} FAKEKEYMATERIAL_293\n-----END PRIVATE KEY-----";
        for (String in : List.of(terminated, unterminated, rawAfter, nested(terminated), nested(unterminated),
                nested(nested(terminated)))) {
            String out = Redactor.redact(in);
            assertFalse(out.contains("FAKEKEYMATERIAL_293"), () -> in + "\n became " + out);
        }
    }

    @Test
    void masksAJwkMemberThatAStrayQuoteInAPrivateKeyBlockHides() {
        // Codex security round 6: the stray quote inside the block closes "note" early, so the JWK read of the text as
        // it came never sees d as a member; masking the block takes the quote away, and 6304ec0 (PEM first) masked d.
        String pem = "{\"kty\":\"RSA\",\"note\":\"-----BEGIN PRIVATE KEY-----\"-----END PRIVATE KEY-----\",\"d\":\"FAKE_PRIVATE_KEY_293\"}";
        String pgp = pem.replace("PRIVATE KEY-----", "PGP PRIVATE KEY BLOCK-----");
        // What 6304ec0 made of the two raw inputs.
        assertEquals("{\"kty\":\"RSA\",\"note\":\"-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\",\"d\":\"[REDACTED]\"}",
                Redactor.redact(pem));
        assertEquals("{\"kty\":\"RSA\",\"note\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED]\n"
                + "-----END PGP PRIVATE KEY BLOCK-----\",\"d\":\"[REDACTED]\"}", Redactor.redact(pgp));
        for (String raw : List.of(pem, pgp)) {
            for (String in : List.of(nested(raw), nested(nested(raw)), nestedEscapingQuotes(raw),
                    nestedEscapingBackslashes(raw), nestedEscapingEverything(raw))) {
                String out = Redactor.redact(in);
                assertFalse(out.contains("FAKE_PRIVATE_KEY_293"), () -> in + "\n became " + out);
            }
        }
    }

    @Test
    void masksEveryPrivateMemberOnceFindingTheJwksSpendsItsBudget() {
        // Codex round 7, finding 1: repeated kty syntax spends the JWK search's 4n + 1024 budget, so every private member
        // name is masked, in an object or not. The leak scanner's r7 test uses these outputs as its masked forms.
        String d = "\"d\":\"FAKE_PRIVATE_KEY_293\"";
        String masked = "\"d\":\"[REDACTED]\"";
        String loose = "\"kty\":\"".repeat(63);
        String spelled = "\"\\u006bty\":\"".repeat(63);
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put(loose + d, loose + masked);
        cases.put("[" + loose + d + "]", "[" + loose + masked + "]");
        cases.put(spelled + d, spelled + masked);
        new LinkedHashMap<>(cases).forEach((leaked, kept) -> cases.put(nested(leaked), nested(kept)));
        // Every character escaped as a unicode escape, once and twice over; the mask is quoted as the name is.
        String quote = "\\u0022";
        String once = nestedEscapingEverything(loose + d);
        cases.put(once, "{\"body\":\"" + escapedEverything(loose + "\"d\":") + quote + "[REDACTED]" + quote + "\"}");
        cases.put(nestedEscapingEverything(once), "{\"body\":\"" + escapedEverything("{\"body\":\"" + escapedEverything(loose + "\"d\":"))
                + escapedEverything(quote) + "[REDACTED]" + escapedEverything(quote) + escapedEverything("\"}") + "\"}");
        // The same text copied from inside such strings, with no bracket or quote left bare.
        cases.put(escapedEverything(escapedEverything(loose + d)), escapedEverything(escapedEverything(loose + "\"d\":"))
                + escapedEverything(quote) + "[REDACTED]" + escapedEverything(quote));
        cases.forEach((leaked, kept) -> assertEquals(kept, Redactor.redact(leaked)));
        // Ten repetitions do not spend it: d is in no object, and is kept.
        String few = "\"kty\":\"".repeat(10) + d;
        assertEquals(few, Redactor.redact(few));
    }

    @Test
    void masksTheTwiceEscapedCopiedFormWithQuotedProseAfterIt() {
        // Codex narrow check at 3c47acc, finding 2: quoted prose after the copied form does not stop the JWK search from
        // spending its budget in the twice-decoded view. The leak scanner's r9 test uses this output as its masked form.
        String loose = "\"kty\":\"".repeat(63);
        String quote = "\\u0022";
        String prose = " note: \"ok\"";
        assertEquals(escapedEverything(escapedEverything(loose + "\"d\":")) + escapedEverything(quote) + "[REDACTED]"
                + escapedEverything(quote) + prose,
                Redactor.redact(escapedEverything(escapedEverything(loose + "\"d\":\"FAKE_PRIVATE_KEY_293\"")) + prose));
        // After a stray quote whose string has an escape JSON has not, with and without the prose: the scanner's r9 tests.
        String stray = "he said \"don\\'t ";
        for (String after : List.of("", prose)) {
            assertEquals(stray + escapedEverything(escapedEverything(loose + "\"d\":")) + escapedEverything(quote) + "[REDACTED]"
                    + escapedEverything(quote) + after,
                    Redactor.redact(stray + escapedEverything(escapedEverything(loose + "\"d\":\"FAKE_PRIVATE_KEY_293\"")) + after));
        }
    }

    @Test
    void masksTheTwiceEscapedCopiedFormAfterAStrayQuoteAndARawLineBreak() {
        // #342: a stray quote and a raw line break (LF, CRLF or CR, with or without a backslash before it) ahead of the
        // copied form do not stop the JWK search from spending its budget in the twice-decoded view. The leak scanner's
        // #342 test uses this output as its masked form.
        String loose = "\"kty\":\"".repeat(63);
        String quote = "\\u0022";
        for (String before : List.of("he said \"\n", "he said \"\r\n", "he said \"\r", "\"\n", "he said \"\\\n",
                "he said \"\\\r\n")) {
            for (String after : List.of("", " note: \"ok\"")) {
                assertEquals(before + escapedEverything(escapedEverything(loose + "\"d\":")) + escapedEverything(quote)
                        + "[REDACTED]" + escapedEverything(quote) + after,
                        Redactor.redact(before + escapedEverything(escapedEverything(loose + "\"d\":\"FAKE_PRIVATE_KEY_342\""))
                                + after));
            }
        }
    }

    @Test
    void masksTheTwiceEscapedCopiedFormAfterAStrayQuoteThatOpensNoMember() {
        // #342: the leak scanner's test of the same name uses this output as its masked form.
        String loose = "\"kty\":\"".repeat(63);
        String quote = "\\u0022";
        for (String before : List.of("\"\n\",\"body\":", "\"\r\n\",\"body\":", "x\",\"body\":")) {
            assertEquals(before + escapedEverything(escapedEverything(loose + "\"d\":")) + escapedEverything(quote)
                    + "[REDACTED]" + escapedEverything(quote),
                    Redactor.redact(before + escapedEverything(escapedEverything(loose + "\"d\":\"FAKE_PRIVATE_KEY_342\""))));
        }
    }

    @Test
    void keepsALooseKtyInAStringAfterAValueWithARawLineBreak() {
        // #342: the leak scanner must accept this as it is.
        String text = "{\"note\":\"a\nb\",\"body\":\"" + "\"kty\":\"RSA\",\"d\":\"dimension\"".replace("\"", "\\u0022") + "\"}";
        assertEquals(text, Redactor.redact(text));
    }

    @Test
    void masksACopiedJwkBeforeAStrayQuoteAndAUnicodeEscape() {
        // #342: the leak scanner's test of the same name uses this output as its masked form.
        String after = " \"x\" \\u0041";
        assertEquals("{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"[REDACTED]\\\"}" + after,
                Redactor.redact("{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"FAKE_JWK_K_342\\\"}" + after));
    }

    @Test
    void masksAnEscapedJwkAfterAStrayQuoteAndARawLineBreak() {
        // #342: the leak scanner's escaped-JWK test uses this output as its masked form.
        for (String before : List.of("he said \"\n", "he said \"\r\n")) {
            assertEquals(before + escapedEverything("{\"kty\":\"oct\",\"k\":") + escapedEverything("\"") + "[REDACTED]"
                    + escapedEverything("\"}"),
                    Redactor.redact(before + escapedEverything("{\"kty\":\"oct\",\"k\":\"FAKE_JWK_K_342\"}")));
        }
    }

    @Test
    void masksACopiedJwkWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak() {
        // #342 (automated review on 925a782): kty quoted with \u0022 and k with \" (or the other way round). The leak
        // scanner's test of the same name uses this output as its masked form.
        String u = "\\u0022";
        String b = "\\\"";
        List<java.util.function.Function<String, String>> forms = List.of(
                v -> "{" + u + "kty" + u + ":" + u + "oct" + u + "," + b + "k" + b + ":" + b + v + b + "}",
                v -> "{" + b + "kty" + b + ":" + b + "oct" + b + "," + u + "k" + u + ":" + u + v + u + "}",
                v -> "{" + u + "kty" + u + ":" + b + "oct" + b + "," + b + "k" + b + ":" + b + v + b + "}",
                v -> "{" + b + "kty" + b + ":" + u + "oct" + u + "," + b + "k" + b + ":" + b + v + b + "}");
        for (String before : List.of("he said \"\n", "he said \"\r\n", "\"\n", "\"\r\n")) {
            for (String after : List.of("", "\"", "\" and \"x\"")) {
                for (var form : forms) {
                    assertEquals(before + form.apply("[REDACTED]") + after,
                            Redactor.redact(before + form.apply("FAKE_JWK_K_342") + after));
                }
            }
        }
    }

    @Test
    void keepsALooseKtyInACopiedValueWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak() {
        // #342 (automated review on c4ffeef and 39dd7ff): the leak scanner must accept each as it is.
        String u = "\\u0022";
        String b = "\\\"";
        List<String> before = List.of("", u + "a" + u + ":0,", u + "a" + u + ":0," + u + "b" + u + ":" + u + "x" + u + ",",
                u + "a" + u + ":{" + u + "x" + u + ":1},", u + "a" + u + ":[1," + u + "y" + u + "],");
        for (String lb : List.of("\n", "\r\n")) {
            for (String members : before) {
                String text = "he said \"" + lb + "{" + b + "body" + b + ":" + b + members + u + "kty" + u + ":" + u + "RSA" + u
                        + "," + u + "d" + u + ":" + u + "dimension" + u + b + "}";
                assertEquals(text, Redactor.redact(text));
            }
        }
    }

    @Test
    void keepsAKtyThatOpensNoMemberInACopiedValueAfterAStrayQuote() {
        // #342 (automated review on 0ab5aeb): only the first string after { or , is a member name, so a kty after a
        // value with no comma makes no JWK. The leak scanner's test of the same form uses these outputs.
        String b = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String mid : List.of("0 ", b + "a" + b + " ", "{" + b + "y" + b + ":1} ", "[1] ")) {
                String text = "he said \"" + lb + "{" + b + "x" + b + ":" + mid + b + "kty" + b + ":" + b + "RSA" + b + ","
                        + b + "d" + b + ":" + b + "dimension" + b + "}";
                assertEquals(text, Redactor.redact(text));
            }
            for (String mid : List.of("0,", "0 , ", "0, x ", "{" + b + "y" + b + ":1},", "[1],")) {
                String form = "he said \"" + lb + "{" + b + "x" + b + ":" + mid + b + "kty" + b + ":" + b + "RSA" + b + ","
                        + b + "d" + b + ":" + b + "%s" + b + "}";
                assertEquals(form.formatted("[REDACTED]"), Redactor.redact(form.formatted("FAKE_PRIVATE_KEY_342")));
            }
        }
    }

    @Test
    void keepsAKtyThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote() {
        // #342 (automated review on 380cf7c): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)),
                text -> "{\\u0022body\\u0022:\\u0022" + text.replace("\"", "\\\\u0022") + "\\u0022}");
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String mid : List.of("0 ", "\"a\" ", "{\"y\":1} ", "[1] ")) {
                    String text = "he said \"" + lb + encode.apply("{\"x\":" + mid + "\"kty\":\"RSA\",\"d\":\"dimension\"}");
                    assertEquals(text, Redactor.redact(text));
                }
                for (String mid : List.of("0,", "0, x ")) {
                    String form = "{\"x\":" + mid + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals("he said \"" + lb + encode.apply(form.formatted("[REDACTED]")),
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void keepsAKtyAfterAnOddNumberOfQuotesInAnEscapedCopyAfterAStrayQuote() {
        // #342 (automated review on 9a3e247): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String before : List.of("\"\"a\":0,", "\"a\":\"b\"c\",")) {
                    String text = "he said \"" + lb + encode.apply("{" + before + "\"kty\":\"RSA\",\"d\":\"dimension\"}");
                    assertEquals(text, Redactor.redact(text));
                }
                for (String before : List.of("\"a\":0,", "")) {
                    String form = "{" + before + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals("he said \"" + lb + encode.apply(form.formatted("[REDACTED]")),
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void keepsAPrivateMemberThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote() {
        // #342 (automated reviews on fa4fd1d and 223512b): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String mid : List.of("0 ", "\"a\" ", "{\"y\":1} ", "[1] ", "\"\"a\":0,", "\"b\"c\",")) {
                    String text = "he said \"" + lb + encode.apply("{\"kty\":\"RSA\",\"x\":" + mid + "\"d\":\"dimension\"}");
                    assertEquals(text, Redactor.redact(text));
                }
                for (String mid : List.of("0,", "0, y ", "[1],", "\"b\"c\"\",")) {
                    String form = "{\"kty\":\"RSA\",\"x\":" + mid + "\"d\":\"%s\"}";
                    assertEquals("he said \"" + lb + encode.apply(form.formatted("[REDACTED]")),
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void readsJwksInAnEscapedCopyAfterAStrayQuoteAsItsSearchFindsThem() {
        // #342 (automated review on 65e1e7f): the leak scanner's test of the same name uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String before : List.of("\"{\":\"\"a\":0,", "\"[\":\"\"a\":0,\"b\":{", "\"a\":\"{\",")) {
                    String form = "{" + before + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals("he said \"" + lb + encode.apply(form.formatted("[REDACTED]")),
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
                String colons = "he said \"" + lb + encode.apply("{\"kty\":\"RSA\",\"d\"::\"dimension\"}");
                assertEquals(colons, Redactor.redact(colons));
            }
        }
    }

    @Test
    void readsAPrivateMemberValueThroughItsLineBreaksAndOnlyAsciiWhitespaceAroundAColon() {
        // #342 (automated review on 7050fef): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"), text -> text.replace("\"", "\\\\u0022"));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String value : List.of("\\nTAIL", "\\r\\nTAIL", "\\n")) {
                    String text = "he said \"" + lb + encode.apply("{\"kty\":\"oct\",\"k\":\"" + value + "\"}");
                    assertEquals("he said \"" + lb + encode.apply("{\"kty\":\"oct\",\"k\":\"[REDACTED]\"}"), Redactor.redact(text));
                }
                for (String space : List.of("\u00a0", "\u2003", "\u3000")) {
                    for (String form : List.of("{\"kty\"" + space + ":\"oct\",\"k\":\"dimension\"}",
                            "{\"kty\":\"oct\",\"k\"" + space + ":\"dimension\"}", "{\"kty\":\"oct\",\"k\":" + space + "\"dimension\"}")) {
                        String text = "he said \"" + lb + encode.apply(form);
                        assertEquals(text, Redactor.redact(text));
                    }
                }
            }
        }
    }

    @Test
    void masksAJwkCopiedAfterTwoStrayQuotesAndEndsAValueAtABackslashBeforeALineBreak() {
        // #342 (automated review on 5173e8e): the leak scanner's test of the same form uses these outputs.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\"}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String before : List.of("he said \"" + lb + "he said \"" + lb, "he said \"" + lb + "x\"" + lb + "more" + lb, "\"" + lb + "\"" + lb)) {
                assertEquals(before + escapedForJson(jwk.formatted("[REDACTED]")),
                        Redactor.redact(before + escapedForJson(jwk.formatted("FAKE_JWK_K_342"))));
            }
            String cut = "he said \"" + lb + escapedForJson("{\"kty\":\"oct\",\"k\":\"[REDACTED]\\" + lb + "TAIL\"}");
            assertEquals(cut, Redactor.redact(cut));
        }
    }

    @Test
    void masksACopiedValueAfterABackslashAndARawUnicodeLineBreakAndReadsNoFormFeedEscapeAsWhitespace() {
        // #342 (automated review on e2487e1): the leak scanner's test of the same form relies on these outputs. A
        // backslash escaped in the copy, then a raw U+0085, U+2028 or U+2029, is part of the value, so the whole value is
        // masked; a \f escape is no whitespace in an escaped copy, so no member is found, while a \u000c is.
        String b = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            String masked = "he said \"" + lb + "{" + b + "kty" + b + ":" + b + "oct" + b + "," + b + "k" + b + ":" + b + "[REDACTED]" + b + "}";
            for (String brk : List.of("\u0085", "\u2028", "\u2029")) {
                for (String k : List.of("", "[REDACTED]")) {
                    String in = "he said \"" + lb + "{" + b + "kty" + b + ":" + b + "oct" + b + "," + b + "k" + b + ":" + b + k + "\\\\" + brk
                            + "TAIL" + b + "}";
                    assertEquals(masked, Redactor.redact(in));
                }
            }
            for (String value : List.of("true", "1", "{}", b + "FAKE_JWK_K_342" + b)) {
                for (String form : List.of("{%1$skty%1$s:%1$soct%1$s,%1$sk%1$s:\\f%2$s}", "{%1$skty%1$s:%1$soct%1$s,%1$sk%1$s\\f:%2$s}",
                        "{%1$skty%1$s\\f:%1$soct%1$s,%1$sk%1$s:%2$s}")) {
                    String kept = "he said \"" + lb + form.formatted(b, value);
                    assertEquals(kept, Redactor.redact(kept));
                }
            }
            String formFeed = "he said \"" + lb + "{" + b + "kty" + b + ":" + b + "oct" + b + "," + b + "k" + b + ":\\u000ctrue}";
            assertEquals("he said \"" + lb + "{" + b + "kty" + b + ":" + b + "oct" + b + "," + b + "k" + b + ":\\u000c" + b + "[REDACTED]" + b + "}",
                    Redactor.redact(formFeed));
        }
    }

    @Test
    void readsPastALineBreakSpelledAsAUnicodeEscapeInAValueAndMasksACopyAfterAPairedStrayString() {
        // #342 (automated review on 4175db6): the leak scanner's test of the same form relies on these outputs.
        String u = "\\u0022";
        String b = "\\\"";
        java.util.function.BiFunction<String, String, String> jwk =
                (q, k) -> "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q + k + q + "}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String q : List.of(u, b)) {
                String masked = "he said \"" + lb + jwk.apply(q, "[REDACTED]");
                for (String brk : List.of("\\u000a", "\\u000d", "\\u0085", "\\u2028", "\\u2029")) {
                    for (String k : List.of("\\u005c" + brk + "TAIL", "[REDACTED]\\u005c" + brk + "TAIL", "[REDACTED]\\\\" + brk + "TAIL")) {
                        assertEquals(masked, Redactor.redact("he said \"" + lb + jwk.apply(q, k)));
                    }
                }
                String kept = "he said \"" + lb + jwk.apply(q, "[REDACTED]\\u005c\\nTAIL");
                assertEquals(kept, Redactor.redact(kept));
            }
            for (String before : List.of("\"" + lb + "\",\"body\":", "\"" + lb + "\",\"b\":1,\"body\":", "x\"" + lb + "\",\"body\":")) {
                assertEquals(before + jwk.apply(b, "[REDACTED]"), Redactor.redact(before + jwk.apply(b, "FAKE_JWK_K_342")));
            }
        }
    }

    @Test
    void masksACopyCutOffInHalfAnEscapeAndANestOfPairedStrayStrings() {
        // #342 (automated review on 5ca573a): the leak scanner's test of the same form relies on these outputs.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\"}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\", "\\u0", "\\u00", "\\u002", "\\\\\\")) {
                String masked = "he said \"" + lb + escapedForJson(jwk.formatted("[REDACTED]")) + tail;
                assertEquals(masked, Redactor.redact("he said \"" + lb + escapedForJson(jwk.formatted("FAKE_JWK_K_342")) + tail));
                assertEquals(masked, Redactor.redact(masked));
            }
            for (int pad : List.of(500, 2000, 10000)) {
                String leaked = "{\"kty\":\"oct\",\"k\":\"FAKE_JWK_K_342\",\"pad\":\"" + "x".repeat(pad) + "\"}";
                String masked = "{\"kty\":\"oct\",\"k\":\"[REDACTED]\",\"pad\":\"" + "x".repeat(pad) + "\"}";
                for (int i = 0; i < 3; i++) {
                    leaked = "\"" + lb + "\"" + lb + escapedForJson(leaked);
                    masked = "\"" + lb + "\"" + lb + escapedForJson(masked);
                }
                assertEquals(masked, Redactor.redact(leaked));
                assertEquals(masked, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksAJwkPrivateMemberWhoseOpeningQuoteIsEscapedOneLevelMore() {
        // #342 (automated review on 32194d8): the leak scanner's test of the same form uses these outputs.
        List<String> forms = List.of("{\"kty\":\"oct\",\\\"k\":\"%1$s\"}", "{\"kty\":\"oct\", \\\"d\":\"%1$s\"}",
                "{\"kty\":\"RSA\",\"n\":\"AQAB\",\\\"d\":\"%1$s\",\\\"p\":\"%1$s\"}");
        for (String lb : List.of("\n", "\r\n")) {
            for (String form : forms) {
                String masked = "he said \"" + lb + escapedForJson(form.formatted("[REDACTED]"));
                assertEquals(masked, Redactor.redact("he said \"" + lb + escapedForJson(form.formatted("FAKE_JWK_K_342"))));
                assertEquals(masked, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksACopyThatEndsInAMalformedUnicodeEscape() {
        // #342 (automated review on 92f3ad6): the leak scanner's test of the same form uses these outputs.
        List<String> forms = List.of("{\"kty\":\"oct\",\"k\":\"%s\"}", "{\"password\":\"%s\"}");
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String form : forms) {
                    String masked = "he said \"" + lb + escapedForJson(form.formatted("[REDACTED]")) + tail;
                    assertEquals(masked, Redactor.redact("he said \"" + lb + escapedForJson(form.formatted("FAKE_JWK_K_342")) + tail));
                    assertEquals(masked, Redactor.redact(masked));
                }
            }
        }
    }

    @Test
    void readsAFormFeedEscapeAfterARepairedMalformedUnicodeEscape() {
        // #342 (automated review on a7d0f8f): the leak scanner's test of the same form relies on these outputs.
        String q = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String pre : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String value : List.of("true", q + "FAKE_JWK_K_342" + q)) {
                    String colon = "he said \"" + lb + pre + "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":\\f" + value + "}";
                    String kty = "he said \"" + lb + pre + "{" + q + "kty" + q + "\\f:" + q + "oct" + q + "," + q + "k" + q + ":" + value + "}";
                    assertEquals(colon, Redactor.redact(colon));
                    assertEquals(kty, Redactor.redact(kty));
                }
                String masked = "he said \"" + lb + pre + "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q + "[REDACTED]" + q + "}";
                assertEquals(masked, Redactor.redact(masked.replace("[REDACTED]", "FAKE_JWK_K_342")));
                assertEquals(masked, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksANestedCopyThatEndsInAMalformedUnicodeEscape() {
        // #342 (automated review on c5a0b7f): the leak scanner's test of the same form relies on these outputs.
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (int pad : List.of(1000, 2000)) {
                    String leaked = "{\"pad\":\"" + "x".repeat(pad) + "\",\"kty\":\"oct\",\"k\":\"FAKE_JWK_K_342\"}";
                    String masked = leaked.replace("FAKE_JWK_K_342", "[REDACTED]");
                    for (int i = 0; i < 3; i++) {
                        leaked = "he said \"" + lb + escapedForJson(leaked);
                        masked = "he said \"" + lb + escapedForJson(masked);
                    }
                    assertEquals(masked + tail, Redactor.redact(leaked + tail));
                    assertEquals(masked + tail, Redactor.redact(masked + tail));
                }
            }
        }
    }

    @Test
    void masksACopiedSecretValueCutOffInAMalformedUnicodeEscape() {
        // #342 (automated review on 058e89a): the leak scanner's test of the same form relies on these outputs.
        String q = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + q;
                    assertEquals(masked, Redactor.redact("he said \"" + lb + head + "[REDACTED]" + tail));
                    assertEquals(masked, Redactor.redact("he said \"" + lb + head + "FAKE_JWK_K_342" + tail));
                    assertEquals(masked, Redactor.redact(masked));
                }
            }
        }
    }

    @Test
    void masksACopiedSecretValueCutOffInHalfAUnicodeEscape() {
        // #342 (Codex security round 2 at 8a06f7e): the leak scanner's test of the same form relies on these outputs.
        // Half an escape inside a value still open at the end is masked with it; after a closed value it is kept.
        String q = "\\\"";
        for (String tail : List.of("\\u", "\\u0", "\\u00", "\\u005")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + q;
                    assertEquals(masked, Redactor.redact("he said \"" + lb + head + "[REDACTED]" + tail));
                    assertEquals(masked, Redactor.redact("he said \"" + lb + head + tail));
                    assertEquals(masked + tail, Redactor.redact(masked + tail));
                    assertEquals(masked + "}" + tail, Redactor.redact(masked + "}" + tail));
                }
            }
            for (String head : List.of("{\"kty\":\"oct\",\"k\":\"", "{\"password\":\"")) {
                assertEquals(head + "[REDACTED]\"", Redactor.redact(head + "[REDACTED]" + tail));
                assertEquals(head + "[REDACTED]\"}" + tail, Redactor.redact(head + "[REDACTED]\"}" + tail));
            }
        }
    }

    @Test
    void keepsACopiedValueCutOffInHalfAUnicodeEscapeAfterAnEscapedBackslash() {
        // #342 (automated review on b9d6038): the leak scanner's test of the same form relies on these outputs. An
        // escaped backslash before half an escape at the end leaves the cut value unmatched, so the text is kept.
        String q = "\\\"";
        String b = "\\\\";
        for (String tail : List.of("\\u", "\\u0", "\\u005")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + b + tail;
                    assertEquals(masked, Redactor.redact(masked));
                    String empty = "he said \"" + lb + head + b + tail;
                    assertEquals(empty, Redactor.redact(empty));
                }
            }
        }
    }

    @Test
    void masksACopiedSecretFieldCutOffInHalfAUnicodeEscapeAfterAUnicodeBackslash() {
        // #342 (automated review on 73e4411): the leak scanner's test of the same form relies on these outputs. A
        // backslash spelled as a unicode escape before half an escape at the end is masked with a secret field's value;
        // the JWK search matches no k member there, and the text is kept.
        String q = "\\\"";
        for (String backslash : List.of("\\u005c", "\\u005C")) {
            for (String tail : List.of("\\u", "\\u0", "\\u005")) {
                for (String lb : List.of("\n", "\r\n")) {
                    String secret = "he said \"" + lb + "{" + q + "password" + q + ":" + q;
                    assertEquals(secret + "[REDACTED]" + q, Redactor.redact(secret + "[REDACTED]" + backslash + tail));
                    assertEquals(secret + "[REDACTED]" + q, Redactor.redact(secret + backslash + tail));
                    String jwk = "he said \"" + lb + "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q;
                    assertEquals(jwk + "[REDACTED]" + backslash + tail, Redactor.redact(jwk + "[REDACTED]" + backslash + tail));
                    assertEquals(jwk + backslash + tail, Redactor.redact(jwk + backslash + tail));
                }
            }
        }
    }

    @Test
    void masksACopiedJwkWithMixedQuoteEscapesAfterAnEscapedQuoteInAValue() {
        // #342: the leak scanner's test of the same name uses this output as its masked form.
        String u = "\\u0022";
        String b = "\\\"";
        String escapedQuote = "\\\\\\\"";
        List<java.util.function.Function<String, String>> forms = List.of(
                k -> "{" + u + "note" + u + ":" + u + "a" + escapedQuote + "b" + u + "," + b + "kty" + b + ":" + b + "oct" + b + ","
                        + b + "k" + b + ":" + b + k + b + "}",
                k -> "{" + b + "note" + b + ":" + b + "a" + escapedQuote + "b" + b + "," + u + "kty" + u + ":" + u + "oct" + u + ","
                        + b + "k" + b + ":" + b + k + b + "}");
        for (String lb : List.of("\n", "\r\n")) {
            for (var form : forms) {
                String before = "he said \"" + lb;
                assertEquals(before + form.apply("[REDACTED]"), Redactor.redact(before + form.apply("FAKE_JWK_K_342")));
            }
        }
    }

    @Test
    void masksACopiedSecretFieldWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak() {
        // #342: the leak scanner's test of the same name uses this output as its masked form.
        String u = "\\u0022";
        String b = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String name : List.of("password", "client_secret", "access_token", "authorization")) {
                String before = "he said \"" + lb;
                assertEquals(before + "{" + u + "a" + u + ":1," + b + name + b + ":" + b + "[REDACTED]" + b + "}",
                        Redactor.redact(before + "{" + u + "a" + u + ":1," + b + name + b + ":" + b + "FAKE_SECRET_342" + b + "}"));
                assertEquals(before + "{" + b + name + b + ":" + b + "[REDACTED]" + b + "}",
                        Redactor.redact(before + "{" + b + name + b + ":" + b + "FAKE_SECRET_342" + u + "}"));
            }
        }
    }

    @Test
    void keepsALoosePrivateMemberNextToMaskedJwks() {
        // Automated review on 26f8c2b: two masked RSA JWKs and a sibling "d" in no JWK. The JWK search reads a few
        // hundred characters of its 4n + 1024, so "d" is kept. The leak scanner's r8 test uses this as an accepted form.
        String jwk = "{\"kty\":\"RSA\",\"kid\":\"%s\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
                + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA".repeat(4) + "\",\"e\":\"AQAB\",\"d\":\"[REDACTED]\","
                + "\"p\":\"[REDACTED]\",\"q\":\"[REDACTED]\",\"dp\":\"[REDACTED]\",\"dq\":\"[REDACTED]\",\"qi\":\"[REDACTED]\"}";
        String text = "{\"keys\":[" + jwk.formatted("a") + "," + jwk.formatted("b") + "],\"d\":\"dimension\"}";
        List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
        for (String form : List.of(text, nested(text))) {
            assertEquals(form, Redactor.redact(form, reads));
        }
        assertTrue(reads.stream().allMatch(read -> read.after() >= 0), reads::toString);
    }

    @Test
    void keepsALoosePrivateMemberNextToMaskedJwksCopiedAfterAStrayQuoteAndARawLineBreak() {
        // #342: the r8 text copied with \" (or \" and \u0022 mixed) after a stray quote and a raw line break. The JWK
        // search still cannot spend its budget, so "d" is kept; an unmasked private member is masked. The leak
        // scanner's test of the same name uses these as accepted forms.
        String jwk = "{\"kty\":\"RSA\",\"kid\":\"%s\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
                + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA".repeat(4) + "\",\"e\":\"AQAB\",\"d\":\"[REDACTED]\","
                + "\"p\":\"[REDACTED]\",\"q\":\"[REDACTED]\",\"dp\":\"[REDACTED]\",\"dq\":\"[REDACTED]\",\"qi\":\"[REDACTED]\"}";
        java.util.function.UnaryOperator<String> u = t -> t.replace("\"", "\\u0022");
        java.util.function.UnaryOperator<String> b = t -> t.replace("\"", "\\\"");
        String head = "{\"keys\":[" + jwk.formatted("a") + ",";
        String tail = jwk.formatted("b") + "],\"d\":\"dimension\"}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String copied : List.of(b.apply(head + tail), u.apply(head) + b.apply(tail), b.apply(head) + u.apply(tail))) {
                String text = "he said \"" + lb + copied;
                assertEquals(text, Redactor.redact(text));
                assertEquals(text, Redactor.redact(text.replaceFirst("\\[REDACTED]", "FAKE_PRIVATE_KEY_342")));
            }
        }
    }

    @Test
    void masksAJwkCopiedAfterAStrayQuoteAndARawLineBreakNestedEightDeep() {
        // #342: the leak scanner's test reading this form within its scan budget uses this output as its masked form.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\",\"pad\":\"" + "x".repeat(100) + "\"}";
        for (String lb : List.of("\n", "\r\n")) {
            String masked = jwk.formatted("[REDACTED]");
            String leaked = jwk.formatted("FAKE_JWK_K_342");
            for (int i = 0; i < 8; i++) {
                masked = "he said \"" + lb + escapedForJson(masked);
                leaked = "he said \"" + lb + escapedForJson(leaked);
            }
            assertEquals(masked, Redactor.redact(masked));
            assertEquals(masked, Redactor.redact(leaked));
        }
    }

    @Test
    void masksAJwkWithALongPadCopiedAfterAStrayQuoteNestedThreeDeep() {
        // #342, Codex security round 1 at 0ab5aeb: the leak scanner's test reading this form within its scan budget uses
        // this output as its masked form.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\",\"pad\":\"" + "x".repeat(2000) + "\"}";
        for (String lb : List.of("\n", "\r\n")) {
            String masked = jwk.formatted("[REDACTED]");
            String leaked = jwk.formatted("FAKE_JWK_K_342");
            for (int i = 0; i < 3; i++) {
                masked = "he said \"" + lb + escapedForJson(masked);
                leaked = "he said \"" + lb + escapedForJson(leaked);
            }
            assertEquals(masked, Redactor.redact(masked));
            assertEquals(masked, Redactor.redact(leaked));
        }
    }

    @Test
    void masksAJwkAfterALongPadCopiedAndClosedThreeDeep() {
        // #342 (automated review on feb555e): the leak scanner's test reading this form within its scan budget uses this
        // output as its masked form.
        String jwk = "{\"pad\":\"" + "x".repeat(5000) + "\",\"kty\":\"oct\",\"k\":\"%s\"}";
        for (String lb : List.of("\n", "\r\n")) {
            String masked = jwk.formatted("[REDACTED]");
            String leaked = jwk.formatted("FAKE_JWK_K_342");
            for (int i = 0; i < 3; i++) {
                masked = "he said \"" + lb + escapedForJson(masked) + "\"";
                leaked = "he said \"" + lb + escapedForJson(leaked) + "\"";
            }
            assertEquals(masked, Redactor.redact(masked));
            assertEquals(masked, Redactor.redact(leaked));
        }
    }

    @Test
    void readsJwksAfterPrivateKeyBlocksWithinTheBudgetLeft() {
        // Codex round 7, finding 2: the JWK read after the key blocks are masked spends what the read of the text as it
        // came left at each escape level, 4n + 1024 in all for a text of length n, and masks every private member name
        // once that is spent. Each case below has a block, so the JWKs are read a second time.
        String block = "-----BEGIN PRIVATE KEY-----\"-----END PRIVATE KEY-----";
        String jwk = "{\"kty\":\"RSA\",\"note\":\"" + block + "\",\"d\":\"FAKE_PRIVATE_KEY_293\"}";
        // 20 repetitions spend about 1,330 of the 1,836 characters the first plain read has, and as much again on the
        // second: with a fresh budget that read is never spent, and the loose p (in no object) is kept.
        String spentOnTheSecondRead = "\"kty\":\"".repeat(20) + block + "\"p\":\"FAKE_PRIVATE_KEY_293\"";
        // 63 repetitions spend all of it on the first read, before any block is masked.
        String spentOnTheFirstRead = "\"kty\":\"".repeat(63) + block + "\"d\":\"FAKE_PRIVATE_KEY_293\"";
        for (String raw : List.of(jwk, spentOnTheSecondRead, spentOnTheFirstRead)) {
            for (String text : List.of(raw, nested(raw), nested(nested(raw)))) {
                List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
                String out = Redactor.redact(text, reads);
                assertFalse(out.contains("FAKE_PRIVATE_KEY_293"), () -> text + "\n became " + out);
                int allowance = 4 * text.length() + 1024;
                Map<String, Integer> left = new LinkedHashMap<>();
                for (Redactor.DiscoveryRead read : reads) {
                    Integer before = left.get(read.level());
                    if (before == null && read.level().startsWith("nested")) {
                        // A nested level's view is no longer than the text.
                        assertTrue(read.before() <= allowance, () -> read + " in " + reads);
                    } else if (before == null) {
                        assertEquals(allowance, read.before(), () -> read + " in " + reads);
                    } else {
                        assertEquals(before, read.before(), () -> "a fresh budget for a second read: " + reads);
                    }
                    left.put(read.level(), read.after());
                }
                assertEquals(2, reads.stream().filter(read -> read.level().equals("plain")).count(), reads::toString);
            }
        }
        List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
        Redactor.redact(spentOnTheFirstRead, reads);
        assertTrue(reads.stream().filter(read -> read.level().equals("plain")).allMatch(read -> read.after() < 0), reads::toString);
    }

    @Test
    void masksALoosePrivateMemberAfterALongKeyBlockAs027fe1eDid() {
        // Codex narrow check at 3c47acc, finding 1: the first read keeps the loose d (63 kty names spend about 13,700
        // of its 43,100 characters), then masking the 10,000-character block leaves a 531-character text. 027fe1e read
        // that with 4 x 531 + 1024 = 3,148, spent it and masked d; the second read must get no more than that.
        String key = "\"kty\":\"".repeat(63) + "\"d\":\"FAKE_PRIVATE_KEY_293\"" + "-----BEGIN PRIVATE KEY-----"
                + "X".repeat(10_000) + "-----END PRIVATE KEY-----";
        String pgp = key.replace("PRIVATE KEY-----", "PGP PRIVATE KEY BLOCK-----");
        // What 027fe1e made of the two raw inputs.
        assertEquals("\"kty\":\"".repeat(63) + "\"d\":\"[REDACTED]\"-----BEGIN PRIVATE KEY-----\n[REDACTED]\n"
                + "-----END PRIVATE KEY-----", Redactor.redact(key));
        assertEquals("\"kty\":\"".repeat(63) + "\"d\":\"[REDACTED]\"-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED]\n"
                + "-----END PGP PRIVATE KEY BLOCK-----", Redactor.redact(pgp));
        // Embedded forms that keep the value and the block's header literal, so the second read runs at an escaped
        // level; each was masked on 027fe1e and kept on 3c47acc.
        List<org.junit.jupiter.api.function.Executable> embedded = new java.util.ArrayList<>();
        for (String raw : List.of(key, pgp)) {
            for (String in : List.of(nested(raw), nested(nested(raw)), nestedEscapingQuotes(raw),
                    nestedEscapingBackslashes(raw), nestedEscapingQuotes(nested(raw)))) {
                assertTrue(in.contains("FAKE_PRIVATE_KEY_293"));
                embedded.add(() -> {
                    String out = Redactor.redact(in);
                    assertFalse(out.contains("FAKE_PRIVATE_KEY_293"), () -> in.substring(0, 80) + "\n became " + out.substring(0, 80));
                });
            }
        }
        org.junit.jupiter.api.Assertions.assertAll(embedded);
    }

    @Test
    void masksManyPrivateKeyBlocksInLinearTime() {
        // The automated review on ac1759e: 16,000 terminated private key blocks (about 900 KB) took 14 s there, each
        // search for an unterminated header reading on to the end of the text. 64,000 (about 4 MB) take well under
        // a second in linear time.
        String block = "-----BEGIN PRIVATE KEY-----\\nFAKEKEY\\n-----END PRIVATE KEY-----";
        String text = block.repeat(64_000) + "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nFAKETAIL";
        String out = assertTimeoutPreemptively(Duration.ofSeconds(4), () -> Redactor.redact(text));
        assertFalse(out.contains("FAKEKEY"), out.substring(0, 200));
        assertTrue(out.endsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED]"), out.substring(out.length() - 80));
    }

    @Test
    void masksAChainPastTheNestingCapWhoseStringIsQuotedWithUnicodeEscapes() {
        // Codex security round 5: past NESTED_LEVELS, a string whose quotes are spelled \\u0022 in the text has no
        // bare quote to find it by; 6304ec0 masked it, and so must the fallback now.
        String quote = "\\u005c" + "u005c".repeat(40) + "u0022";
        String jwk = "{" + quote + "kty" + quote + ":" + quote + "oct" + quote + "," + quote + "k" + quote + ":" + quote
                + "PRIVATECHAINVALUE" + quote + "}";
        for (String in : List.of("\\u0022" + jwk + "\\u0022", "{\\u0022body\\u0022:\\u0022" + jwk + "\\u0022}",
                "\\u005cu0022" + jwk + "\\u005cu0022")) {
            String out = Redactor.redact(in);
            assertFalse(out.contains("PRIVATECHAINVALUE"), () -> in.substring(0, 40) + " became " + out.substring(0, Math.min(80, out.length())));
            assertTrue(out.length() <= in.length());
        }
    }

    @Test
    void masksBothPrivateMembersThatShareAQuoteOnceTheBudgetIsSpent() {
        // d's empty value closes on the quote that opens p: masking d must not skip p's value.
        assertEquals("{\"d\":\"[REDACTED]\"p\":\"[REDACTED]\",\"kty\":\"RSA\"}",
                Redactor.maskJwks("{\"d\":\"\"p\":\"PRIVP\",\"kty\":\"RSA\"}", false, 0));
        assertEquals("{\\\"d\\\":\\\"[REDACTED]\\\"p\\\":\\\"[REDACTED]\\\",\\\"kty\\\":\\\"RSA\\\"}",
                Redactor.maskJwks("{\\\"d\\\":\\\"\\\"p\\\":\\\"PRIVP\\\",\\\"kty\\\":\\\"RSA\\\"}", true, 0));
        // The review's shape: 63 repeated kty members spend the budget.
        String out = Redactor.redact("\"kty\":\"".repeat(63) + "{\"d\":\"\"p\":\"PRIVP\",\"kty\":\"RSA\"}");
        assertFalse(out.contains("PRIVP"), out);
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
