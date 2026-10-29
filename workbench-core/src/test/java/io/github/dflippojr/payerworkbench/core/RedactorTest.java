package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
                "{\"b\":\"" + "[".repeat(n / 2) + "\\\"kty\\\":1],".repeat(n / 2) + "\"}");
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(Redactor::redact));
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
    void masksTokenAndDPoPCredentials() {
        assertEquals("Token [REDACTED]", Redactor.redact("Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"));
        assertEquals("DPoP " + Redactor.MASK, Redactor.redact("DPoP PHNhbWw6QXNz"));
        assertEquals("{\"error_description\":\"rejected token [REDACTED]\"}",
                Redactor.redact("{\"error_description\":\"rejected token gho_SynthTok123:x\"}"));
        assertEquals("Bearer [REDACTED]", Redactor.redact("Bearer --------"));
        // Eight characters count before a prose colon is dropped.
        assertEquals("Token [REDACTED]", Redactor.redact("Token -------:"));
        assertEquals("sent dpop [REDACTED], twice", Redactor.redact("sent dpop eyJhbGciOiJFUzI1NiJ9.e30.SIG, twice"));
        // Prose, as after Bearer; after Token a word may end with a colon (token endpoint: <url>).
        for (String text : List.of("Token expired.", "DPoP proof required", "the access token was revoked",
                "token endpoint: https://payer.example/token\ntoken response: error=invalid_client",
                "POST https://payer.example/oauth/token -> HTTP 401 in 12 ms")) {
            assertEquals(text, Redactor.redact(text));
        }
    }

    @Test
    void masksAUrlEncodedBearerCredential() {
        assertEquals("Bearer " + Redactor.MASK, Redactor.redact("Bearer%20abc123def"));
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

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String b64url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
