package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.github.dflippojr.payerworkbench.core.Canonical.assertKept;
import static io.github.dflippojr.payerworkbench.core.Canonical.assertRedactsTo;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
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
        // The block is masked whole, its armor too (#377 criterion 2: no armor header in the Redactor's output).
        assertEquals("credential file contents:\n" + Redactor.MASK + "\ntrailing text", out);
    }

    @Test
    void masksTruncatedPemPrivateKey() {
        String body = randomToken() + randomToken();
        String out = Redactor.redact("-----BEGIN EC PRIVATE KEY-----\n" + body);

        assertFalse(out.contains(body));
        assertEquals(Redactor.MASK, out);
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
            assertKept(text);
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
        assertKept(text);
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
        // A lone backslash at the end, or before the line break that starts a note on a cut body. A value no strict reading
        // reads to its end has an unknown end, so the note goes with it (Codex round 5 on 8e6f207, fail closed).
        assertEquals("{\"access_token\":\"[REDACTED]\"", Redactor.redact("{\"access_token\":\"FAKE-CREDENTIAL-1\\"));
        assertEquals("{\"access_token\":\"[REDACTED]\"",
                Redactor.redact("{\"access_token\":\"FAKE-CREDENTIAL-1\\\n[note]"));
        // Embedded JSON: one or three backslashes left, or an inner escape cut before the JSON was quoted.
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"",
                Redactor.redact("{\"debug\":\"{\\\"access_token\\\":\\\"FAKE-CREDENTIAL-1\\"));
        assertEquals("{\"debug\":\"{\\\"access_token\\\":\\\"[REDACTED]\\\"",
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
        assertKept(text);
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
            assertRedactsTo("{\"echo\":\"Bearer [REDACTED]\"}", "{\"echo\":\"Bearer" + separator + "SecretTokenValue99\"}", separator);
            assertRedactsTo("{\"echo\":\"Basic [REDACTED]\"}", "{\"echo\":\"Basic" + separator + "c3ludGhjbGllbnQ6U3ludGg\"}", separator);
            assertRedactsTo("{\"echo\":\"Authorization: Bearer [REDACTED]\"}", "{\"echo\":\"Authorization: Bearer" + separator + "SecretTokenValue99\"}", separator);
            assertRedactsTo("{\"echo\":\"rejected bearer [REDACTED], twice\"}", "{\"echo\":\"rejected bearer" + separator + "Ab12\\/SecretRemainder99, twice\"}", separator);
        }
        // In JSON quoted inside a JSON string.
        assertRedactsTo("{\"debug\":\"{\\\"e\\\":\\\"Bearer [REDACTED]\\\"}\"}", "{\"debug\":\"{\\\"e\\\":\\\"Bearer\\\\tSecretTokenValue99\\\"}\"}");
        // After Token and DPoP, only an escaped space or tab, as only a real space or tab is.
        for (String separator : List.of("\\t", "\\u0020", "\\u0009", "\\\\t", "\\\\u0020", " \\t")) {
            assertRedactsTo("{\"echo\":\"Token [REDACTED]\"}", "{\"echo\":\"Token" + separator + "9944b09199c62bcf9418\"}", separator);
            assertRedactsTo("{\"echo\":\"rejected DPoP [REDACTED]\"}", "{\"echo\":\"rejected DPoP" + separator + "PHNhbWw6QXNzZXJ0aW9u\"}", separator);
        }
        for (String separator : List.of("\\n", "\\r", "\\u000A", "\\u000D", "\\r\\n", "\\\\n")) {
            String text = "{\"m\":\"issue a token" + separator + "2 times per hour; DPoP" + separator + "proof-v2 required\"}";
            assertKept(text, separator);
        }
    }

    @Test
    void masksACredentialAfterAJsonEscapedFormFeedOrVerticalTab() {
        // Java's \s also takes a form feed and a vertical tab after Bearer or Basic, so their JSON escapes are the
        // separator too: \f, and the six-character escapes 000C and 000B in either case; also escaped again, and
        // mixed with other separators (#212, Codex round 1).
        for (String separator : List.of("\\f", "\\u000C", "\\u000c", "\\u000B", "\\u000b", "\\\\f", "\\\\u000C",
                "\\t\\f", "\\f\\n", " \\f", "\\u000b\\u0020")) {
            assertRedactsTo("{\"echo\":\"Bearer [REDACTED]\"}", "{\"echo\":\"Bearer" + separator + "SecretTokenValue99\"}", separator);
            assertRedactsTo("{\"echo\":\"Basic [REDACTED]\"}", "{\"echo\":\"Basic" + separator + "c3ludGhjbGllbnQ6U3ludGg\"}", separator);
            assertRedactsTo("{\"echo\":\"Authorization: Bearer [REDACTED]\"}", "{\"echo\":\"Authorization: Bearer" + separator + "SecretTokenValue99\"}", separator);
            assertRedactsTo("{\"echo\":\"rejected bearer [REDACTED], twice\"}", "{\"echo\":\"rejected bearer" + separator + "Ab12\\/SecretRemainder99, twice\"}", separator);
            assertRedactsTo("{\"echo\":\"rejected bearer [REDACTED], twice\"}", "{\"echo\":\"rejected bearer" + separator + "Ab12\\u002BSecretRemainder99, twice\"}", separator);
        }
        // In JSON quoted inside a JSON string.
        assertRedactsTo("{\"debug\":\"{\\\"e\\\":\\\"Bearer [REDACTED]\\\"}\"}", "{\"debug\":\"{\\\"e\\\":\\\"Bearer\\\\fSecretTokenValue99\\\"}\"}");
        // After Token and DPoP only a space or tab separates, so an escaped form feed or vertical tab does not.
        for (String separator : List.of("\\f", "\\u000C", "\\u000b")) {
            String text = "{\"m\":\"issue a token" + separator + "2 times per hour; DPoP" + separator + "proof-v2 required\"}";
            assertKept(text, separator);
        }
        // Prose and challenge parameters after one stay as they are.
        for (String text : List.of("{\"m\":\"Missing bearer\\ftoken\"}", "{\"m\":\"Basic\\u000Cplan\"}",
                "{\"h\":\"Bearer\\frealm=\\\"synthetic\\\", error=\\\"invalid_token\\\"\"}")) {
            assertKept(text);
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
            assertKept(text);
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
            assertKept(text);
        }
    }

    @Test
    void masksJwkMembersWhoseNamesAreSpelledWithEscapes() {
        // JSON may spell any character of a member name as a \\u escape, in either hex case: "kt\\u0079" is
        // kty and "\\u0064" is d.
        assertRedactsTo("{\"kt\\u0079\":\"RSA\",\"n\":\"N1\",\"d\":\"[REDACTED]\"}", "{\"kt\\u0079\":\"RSA\",\"n\":\"N1\",\"d\":\"PRIVD\"}");
        assertRedactsTo("{\"kty\":\"RSA\",\"\\u0064\":\"[REDACTED]\",\"\\u0064p\":\"[REDACTED]\",\"n\":\"N1\"}", "{\"kty\":\"RSA\",\"\\u0064\":\"PRIVD\",\"\\u0064p\":\"PRIVDP\",\"n\":\"N1\"}");
        assertRedactsTo("{\"\\u006B\\u0074\\u0079\":\"oct\",\"\\u006b\":\"[REDACTED]\"}", "{\"\\u006B\\u0074\\u0079\":\"oct\",\"\\u006b\":\"PRIVK\"}");
        assertRedactsTo("{\"kty\":\"RSA\",\"\\u006fth\":\"[REDACTED]\"}", "{\"kty\":\"RSA\",\"\\u006fth\":[{\"r\":\"PRIVR\"}]}");
        assertRedactsTo("{\"keys\":[{\"k\\u0074y\":\"oct\",\"\\u006B\":\"[REDACTED]\"}]}", "{\"keys\":[{\"k\\u0074y\":\"oct\",\"\\u006B\":\"PRIVK\"}]}");
        // In JSON embedded in a JSON string the inner escape's backslash is escaped (\\\\u0064), or the
        // outer string spells the letter itself (\\u0064).
        assertRedactsTo("{\"body\":\"{\\\"kt\\\\u0079\\\":\\\"RSA\\\",\\\"\\\\u0064\\\":\\\"[REDACTED]\\\"}\"}", "{\"body\":\"{\\\"kt\\\\u0079\\\":\\\"RSA\\\",\\\"\\\\u0064\\\":\\\"PRIVD\\\"}\"}");
        assertRedactsTo("{\"body\":\"{\\\"kt\\u0079\\\":\\\"RSA\\\",\\\"\\u0064\\\":\\\"[REDACTED]\\\"}\"}", "{\"body\":\"{\\\"kt\\u0079\\\":\\\"RSA\\\",\\\"\\u0064\\\":\\\"PRIVD\\\"}\"}");
        // Once the budget is spent, every private member name is found, also spelled with escapes.
        assertEquals("{\"\\u0064\":\"[REDACTED]\",\"kty\":\"RSA\"}",
                Redactor.maskJwks("{\"\\u0064\":\"PRIVD\",\"kty\":\"RSA\"}", false, 0));
        assertEquals("{\\\"\\\\u0064\\\":\\\"[REDACTED]\\\",\\\"kty\\\":\\\"RSA\\\"}",
                Redactor.maskJwks("{\\\"\\\\u0064\\\":\\\"PRIVD\\\",\\\"kty\\\":\\\"RSA\\\"}", true, 0));
        // Without kty the names stay, and an escaped backslash is not an escape: "\\\\u0064" is not d.
        for (String text : List.of("{\"\\u0064\":\"x\"}", "{\"kty\":\"RSA\",\"\\\\u0064\":\"x\"}",
                "{\"\\\\u006bty\":\"RSA\",\"d\":\"x\"}")) {
            assertKept(text);
        }
    }

    @Test
    void masksSecretFieldsWhoseNamesAreSpelledWithEscapes() {
        assertRedactsTo("{\"client_s\\u0065cret\":\"[REDACTED]\"}", "{\"client_s\\u0065cret\":\"PRIVS\"}");
        assertRedactsTo("{\"body\":\"{\\\"client_s\\\\u0065cret\\\":\\\"[REDACTED]\\\"}\"}", "{\"body\":\"{\\\"client_s\\\\u0065cret\\\":\\\"PRIVS\\\"}\"}");
        assertRedactsTo("{\"private_k\\u0065y\":\"[REDACTED]\"}", "{\"private_k\\u0065y\":{\"kty\":\"oct\"}}");
        // An Authorization-style name keeps the scheme, also spelled with an escape.
        assertRedactsTo("{\"\\u0041uthorization\":\"SCRAM-SHA-256 [REDACTED]\"}", "{\"\\u0041uthorization\":\"SCRAM-SHA-256 PRIVSCRAM\"}");
    }

    /** The length unit of the smaller size that {@link #findsJwksInLinearTime} times. */
    private static final int SMALL = 1_000;
    /** Samples per size in {@link #findsJwksInLinearTime}: each shape keeps its fastest. */
    private static final int SAMPLES = 5;
    /** Shortest timed run in {@link #findsJwksInLinearTime}, so that a fast shape is not timed as clock noise. */
    private static final long MIN_SAMPLE_NANOS = 1_000_000L;
    /** Growth in time allowed per doubling of length: linear growth doubles the time, quadratic quadruples it. */
    private static final double MAX_GROWTH_PER_DOUBLING = 2.5;

    /**
     * Guards against a quadratic regression in the JWK search: redaction must take time that grows about linearly
     * with the length of the text. Each shape of {@link #linearTimeShapes} is timed at {@link #SMALL} and at eight
     * times that length, in this JVM after warm-up. Its growth is the exponent of the time ratio over the length
     * ratio, 1 for linear and 2 for quadratic, and it must stay below log2 of {@link #MAX_GROWTH_PER_DOUBLING}. The
     * check uses the CPU time of this thread and the ratio of two sizes, so a busy machine does not change the
     * result; the timeout only ends a hang and is not a speed claim.
     */
    @Test
    void findsJwksInLinearTime() {
        List<String> small = linearTimeShapes(SMALL);
        List<String> large = linearTimeShapes(8 * SMALL);
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2),
                () -> growthBeyondLinear(small, large));
        assertTrue(tooSlow.isEmpty(), "time grows more than " + MAX_GROWTH_PER_DOUBLING + " times per doubling of the text: "
                + tooSlow);
    }

    /** The shapes that {@link #findsJwksInLinearTime} times, in order, and the ones whose time grows too fast. */
    private static List<String> growthBeyondLinear(List<String> small, List<String> large) {
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        for (int shape = 0; shape < small.size(); shape++) {
            cpuNanosPerRun(threads, small.get(shape));
            cpuNanosPerRun(threads, large.get(shape));
        }
        double[] smallNanos = new double[small.size()];
        double[] largeNanos = new double[small.size()];
        Arrays.fill(smallNanos, Double.MAX_VALUE);
        Arrays.fill(largeNanos, Double.MAX_VALUE);
        for (int sample = 0; sample < SAMPLES; sample++) {
            for (int shape = 0; shape < small.size(); shape++) {
                smallNanos[shape] = Math.min(smallNanos[shape], cpuNanosPerRun(threads, small.get(shape)));
                largeNanos[shape] = Math.min(largeNanos[shape], cpuNanosPerRun(threads, large.get(shape)));
            }
        }
        double maxExponent = Math.log(MAX_GROWTH_PER_DOUBLING) / Math.log(2);
        List<String> tooSlow = new ArrayList<>();
        for (int shape = 0; shape < small.size(); shape++) {
            double lengthRatio = (double) large.get(shape).length() / small.get(shape).length();
            double timeRatio = largeNanos[shape] / smallNanos[shape];
            double exponent = Math.log(timeRatio) / Math.log(lengthRatio);
            if (exponent >= maxExponent) {
                tooSlow.add(String.format(Locale.ROOT, "shape %d (time x%.1f over length x%.1f, exponent %.2f)",
                        shape + 1, timeRatio, lengthRatio, exponent));
            }
        }
        return tooSlow;
    }

    /** CPU nanoseconds of one {@link Redactor#redact} of {@code text}, averaged over runs of at least {@link #MIN_SAMPLE_NANOS}. */
    private static double cpuNanosPerRun(ThreadMXBean threads, String text) {
        long start = threads.getCurrentThreadCpuTime();
        int runs = 0;
        long elapsed;
        do {
            Redactor.redact(text);
            runs++;
            elapsed = threads.getCurrentThreadCpuTime() - start;
        } while (elapsed < MIN_SAMPLE_NANOS);
        return (double) elapsed / runs;
    }

    /** The shapes that {@link #findsJwksInLinearTime} times, each made of about {@code n} units of its pattern. */
    private static List<String> linearTimeShapes(int n) {
        // distinctBackslashCounts(k) is about k * k characters long, so k grows with the root of n.
        int k = (int) Math.round(3.5 * Math.sqrt(n));
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
                "{\"b\":\"" + "\\".repeat(13 * n) + "\\\"kty\\\":1\"}",
                // Members each quoted with a different number of backslashes after a kty (Codex security round 2),
                // bare and as a recorded body in a report: every search is charged to its level's budget.
                distinctBackslashCounts(k), nested(distinctBackslashCounts(k)));
        return texts;
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
        assertRedactsTo("{\"body\":\"{\\u0022kty\\u0022:\\u0022oct\\u0022,\\u0022k\\u0022:\\u0022[REDACTED]\\u0022}\"}", "{\"body\":\"{\\u0022kty\\u0022:\\u0022oct\\u0022,\\u0022k\\u0022:\\u0022PRIVK\\u0022}\"}");
        assertRedactsTo("{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\u0022k\\u0022:\\u0022[REDACTED]\\u0022}\"}", "{\"body\":\"{\\\"kty\\\":\\\"oct\\\",\\u0022k\\u0022:\\u0022PRIVK\\u0022}\"}");
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
        assertRedactsTo(plain, plain);
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
        assertRedactsTo("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_secret\\\\\\\":\\\\\\\"[REDACTED]\\\\\\\"}\\\"}\"}", "{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"client_secret\\\\\\\":\\\\\\\"s3cr3t\\\\\\\"}\\\"}\"}");
        // Three levels deep, \\\\\\\" quotes.
        assertRedactsTo("{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"c\\\\\\\":\\\\\\\"{\\\\\\\\\\\\\\\"client_secret\\\\\\\\\\\\\\\":"
                        + "\\\\\\\\\\\\\\\"[REDACTED]\\\\\\\\\\\\\\\"}\\\\\\\"}\\\"}\"}", "{\"a\":\"{\\\"b\\\":\\\"{\\\\\\\"c\\\\\\\":\\\\\\\"{\\\\\\\\\\\\\\\"client_secret\\\\\\\\\\\\\\\":"
                        + "\\\\\\\\\\\\\\\"s3cr3t\\\\\\\\\\\\\\\"}\\\\\\\"}\\\"}\"}");
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
            assertRedactsTo(masked, json);
            String in = json;
            String out = masked;
            for (int depth = 1; depth <= 4; depth++) {
                in = nested(in);
                out = nested(out);
                assertRedactsTo(out, in, "depth " + depth + ": " + json);
            }
        }
    }

    @Test
    void masksSecretFieldsWhoseEmbeddedJsonIsSpelledWithUnicodeEscapes() {
        // #339: quotes spelled \\u0022, in a JSON string and at the top level (text copied from inside a string).
        assertRedactsTo("{\"a\":\"{\\u0022client_secret\\u0022:\\u0022[REDACTED]\\u0022}\"}", "{\"a\":\"{\\u0022client_secret\\u0022:\\u0022s3cr3t\\u0022}\"}");
        assertRedactsTo("{\\u0022client_secret\\u0022:\\u0022[REDACTED]\\u0022}", "{\\u0022client_secret\\u0022:\\u0022s3cr3t\\u0022}");
        // A level written with \" inside a level written with \\u0022, and the reverse.
        assertRedactsTo("{\"a\":\"{\\u0022b\\u0022:\\u0022{\\\\\\\"client_secret\\\\\\\":\\\\\\\"[REDACTED]\\\\\\\"}\\u0022}\"}", "{\"a\":\"{\\u0022b\\u0022:\\u0022{\\\\\\\"client_secret\\\\\\\":\\\\\\\"s3cr3t\\\\\\\"}\\u0022}\"}");
        assertRedactsTo("{\"a\":\"{\\\"b\\\":\\\"{\\\\u0022client_secret\\\\u0022:\\\\u0022[REDACTED]\\\\u0022}\\\"}\"}", "{\"a\":\"{\\\"b\\\":\\\"{\\\\u0022client_secret\\\\u0022:\\\\u0022s3cr3t\\\\u0022}\\\"}\"}");
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
            assertRedactsTo(masked, json);
            for (UnaryOperator<String> a : levels) {
                for (UnaryOperator<String> b : levels) {
                    for (UnaryOperator<String> c : levels) {
                        for (String[] pair : List.of(new String[] {a.apply(json), a.apply(masked)},
                                new String[] {b.apply(a.apply(json)), b.apply(a.apply(masked))},
                                new String[] {c.apply(b.apply(a.apply(json))), c.apply(b.apply(a.apply(masked)))})) {
                            assertRedactsTo(pair[1], pair[0], pair[0]);
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
            assertRedactsTo(in, in);
        }
    }

    @Test
    void masksSecretFieldsWhoseNameAndValueQuotesAreSpelledDifferently() {
        // #339 security round 1, finding 1: \\u0022 on only the name's quotes, only the value's, or on single
        // delimiters. Quoted two ways at one level, the value has no end a reading can trust: since Codex round 4 on
        // b856d74 it is masked from its colon to the end of the outermost string or text, quoted as the name is (owner
        // decision on #339, fail closed). Quoted one way, as {\\u0022password\\u0022:123456}, it is masked alone.
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":\\u0022s3cr3t\\u0022}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\\u0022client_secret\\u0022:\"s3cr3t\"}", "{\\u0022client_secret\\u0022:\\u0022[REDACTED]\\u0022"},
                new String[] {"{\"client_secret\\u0022:\"s3cr3t\"}", "{\"client_secret\\u0022:\\u0022[REDACTED]\\u0022"},
                new String[] {"{\\u0022client_secret\":\"s3cr3t\"}", "{\\u0022client_secret\":\"[REDACTED]\""},
                new String[] {"{\"client_secret\":\\u0022s3cr3t\"}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"n\":1,\"clientSecret\":\\u0022s3cr3t\\u0022,\"scope\":\"x\"}",
                        "{\"n\":1,\"clientSecret\":\"[REDACTED]\""},
                new String[] {"{\\u0022password\\u0022:123456}", "{\\u0022password\\u0022:\\u0022[REDACTED]\\u0022}"})) {
            assertRedactsTo(pair[1], pair[0], pair[0]);
            // Wrapped: the same text in a JSON string, one and two levels deep, whichever way each level escapes.
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(RedactorTest::nested,
                    RedactorTest::nestedEscapingQuotes, t -> nested(nested(t)), t -> nestedEscapingQuotes(nested(t)),
                    t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, pair[1]), wrap.apply(pair[0]), wrap.apply(pair[0]));
            }
        }
        // A value opened with a plain quote is a JSON string, where \\u0022 is a character of it: masked through its
        // plain closing quote, as JSON_FIELD masks it on main (review on 47c938e), so no part of the value is kept.
        assertRedactsTo("{\"client_secret\":\"[REDACTED]\"", "{\"client_secret\":\"s3cr3t\\u0022,\"client_id\":\"app\"}");
        assertRedactsTo("{\"password\":\"[REDACTED]\"}", "{\"password\":\"ab\\u0022cd\"}");
        // Non-secret names spelled the same way stay byte for byte.
        for (String in : List.of("{\"client_id\":\\u0022app\\u0022}", "{\\u0022client_id\\u0022:\"app\"}",
                nested("{\"client_id\":\\u0022app\\u0022,\\u0022scope\\u0022:\"a b\"}"))) {
            assertRedactsTo(in, in);
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
                assertRedactsTo(wrapped(wrap, pair[1]), wrap.apply(pair[0]), wrap.apply(pair[0]));
            }
        }
        // The same with every quote of the text spelled \\u0022.
        assertRedactsTo("{QxQ:QQclient_secretQ:Q[REDACTED]Q}".replace("Q", "\\u0022"), "{QxQ:QQclient_secretQ:Qs3cr3tQ}".replace("Q", "\\u0022"));
        // A non-secret name in the same place is kept.
        String kept = nested(nested("{\"x\":\"\"client_id\":\"app\"}"));
        assertRedactsTo(kept, kept);
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
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
        assertRedactsTo("{QpasswordQ:Q[REDACTED]Q}".replace("Q", "\\u0022"), "{QpasswordQ:QQ}".replace("Q", "\\u0022"));
    }

    @Test
    void masksASecretObjectWholeWhoseMembersAnEarlierReadingMasked() {
        // Review on 806a28c: a secret-named object whose own members a shallower reading masked first
        // ({\\u0022private_key\\u0022:{"password":"",...}}) lost its whole-object mask, keeping its other members.
        for (String[] pair : List.of(
                new String[] {"{QprivateKeyQ:{\"password\":\"\",\"other\":42}}", "{QprivateKeyQ:Q[REDACTED]Q"},
                new String[] {"{Qprivate_keyQ:{\"password\":\"pw\",\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{Qprivate_keyQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secretQ:[\"a\",{\"access_token\":\"t\"},\"PRIVITEM\"]}", "{Qclient_secretQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes)) {
                assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
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
                new String[] {"{Qprivate_keyQ:{Qpassword\":{},\"other\":42}}", "{Qprivate_keyQ:Q[REDACTED]Q"},
                new String[] {"{QprivateKeyQ:{\"a\":1,Qclient_secret\":[1,2],\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{QprivateKeyQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes)) {
                assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
        String in = "{\"private_key\":{\"a\":\"x\\\\\",\"b\":[\"]\\\\\"]},\"client_id\":\"app\",\"n\":[1]}";
        String out = "{\"private_key\":\"[REDACTED]\",\"client_id\":\"app\",\"n\":[1]}";
        UnaryOperator<String> wrap = UnaryOperator.identity();
        for (int depth = 0; depth <= 4; depth++, wrap = compose(wrap)) {
            assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
        }
    }

    @Test
    void masksAMixedQuotedSecretObjectWholeThroughEscapedQuotesInItsStrings() {
        // Review on 7a80b9c: a secret object whose name is quoted one level deeper than its members was masked in the
        // next view, which also takes an escape off the members' strings, so "a\"}b" read as closing the object at its
        // brace. It is read in its own view instead, its strings at their own level.
        for (String[] pair : List.of(
                new String[] {"{Qprivate_keyQ:{\"note\":\"a\\\"}b\",\"other\":\"PRIVOTHER\"},\"kid\":\"k1\"}",
                        "{Qprivate_keyQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secretQ:[\"x\\\"]\",\"PRIVITEM\"],\"n\":1}", "{Qclient_secretQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAPlainQuotedValueAfterAMixedQuotedNameAtItsOwnEscapeLevel() {
        // Review on 5b051eb: after a name whose quotes are spelled \\u0022 (one or both), a plain-quoted string value was
        // read only in the next view, which takes an escape off it: an escaped quote in it closed it early, keeping the
        // rest, and an escaped backslash at its end ran it through the next member. It is read in its own view. Since Codex round 4 on b856d74 a
        // value quoted two ways at one level is masked from its colon to the end of the outermost string or text (owner
        // decision on #339, fail closed).
        for (String[] pair : List.of(
                new String[] {"{Qclient_secretQ:\"s3\\\"cr3t\",\"n\":1}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secretQ:\"s3cr3t\\\\\",\"n\":1}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qpassword\":\"a\\\\\\\"b\",\"n\":1}", "{Qpassword\":\"[REDACTED]\""},
                new String[] {"{\"client_secretQ:\"s3\\\"cr3t\"}", "{\"client_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qprivate_key\":{\"note\":\"a\\\"}b\",\"other\":\"PRIVOTHER\"},\"n\":1}",
                        "{Qprivate_key\":\"[REDACTED]\""})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAValueOpenedByAUnicodeQuoteAtItsOwnEscapeLevel() {
        // Security round 2: a string value whose opening quote is spelled \\u0022 after a plain or mixed-quoted name
        // was read only in the next view, which takes an escape off it: an escaped quote at its start closed it there,
        // so an empty string was masked and the rest kept, and an escaped backslash at its end ran it on. It is read in
        // its own view, with its own escapes, and masked whole. The escaped backslash before a closing \\u0022 may also read
        // as an escaped quote (review on 92c40cb), so that value has no certain end and is masked to the end of the string
        // holding it (owner decision on #339, fail closed). Since Codex round 4 on b856d74 so is every value quoted two
        // ways at one level, here after a plain or mixed-quoted name.
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":Q\\\"s3cr3tQ}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"client_secret\":Q\\\"s3cr3t\"}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"client_secret\":Q\\\\\\\"s3cr3tQ,\"n\":1}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"client_secret\":Qs3cr3t\\\\Q,\"n\":1}", "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"password\":Qs3\\\"cr3t\\\\\\\\Q,\"client_id\":\"app\"}",
                        "{\"password\":\"[REDACTED]\""},
                new String[] {"{Qclient_secretQ:Q\\\"s3cr3tQ}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secret\":Qs3\\\"cr3t\"}", "{Qclient_secret\":\"[REDACTED]\""})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
        // A non-secret value so quoted keeps every byte.
        for (String text : List.of("{\"client_id\":Q\\\"appQ,\"n\":1}".replace("Q", "\\u0022"),
                nested(nested("{\"scope\":Qa\\\\Q,\"n\":1}".replace("Q", "\\u0022"))))) {
            assertKept(text);
        }
    }

    @Test
    void keepsTheUnicodeQuotesInAPlainQuotedValueAfterANameQuotedWithThem() {
        // Review on 96428f9: the flattened view reads every quote a level decodes from \\u0022 as a bare one, so a
        // plain-quoted value after a name so quoted closed at a \\u0022 of its own and kept the rest. A plain-quoted
        // value is read in the decoded view, where such a quote stays an escape, as a7a971d read it. Since Codex round 4 on b856d74 a
        // value quoted two ways at one level is masked from its colon to the end of the outermost string or text (owner
        // decision on #339, fail closed).
        for (String[] pair : List.of(
                new String[] {"{Qclient_secretQ:\"preQTAIL\"}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secretQ:\"Q,TAIL\"}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{\"client_secretQ:\"preQ,TAIL\"}", "{\"client_secretQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secret\":\"preQTAIL\",\"n\":1}", "{Qclient_secret\":\"[REDACTED]\""},
                new String[] {"{QpasswordQ:\"a\\\"bQ\\\\c\",\"client_id\":\"app\"}",
                        "{QpasswordQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
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
                        "{Qprivate_keyQ:Q[REDACTED]Q"},
                new String[] {"{Qprivate_keyQ:{QnoteQ:Q\\\"}Q,QotherQ:\"PRIVOTHER\"},\"n\":1}",
                        "{Qprivate_keyQ:Q[REDACTED]Q"},
                new String[] {"{QsecretQ:[Q\\\"]Q,QPRIVOTHERQ]}",
                        "{QsecretQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
            }
        }
    }

    @Test
    void masksASecretObjectWholeThroughABracketInsideAUnicodeQuotedString() {
        // Review on 9de277d, P1: the plain structure pass ran first and closed the object at a bracket inside a string
        // quoted with \\u0022, keeping the members after it, before the flattened view could read the object whole.
        // The text mixes plain and \\u0022 quotes at one level, so its readings disagree on where the object ends; by
        // the owner's decision on #339 (fail closed) their union is masked, here to the end of the text.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"note\":Q}Q,\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\""},
                new String[] {"{\"private_key\":{\"note\":Q}Q,\"other\":\"PRIVOTHER\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\""},
                new String[] {"{\"private_key\":[Q]Q,\"PRIVOTHER\"],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\""})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void masksAUnicodeQuotedValueEndingInAnEscapedBackslashThroughEveryReadingOfIt() {
        // Review on 9de277d, P2: the embedded reading reads the value's escaped backslash and closing \\u0022 as an
        // escaped quote and runs it on to the next bare quote; the flattened reading closes it at that \\u0022. By the
        // owner's decision on #339 (fail closed) the union is masked, and as the longer reading found no closing quote of
        // its own, the value's end is unknown and it is masked to the end of the outermost string or text (review on
        // 9593177: masked only to the next member's quote, the output read as a mask that stops short).
        for (String[] pair : List.of(
                new String[] {"{QpasswordQ:Qx\\\\Q,\"n\":1}",
                        "{QpasswordQ:Q[REDACTED]Q"},
                new String[] {"{Qclient_secretQ:Qs3\\\\Q,\"client_id\":\"app\"}",
                        "{Qclient_secretQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertEquals(wrapped(wrap, out), Redactor.redact(wrap.apply(in)), wrap.apply(in));
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
                        "{QpasswordQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
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
                "{\"a\":{\"pass\\\\u0077ord\":\"x\"}}")) {
            String in = text.replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrap.apply(in), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void boundsASecretObjectByTheReadingWhoseBracketsClose() {
        // Review on 22ff6ea: a member name opened by a plain quote and closed by \\u0022 kept the flattened reading in
        // the name, so the object closed at a brace in the value after it (P1); and a reading that ran to the end of the
        // text kept the object's mask past its close bracket over the flattened reading that closes there (P2). The
        // last three keep valid JSON's bounds: a \\u0022 inside a plain-quoted value or name is the string's own. The
        // second mixes quotes at one level, so by the owner's decision on #339 (fail closed) the union of its readings,
        // to the end of the text, is masked.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"passwordQ:\"}TAIL\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\""},
                new String[] {"{QprivateKeyQ:{\"note\":QxQ},\"n\":1}",
                        "{QprivateKeyQ:Q[REDACTED]Q"},
                new String[] {"{\"private_key\":{\"note\":\"aQ\"},\"n\":\"bQ}\"}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":\"bQ}\"}"},
                new String[] {"{\"private_key\":[QaQ,\"}TAIL\"],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\""},
                new String[] {"{\"private_key\":{\"passQword\":\"x\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void masksTheUnionOfDisagreeingReadingsOfASecretObject() {
        // Review on 59b603d, owner decision (fail closed, #339): where readings of a secret object at one level disagree
        // on its bounds, the union of their masks is masked, so nothing a reading finds in it is kept. These texts mix
        // plain, escaped and \\u0022 quotes at one level; nested(nestedEscapingQuotes(...)) of the first kept TAIL and
        // "other":42. Masking past the object in such ambiguous text is accepted.
        for (String shape : List.of(
                "{\"private_key\":{\"noteQ:Q\\\"}TAILQ,\"other\":42},\"n\":1}",
                "{\"private_key\":{\"note\":Q\\\"}TAILQ,\"other\":42},\"n\":1}")) {
            String in = shape.replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                String out = Redactor.redact(wrap.apply(in));
                assertFalse(out.contains("TAIL") || out.contains("other"), wrap.apply(in) + " => " + out);
                assertTrue(out.contains("private_key"), out);
            }
        }
    }

    @Test
    void keepsValidJsonsBoundsWhenItsStringsAreWrittenWithUnicodeQuotes() {
        // Review on 9593177: written into a JSON string with \\u0022 for its quotes (nestedEscapingQuotes), valid JSON
        // whose strings hold an escaped quote was over-masked: the flattened view turned the \\u0022 inside the plain
        // string holding it into quotes, read an escaped quote as an escaped backslash and a closing quote, and that
        // reading's mask ran on past the object. A \\u0022 inside a plain-quoted value is that string's own.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"note\":\"a\\\"b\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"password\":\"a\\\"b\",\"n\":1}",
                        "{\"password\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":[\"a\\\"]\",1],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":{\"note\":\"a\\\\\"},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"})) {
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)),
                    t -> nestedEscapingQuotes(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, pair[1]), wrap.apply(pair[0]), wrap.apply(pair[0]));
            }
        }
    }

    @Test
    void keepsAValidNameWhoseUnicodeQuoteAColonFollowsWhole() {
        // Security round 3, finding 2: {"note\\u0022:foo":...} is valid JSON, its name note":foo. The flattened view
        // took that \\u0022 for the name's closing quote because a colon follows it, and its longer reading of the
        // secret object, joined with the right one, ran on to the end of the text. A name that closes with a plain
        // quote and a colon keeps its \\u0022 as its own.
        for (String[] pair : List.of(
                new String[] {"{\"private_key\":{\"noteQ:foo\":\"{TAIL\",\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":{\"noteQ :foo\":\"}TAIL\",\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":{\"aQ:bQ:c\":\"x\",\"other\":42},\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"private_key\":[{\"noteQ:foo\":\"]TAIL\"}],\"n\":1}",
                        "{\"private_key\":\"[REDACTED]\",\"n\":1}"},
                new String[] {"{\"noteQ:foo\":\"{\",\"password\":\"s3\",\"n\":1}",
                        "{\"noteQ:foo\":\"{\",\"password\":\"[REDACTED]\",\"n\":1}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)),
                    t -> nestedEscapingQuotes(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void leavesAValidNameHoldingAUnicodeQuoteBeforeASecretWordAlone() {
        // Review on 3c5ddac: {"x\\u0022password":...} is valid JSON, its name x"password. Decoded, the view held
        // "x\"password", and the plain and mixed readings opened a name at that escaped quote, read password, and masked
        // the value. A name opens only at a quote the reading reads as one.
        for (String text : List.of(
                "{\"xQpassword\":\"visible\",\"n\":1}",
                "{\"note\":\"a\",\"xQclient_secret\":42}",
                "{\"aQ:Qpassword\":\"v\",\"n\":1}",
                "{\"kid\":\"k1\",\"xQpassword\":{\"y\":1}}")) {
            String in = text.replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrap.apply(in), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAValidNameWhosePartBeforeAUnicodeQuoteAndColonIsASecretNameBothWays() {
        // Review on 9f45005: {"private_key\\u0022:{\\u0022x":42}} is valid JSON with one name, private_key":{"x, and also,
        // with \\u0022 read as a quote, {"private_key":{"x":42}}. Keeping every valid name whole missed the secret
        // object. Where the part of a valid name before a \\u0022 and a colon is a secret name, both readings are
        // admitted and their union masked (owner decision on #339, fail closed); a name whose part there is not a secret
        // name is kept whole, as before.
        for (String[] pair : List.of(
                new String[] {"{\"private_keyQ:{Qx\":42}}",
                        "{\"private_keyQ:Q[REDACTED]Q"},
                new String[] {"{\"client_secretQ:Qs3cr3t\":1}",
                        "{\"client_secretQ:Q[REDACTED]\":1}"},
                new String[] {"{\"noteQ:{Qx\":42}}",
                        "{\"noteQ:{Qx\":42}}"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), t -> nested(nested(nested(t))), RedactorTest::nestedEscapingQuotes,
                    t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void readsAValidNameHoldingManyUnicodeQuotesBeforeColonsInLinearTime() {
        // Review on 2b4b788: a valid name holding \\u0022: many times made each of them decode the whole part of the
        // name before it, to see whether it is a secret name, so the work grew with the square of the name's length.
        int n = 150_000;
        List<String> texts = List.of(
                "{\"a" + "\\u0022:".repeat(n) + "\":1}",
                "{\"private_key" + "\\u0022:".repeat(n) + "\":1}",
                nested("{\"a" + "\\u0022:".repeat(n / 2) + "\":1}"));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(text -> {
            String out = Redactor.redact(text);
            assertTrue(out.length() <= 2 * text.length(), () -> out.length() + " > 2 * " + text.length());
        }));
    }

    @Test
    void masksAUnicodeQuotedValueThroughAQuoteItsEscapedBackslashMayEscape() {
        // Review on 92c40cb: in {"client_secret":\\u0022S3\\\\\\u0022,TAIL\\u0022} the flattened view read the escaped
        // backslash and the \\u0022 after it as the value's end, and only S3 was masked. Read as text copied from inside a
        // string, those decode to an escaped quote, and the value runs on to the last \\u0022: both readings are taken
        // and their union masked (owner decision on #339, fail closed). Five backslashes are an escaped backslash and a
        // closing quote either way. Since Codex round 4 on b856d74 a
        // value quoted two ways at one level is masked from its colon to the end of the outermost string or text (owner
        // decision on #339, fail closed).
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":QS3\\\\Q,TAILQ}",
                        "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"password\":Qa\\\\QbQ,\"n\":1}",
                        "{\"password\":\"[REDACTED]\""},
                new String[] {"{\"password\":Qa\\\\\\\\Q,\"n\":1}",
                        "{\"password\":\"[REDACTED]\""})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)))) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void masksAValueQuotedWithEscapedQuotesAfterANameClosedByAUnicodeQuote() {
        // Review on 9d5f47d, P1: {"client_secret\\u0022:\\"s3cr3t\\"} was kept whole: the mixed reading needs a
        // plain-quoted value, the flattened one a value opened by \\u0022, and the deeper views read the name as the level
        // above's. After a name the flattened view closes with a quote it turned bare, a value opened by an escaped quote
        // is masked whole, escaped quotes included, quoted as the name is. Since Codex round 4 on b856d74 a
        // value quoted two ways at one level is masked from its colon to the end of the outermost string or text (owner
        // decision on #339, fail closed).
        for (String[] pair : List.of(
                new String[] {"{\"client_secretQ:\\\"s3cr3t\\\"}",
                        "{\"client_secretQ:Q[REDACTED]Q"},
                new String[] {"{\"passwordQ:\\\"s3cr3t\\\",\"n\":1}",
                        "{\"passwordQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes)) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void leavesAValidNameHoldingAnEscapedQuoteAloneAtEveryDepth() {
        // Review on 9d5f47d, P2: {"x\\"password":...} is valid JSON, its name x"password. Nested twice, its escaped quote
        // is \\\\\\" in the view, an escaped quote at the embedded level, and the embedded reading opened a name at its
        // last \\" and masked the value. An embedded name opens only after a run of backslashes 1 more than a multiple of 4.
        // Unwrapped, or nested once with \\" or \\u005C, main's patterns on the text itself mask it already; those are
        // out of this test. Nested once with \\u0022, and twice in any way, main keeps it whole.
        List<UnaryOperator<String>> levels = List.of(RedactorTest::nested, RedactorTest::nestedEscapingQuotes,
                RedactorTest::nestedEscapingBackslashes);
        List<String> verdictsByText = new ArrayList<>();
        for (String text : List.of(
                "{\"x\\\"password\":\"visible\",\"n\":1}",
                "{\"note\":\"a\",\"x\\\"client_secret\":42}",
                "{\"a\\\":\\\"password\":\"v\",\"n\":1}")) {
            // Since #377 stage 1 the text engine also reads each string that holds an escape as the text spells it, and
            // in some of these forms that reading masks the value, fail closed; nothing else changes. The verdict of
            // each form is pinned: K kept (the same JSON), M only the value masked; once with \\u0022, then each pair of
            // levels in order.
            String valueMasked = text.replace(":\"visible\"", ":\"[REDACTED]\"").replace(":42", ":\"[REDACTED]\"")
                    .replace(":\"v\"", ":\"[REDACTED]\"");
            List<UnaryOperator<String>> forms = new ArrayList<>(List.of(RedactorTest::nestedEscapingQuotes));
            for (UnaryOperator<String> a : levels) {
                for (UnaryOperator<String> b : levels) {
                    forms.add(t -> b.apply(a.apply(t)));
                }
            }
            StringBuilder verdicts = new StringBuilder();
            for (UnaryOperator<String> form : forms) {
                String in = form.apply(text);
                String out = Redactor.redact(in);
                verdicts.append(Canonical.of(in).equals(out) ? 'K' : Canonical.of(form.apply(valueMasked)).equals(out) ? 'M' : '?');
            }
            verdictsByText.add(verdicts.toString());
        }
        // main kept all 30. The inner level escaping quotes with \\u0022 keeps the value; with \\" or \\u005C the reading
        // as spelled masks it.
        assertEquals(List.of("KMMMKKKMMM", "KMMMKKKMMM", "KMMMKKKMMM"), verdictsByText);
    }

    @Test
    void masksAValueOpenedByAnEscapedQuoteThatNoReadingBoundsToTheEndOfItsString() {
        // Review on f94fa05: {"client_secret":\\"s3cr3t\\u0022} was kept whole: no reading reads a value an escaped quote
        // opens after a plain-quoted name, whatever closes it. Such a value has no end any reading finds, so it is masked
        // to the end of the outermost string or text (owner decision on #339, fail closed; Codex round 5 on 8e6f207);
        // valid JSON has no such value.
        for (String[] pair : List.of(
                new String[] {"{\"client_secret\":\\\"s3cr3tQ}",
                        "{\"client_secret\":\"[REDACTED]\""},
                new String[] {"{\"password\":\\\"s3cr3tQ,\"n\":1}",
                        "{\"password\":\"[REDACTED]\""},
                new String[] {"{\"client_secret\":\\\"s3cr3t\"}",
                        "{\"client_secret\":\"[REDACTED]\""})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes)) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void masksAnEscapedQuoteValueAfterAUnicodeClosedNameToTheEndOfItsStringWhenItsEndIsUnsure() {
        // Found with the review on f94fa05: after a name closed by \\u0022, a value an escaped quote opens was read as an
        // embedded string, which closed at a bare quote or at an escaped quote with more of the value right after it,
        // keeping that rest (TAIL, S3CR3T). With no end of its own the value is masked to the end of the outermost string or
        // text (Codex round 5 on 8e6f207).
        for (String[] pair : List.of(
                new String[] {"{\"client_secretQ:\\\"S3\\\\Q,TAIL\"}",
                        "{\"client_secretQ:Q[REDACTED]Q"},
                new String[] {"{\"client_secretQ:\\\"\\\"S3CR3T\"}",
                        "{\"client_secretQ:Q[REDACTED]Q"})) {
            String in = pair[0].replace("Q", "\\u0022");
            String out = pair[1].replace("Q", "\\u0022");
            for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                    t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes)) {
                assertRedactsTo(wrapped(wrap, out), wrap.apply(in), wrap.apply(in));
            }
        }
    }

    @Test
    void masksAValueAfterEscapedWhitespaceAndAnEscapedQuoteToTheEndOfItsString() {
        // Codex round 4 on b856d74: {"client_secret":\\t\\"s3cr3t\\u0022} (\\t written as two characters) was kept whole.
        // The fallback for a value an escaped quote opens skipped only real whitespace, so escaped whitespace before that
        // quote, which EMBEDDED_SPACE reads as whitespace, hid the value from every reading. Quoted two ways, the value
        // has no end a reading can trust: it is masked from its colon to the end of the outermost string or text (owner
        // decision on #339, fail closed), with \\t, \\n or \\r, after a plain or \\u0022-closed name, at every depth.
        for (String space : List.of("~t", "~n", "~r")) {
            for (String[] pair : List.of(
                    new String[] {"{\"client_secret\":S~\"s3cr3tQ}", "{\"client_secret\":\"[REDACTED]\""},
                    new String[] {"{\"client_secret\":S~\"s3cr3tQ,\"n\":1}", "{\"client_secret\":\"[REDACTED]\""},
                    new String[] {"{\"client_secret\":S~\"s3cr3t~\",\"n\":1}", "{\"client_secret\":\"[REDACTED]\""},
                    new String[] {"{\"passwordQ:S~\"s3cr3t~\"}", "{\"passwordQ:Q[REDACTED]Q"},
                    new String[] {"{\"passwordQ:S~\"s3cr3tQ,\"n\":1}", "{\"passwordQ:Q[REDACTED]Q"},
                    new String[] {"{\"client_secretQ:SQs3cr3tQ}", "{\"client_secretQ:Q[REDACTED]Q"})) {
                String in = withEscapes(pair[0].replace("S", space));
                assertRedactsTo(withEscapes(pair[1].replace("S", space)), in, in);
                // Nested, the embedded reading masks from the escaped whitespace on, which the text escapes again there;
                // everything before the value is kept.
                String secret = in.contains("password") ? "password" : "client_secret";
                List<UnaryOperator<String>> wraps = List.of(RedactorTest::nested, t -> nested(nested(t)),
                        RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)));
                for (int w = 0; w < wraps.size(); w++) {
                    String wrapped = wraps.get(w).apply(in);
                    String out = Redactor.redact(wrapped);
                    assertFalse(out.contains("s3cr3t"), () -> wrapped + " => " + out);
                    // Everything up to the value's colon is kept, as Jackson's encoder spells the strings since #377.
                    // Pinned (#377 gate change): nested around a \u0022-quoted level, the embedded reading masks the
                    // value in that string's own spelling, which the encoder does not write, so there the prefix is the
                    // input's own, byte for byte, as on main.
                    String expected = w == 3 ? wrapped : Canonical.of(wrapped);
                    assertTrue(out.startsWith(expected.substring(0, expected.indexOf(':', expected.indexOf(secret)) + 1)),
                            () -> wrapped + " => " + out);
                }
            }
        }
    }

    @Test
    void masksEverySecretValueQuotedTwoWaysOrOpenedByAnEscapeAtEveryDepth() {
        // Codex round 4 on b856d74: each review round found one more spelling of a field quoted two ways at one level
        // that its own fallback missed. Every spelling of the name's quotes (plain, closed or opened by \\u0022, both
        // \\u0022), every gap between its colon and value (none, escaped \\t \\n \\r, those among spaces, a run of
        // backslashes, \\u0009), and the values of the earlier rounds (opened and closed by escaped, \\u0022 and plain quotes,
        // an escaped backslash before a \\u0022, an empty escaped string first), keep no part of the secret, bare and
        // nested every way.
        List<String> names = List.of("\"client_secret\"", "\"client_secretQ", "Qclient_secret\"", "Qclient_secretQ");
        List<String> gaps = List.of("", "~t", "~n", "~r", " ~t ", "~~t", "~u0009");
        List<String> values = List.of("~\"s3cr3tQ", "~\"s3cr3t~\"", "Qs3cr3tQ", "Qs3cr3t\"", "\"s3cr3tQ", "~\"s3cr3t\"",
                "\"s3cr3t\"", "Q~\"s3cr3tQ", "QS3~~Q,s3cr3tQ", "~\"S3~~Q,s3cr3t\"", "~\"~\"s3cr3t\"");
        List<UnaryOperator<String>> wraps = List.of(t -> t, RedactorTest::nested, t -> nested(nested(t)),
                RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)));
        List<String> kept = new ArrayList<>();
        int texts = 0;
        for (String name : names) {
            for (String gap : gaps) {
                for (String value : values) {
                    for (String tail : List.of("}", ",\"n\":1}")) {
                        String in = withEscapes("{" + name + ":" + gap + value + tail);
                        for (UnaryOperator<String> wrap : wraps) {
                            texts++;
                            String out = Redactor.redact(wrap.apply(in));
                            if (out.contains("s3cr3t")) {
                                kept.add(wrap.apply(in) + " => " + out);
                            }
                        }
                    }
                }
            }
        }
        int total = texts;
        assertEquals(List.of(), kept, () -> kept.size() + " of " + total + " texts kept the secret, first: "
                + kept.subList(0, Math.min(5, kept.size())));
    }

    @Test
    void keepsValidJsonWithWhitespaceBeforeItsValuesWholeButTheSecretsAtEveryDepth() {
        // Codex round 4 on b856d74: a value is now located past the whitespace EMBEDDED_SPACE reads, a line break or tab
        // written plainly or escaped once, and one that then starts with an escape is quoted two ways. Valid JSON has no
        // such value: pretty-printed, and nested however a level escapes its quotes and backslashes, it keeps every byte
        // but the secrets.
        String doc = "{\n\t\"password\":\t\"s3cr3t\",\n\t\"note\":\n\t\t\"a\\\"b\",\n\t\"client_secret\" :\r\n 42,\n"
                + "\t\"private_key\":\t{\"x\":\t\"y\"},\n\t\"n\": null\n}";
        String masked = "{\n\t\"password\":\t\"[REDACTED]\",\n\t\"note\":\n\t\t\"a\\\"b\",\n\t\"client_secret\" :\r\n"
                + " \"[REDACTED]\",\n\t\"private_key\":\t\"[REDACTED]\",\n\t\"n\": null\n}";
        for (UnaryOperator<String> wrap : List.<UnaryOperator<String>>of(t -> t, RedactorTest::nested,
                t -> nested(nested(t)), RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)),
                RedactorTest::nestedEscapingBackslashes, t -> nested(nestedEscapingBackslashes(t)),
                t -> nestedEscapingQuotes(nestedEscapingQuotes(t)))) {
            assertEquals(wrap.apply(masked), Redactor.redact(wrap.apply(doc)), wrap.apply(doc));
        }
    }

    @Test
    void masksAValueAnyEscapeOpensFromTheColonToTheEndOfTheOutermostString() {
        // Codex round 5 on 8e6f207. F1: {\"client_secret\":\/\"s3cr3t\"} kept the secret, because only a run of two or more
        // backslashes counted as an escaped value one level deep. F2: {\"client_secret\":\\"s3cr3t\"} masked only the two
        // backslashes, because the quote after them was taken for the end of the string holding the value. No strict
        // reading of the name's level reads either value, so it is masked from just after the colon to the end of the
        // outermost string holding it, or, with no valid JSON around it to say where that is, to the end of the text.
        String masked = "{\\\"client_secret\\\":\\\"[REDACTED]\\\"";
        for (String in : List.of("{\\\"client_secret\\\":\\/\\\"s3cr3t\\\"}", "{\\\"client_secret\\\":\\\\\"s3cr3t\\\"}",
                "{\\\"client_secret\\\":\\f\\\"s3cr3t\\\"}", "{\\\"client_secret\\\":\\/\\\"s3cr3t",
                "{\\\"client_secret\\\":\\\\\"s3cr3t")) {
            assertEquals(masked, Redactor.redact(in), in);
            assertEquals("log: " + masked, Redactor.redact("log: " + in + " next line"), in);
            // In a string of valid JSON the mask stops at that string's end: the members after it are kept.
            assertEquals("{\"body\":" + JSON.writeValueAsString(masked) + ",\"n\":1}",
                    Redactor.redact("{\"body\":" + JSON.writeValueAsString(in) + ",\"n\":1}"), in);
            // Two levels down that is the outer string's end: the inner string and object around the name go with it.
            String twice = nested(nested(masked));
            assertEquals(twice.substring(0, twice.length() - "\\\"}\"}".length()) + "\"}",
                    Redactor.redact(nested(nested(in))), in);
        }
    }

    @Test
    void masksEverySecretValueTheStrictReadingDoesNotConsumeAndWritesTheOutputsForTheScanner() throws Exception {
        // Codex round 5 on 8e6f207: one rule for every spelling instead of a trigger per shape. Every quote spelling of the
        // name's quotes (plain or \\u0022 after 0 to 3 backslashes), every single-character JSON escape or a space before
        // the value, every quote spelling of the value's quotes, closed plainly or as it opened or cut off by the end of
        // the text, bare and nested: no secret is kept unless the text is valid JSON whose name is not a secret one (a
        // backslash closes "client_secret\\" inside the name), which is kept whole. With the earlier rounds' inputs,
        // the outputs must match the committed scanner-grids/fail-closed-grid.json.gz, where replay/test/leaks.test.mjs
        // checks that the scanner accepts every one of them.
        List<String> quotes = List.of("\"", "~\"", "~~\"", "~~~\"", "Q", "~Q", "~~Q");
        List<String> gaps = List.of("", " ", "~\"", "~~", "~/", "~b", "~f", "~n", "~r", "~t");
        List<String> values = new ArrayList<>(List.of(""));
        for (String open : quotes) {
            values.add(open + "s3cr3t" + open + "}");
            if (!open.equals("\"")) {
                values.add(open + "s3cr3t\"}");
            }
            values.add(open + "s3cr3t");
        }
        List<UnaryOperator<String>> wraps = List.of(RedactorTest::nested, t -> nested(nested(t)),
                RedactorTest::nestedEscapingQuotes, t -> nested(nestedEscapingQuotes(t)));
        List<String[]> pairs = new ArrayList<>();
        List<String> wrong = new ArrayList<>();
        int texts = 0;
        int inputs = 0;
        for (String open : quotes) {
            for (String close : quotes) {
                for (String gap : gaps) {
                    for (String value : values) {
                        String in = withEscapes("{" + open + "client_secret" + close + ":" + gap + value);
                        boolean kept = isValidWithoutSecretNames(in);
                        for (String text : List.of(in, wraps.get(inputs++ % wraps.size()).apply(in))) {
                            texts++;
                            String out = Redactor.redact(text);
                            pairs.add(new String[] {text, out});
                            if (kept ? !Canonical.of(text).equals(out) : out.contains("s3cr3t")) {
                                wrong.add(text + " => " + out);
                            }
                        }
                    }
                }
            }
        }
        // The earlier rounds' inputs (#339), each with the parts of its secret that must not be kept.
        for (String[] round : List.of(
                new String[] {"{\"client_secret\":\"~\"s3cr3t\"}", "s3cr3t"},
                new String[] {"{\"client_secret\":~\"s3cr3tQ}", "s3cr3t"},
                new String[] {"{\"client_secret\":\"s3cr3tQ,\"client_id\":\"app\"}", "s3cr3t"},
                new String[] {"{\"client_secret\":~t~\"s3cr3tQ}", "s3cr3t"},
                new String[] {"{\"client_secretQ:~\"s3cr3t~\"}", "s3cr3t"},
                new String[] {"{\"client_secretQ:~\"~\"S3CR3T\"}", "S3CR3T"},
                new String[] {"{\"client_secret\":Q~\"s3cr3tQ}", "s3cr3t"},
                new String[] {"{\"client_secret\":Qs3cr3t~~~Q,\"n\":1}", "s3cr3t"},
                new String[] {"{\"client_secret\":Qs3cr3tQ,\"n\":1}", "s3cr3t"},
                new String[] {"{\"client_secretQ:~\"S3~~~Q,TAIL\"}", "S3", "TAIL"},
                new String[] {"{\"client_secret\":QS3~~~Q,TAILQ}", "S3", "TAIL"},
                new String[] {"{\"password\":\"abQcd\"}", "ab", "cd"},
                new String[] {"{\"private_key\":{\"passwordQ:\"}TAIL\"},\"n\":1}", "TAIL"},
                new String[] {"{Qclient_secret\":\"s3Q,\"n\":1}", "s3"},
                new String[] {"{Qclient_secretQ:\"preQTAIL\"}", "{Qclient_secretQ:Q[REDACTED]Q", "TAIL"},
                new String[] {"{Qclient_secretQ:\"Q,TAIL\"}", "{Qclient_secretQ:Q[REDACTED]Q"},
                new String[] {"{QpasswordQ:QXSEC~~~Q,\"n\":1}", "XSEC"},
                new String[] {"{Qprivate_keyQ:{Qpassword\":{},\"other\":\"OTHERSEC\"}}", "OTHERSEC"},
                new String[] {"{\"x\":\"\"client_secret\":\"s3cr3t\"}", "s3cr3t"},
                new String[] {"{Qclient_secretQ:QS3QCR3T\"}", "S3", "CR3T"},
                new String[] {"{\\\"client_secret\\\":\\/\\\"s3cr3t\\\"}", "s3cr3t"},
                new String[] {"{\\\"client_secret\\\":\\\\\"s3cr3t\\\"}", "s3cr3t"})) {
            String in = withEscapes(round[0]);
            for (String text : List.of(in, nested(in), nested(nested(in)), nestedEscapingQuotes(in),
                    nested(nestedEscapingQuotes(in)))) {
                texts++;
                String out = Redactor.redact(text);
                pairs.add(new String[] {text, out});
                for (int i = 1; i < round.length; i++) {
                    if (out.contains(round[i])) {
                        wrong.add(text + " => " + out);
                    }
                }
            }
        }
        int total = texts;
        assertEquals(List.of(), wrong, () -> wrong.size() + " of " + total + " texts are wrong, first: "
                + wrong.subList(0, Math.min(5, wrong.size())));
        assertScannerGrid("fail-closed-grid", pairs);
    }

    @Test
    void masksASecretNameWhoseQuoteIsSpelledThroughAnEscapeChainOfAnyDepthAndWritesTheOutputsForTheScanner()
            throws Exception {
        // Review on a7a1eef: {"password\\u005cu0022: then a plain-quoted value was kept whole, because a quote counted only
        // with a backslash right before its u0022, and \\u005c then u0022 is a quote two levels down. Owner decision
        // (2026-11-09): a quote, a colon or a name character spelled through a chain of \\u005c escapes counts at any
        // depth of the chain. The chain is decoded at most NESTED_LEVELS times: a quote it makes only deeper than that is
        // a quote of no level the strict reading reads, so the value is masked, never kept. The outputs must match the
        // committed scanner-grids/escape-chain-grid.json.gz, where replay/test/leaks.test.mjs checks that the scanner
        // accepts every one.
        assertRedactsTo("{\"password\\u005cu0022:\\u005cu0022[REDACTED]\\u005cu0022", "{\"password\\u005cu0022:\"s3cr3t\"}");
        // The bound: a chain that makes a quote NESTED_LEVELS levels down is read; one level more is a quote of no level,
        // and its value is masked all the same, the mask unquoted.
        String atBound = "\\" + "u005c".repeat(Redactor.NESTED_LEVELS - 1) + "u0022";
        String pastBound = "\\" + "u005c".repeat(Redactor.NESTED_LEVELS) + "u0022";
        assertEquals(Redactor.NESTED_LEVELS, Redactor.quoteLevel(atBound));
        assertEquals(-1, Redactor.quoteLevel(pastBound));
        for (String c : List.of(atBound, pastBound)) {
            String out = Redactor.redact("{\"password" + c + ":\"s3cr3t\"}");
            assertFalse(out.contains("s3cr3t"), out);
            assertTrue(out.endsWith(c.equals(atBound) ? Redactor.MASK + atBound : Redactor.MASK), out);
        }
        List<String> chains = new ArrayList<>();
        for (int depth = 1; depth <= Redactor.NESTED_LEVELS + 3; depth++) {
            chains.add("~" + "u005c".repeat(depth) + "u0022");
        }
        chains.addAll(List.of("~~u005cu0022", "~u005c~u005cu0022", "~u005c~\"", "~u005Cu0022", "~u005cu005C~~u0022",
                "~~~u005cu005cu0022"));
        List<String> colons = List.of(":", "~u005cu003a", "~u005cu005cu003A");
        List<String> names = List.of("password", "pass~u005cu0077ord", "client~u005cu005cu005fsecret");
        List<UnaryOperator<String>> wraps = List.of(t -> t, RedactorTest::nested, t -> nested(nested(t)),
                RedactorTest::nestedEscapingQuotes, t -> "log: " + t + " next line");
        List<String> inputs = new ArrayList<>(List.of("{\"note\":\"password~u005cu0022: s3cr3t\"}",
                "{\"x~u005cu0022\":\"password~u005cu0022:s3cr3t\",\"n\":1}",
                "{\"a~u005cu005cu0022b\":1,\"note\":\"password~u005cu005cu0022:s3cr3t\"}"));
        for (String c : chains) {
            for (String colon : colons) {
                for (String name : names) {
                    inputs.add("{\"" + name + c + colon + "\"s3cr3t\"}");
                    inputs.add("{" + c + name + "\"" + colon + "\"s3cr3t\"}");
                    inputs.add("{" + c + name + c + colon + c + "s3cr3t" + c + "}");
                    inputs.add("{\"" + name + c + colon + "\"s3cr3t");
                    inputs.add("{\"" + name + "\"" + colon + c + "s3cr3t" + c + "}");
                    inputs.add("{" + c + name + c + colon + "\"s3cr3t\",\"n\":1}");
                }
            }
        }
        List<String[]> pairs = new ArrayList<>();
        List<String> wrong = new ArrayList<>();
        for (String input : inputs) {
            boolean kept = isValidWithoutSecretNames(withEscapes(input));
            for (UnaryOperator<String> wrap : wraps) {
                String text = wrap.apply(withEscapes(input));
                String out = Redactor.redact(text);
                pairs.add(new String[] {text, out});
                // Valid JSON stays the same JSON (#377: only its escape spellings may change); in a log line it is text that is not JSON, where the fail-closed rule holds.
                if (kept ? isValidWithoutSecretNames(text) && !Canonical.of(text).equals(out) : out.contains("s3cr3t")) {
                    wrong.add(text + " => " + out);
                }
            }
        }
        assertEquals(List.of(), wrong, () -> wrong.size() + " of " + pairs.size() + " texts are wrong, first: "
                + wrong.subList(0, Math.min(5, wrong.size())));
        assertScannerGrid("escape-chain-grid", pairs);
    }

    @Test
    void writesTheGenericFieldSeparatorGridsForTheScanner() throws Exception {
        // #348: secret-named fields with an unusual separator between the name and its colon, in escaped copies and plain
        // JSON. The pin grid holds the 57 forms of #344's probe whose verdicts main already gets right: since #351 the
        // Redactor masks 48 of them and keeps 9. The miss grid holds the separator class the scanner missed, with the
        // forms around it that the Redactor keeps. The note grid holds such fields at the top level whose value ends in a
        // cut before a note, each also in its report form, which the Redactor reads differently. The mixed grid holds such
        // fields whose name and value are quoted at different escape levels (security round 1 at 42d0b14). #374's level
        // grids hold such fields after a stray quote or inside a string value, where the bare quotes before the value
        // decide whether its unicode-escaped quote opens it: the level-miss grid has the name one or two levels down and
        // the value one level below it (#373), the level-over grid a plain-quoted name and the value one level down, and the
        // level-name grid such a field after a name a plain quote opens and a unicode-escaped quote closes before its colon
        // (review on fc94026), each for every generic secret name; the level-spelling grid pins such fields whose own name
        // opens and closes with the same or different quote spellings, or with a quote of no level, where main's verdicts
        // are already right (review on bc95162); the level-case grid holds the level grids' unmasked forms with the value's
        // opening or closing escape spelled with an uppercase U, which the Redactor reads as no escape (review on 98a6d37); the level-flat
        // grid holds a plain-named field whose value's unicode-escaped quote the Redactor turns bare where it closes a name a
        // stray quote left open, a colon following it (review on 010df1f); the level-cut grid holds such a value with a quote of a
        // shallower level inside it, in a text cut at its end, whose Redactor output the scanner must accept; the level-escape
        // grid holds a secret name spelled with unicode escapes after an earlier name closed early (Codex security round 1 on
        // ddfd74c), the level-deeper grid holds such fields whose name opens with a quote of a deeper level than the view
        // that reads its value, closed with either spelling, with masked values ending in a quote, a cut escape or nothing
        // (#374, option A), the level-slice grid holds such fields in a string read after a stray quote and a quote of
        // the string's own level or one it turns bare (review on d931f68), the level-whole grid holds such fields after a
        // stray quote of any spelling at the top level or one level down, with the name, separator and value quoted at
        // several levels (review on 8f48a35), the level-spelled grid holds the level-slice grid's inputs and outputs with
        // their unicode-escaped quotes spelled through an escaped backslash, and some nested five or seven times (review on
        // 537c8ea), the level-loose grid holds such fields after a stray quote whose value's closing quote a string read
        // whole decodes past, held as an escaped quote or backslash or dropped with the empty string after it, or whose
        // closing quote's backslash run holds a \\u005c escape the view decodes into the value (review on c3019ff), the
        // level-respelled grid holds the level-loose and level-whole grids' inputs and outputs with every backslash
        // spelled \\u005c (review on e7f8ff1), the level-chain grid holds such fields with every backslash spelled \\u005c cut
        // just after or inside a masked value's closing quote, and with every other backslash spelled so, the level-wrapped
        // grid holds such fields with their quotes spelled through \\u005c escapes wrapped in one more JSON string (review
        // on 1e2b532), the level-generated grid holds such fields generated over every quote and backslash spelling, the
        // name's and the value's levels and each kind of end, with the report forms the Redactor masks of some kept texts
        // and outputs (review on dd53a50), and the level-probe grid is #374's 18,200-text mixed-level probe, which the scanner's guard
        // against main reads. Their inputs are the committed files' own, so the exact forms stay
        // in data; replay/test/leaks.test.mjs checks the scanner's verdict on each input and that it accepts each output.
        Map<String, int[]> counts = Map.ofEntries(
                Map.entry("generic-separator-pin-grid", new int[] {48, 9}),
                Map.entry("generic-separator-miss-grid", new int[] {6111, 1326}),
                Map.entry("generic-separator-note-grid", new int[] {369, 180}),
                Map.entry("generic-separator-mixed-grid", new int[] {1600, 2600}),
                Map.entry("generic-separator-level-miss-grid", new int[] {640, 1920}),
                Map.entry("generic-separator-level-over-grid", new int[] {180, 1740}),
                Map.entry("generic-separator-level-name-grid", new int[] {680, 2200}),
                Map.entry("generic-separator-level-spelling-grid", new int[] {800, 3640}),
                Map.entry("generic-separator-level-case-grid", new int[] {1340, 1220}),
                Map.entry("generic-separator-level-flat-grid", new int[] {4960, 1440}),
                Map.entry("generic-separator-level-cut-grid", new int[] {2880, 0}),
                Map.entry("generic-separator-level-escape-grid", new int[] {3920, 12400}),
                Map.entry("generic-separator-level-deeper-grid", new int[] {960, 11820}),
                Map.entry("generic-separator-level-slice-grid", new int[] {1020, 1830}),
                Map.entry("generic-separator-level-whole-grid", new int[] {2420, 4020}),
                Map.entry("generic-separator-level-spelled-grid", new int[] {1536, 4752}),
                Map.entry("generic-separator-level-loose-grid", new int[] {4900, 0}),
                Map.entry("generic-separator-level-respelled-grid", new int[] {5500, 9600}),
                Map.entry("generic-separator-level-chain-grid", new int[] {4060, 3866}),
                Map.entry("generic-separator-level-wrapped-grid", new int[] {2853, 11192}),
                // #377: 15 rows that already hold a mask are masked again by the reading of each string as spelled.
                Map.entry("generic-separator-level-generated-grid", new int[] {11905, 4113}),
                Map.entry("generic-separator-level-probe-grid", new int[] {6940, 11260}));
        for (Map.Entry<String, int[]> grid : counts.entrySet()) {
            List<String[]> pairs = new ArrayList<>();
            int masked = 0;
            for (List<String> pair : committedScannerGrid(grid.getKey())) {
                String out = Redactor.redact(pair.get(0));
                pairs.add(new String[] {pair.get(0), out});
                // Kept is the same JSON since the structural path (#377): only the escape spellings may change.
                masked += Canonical.of(pair.get(0)).equals(out) ? 0 : 1;
            }
            assertEquals(grid.getValue()[0], masked, grid.getKey() + ": masked");
            assertEquals(grid.getValue()[1], pairs.size() - masked, grid.getKey() + ": kept");
            assertScannerGrid(grid.getKey(), pairs);
        }
    }

    /** The input and output pairs of the committed {@code src/test/resources/scanner-grids/<name>.json.gz}. */
    static List<List<String>> committedScannerGrid(String name) throws java.io.IOException {
        java.nio.file.Path grid = java.nio.file.Path.of("src", "test", "resources", "scanner-grids", name + ".json.gz");
        try (var in = new java.util.zip.GZIPInputStream(java.nio.file.Files.newInputStream(grid))) {
            return JSON.readValue(new String(in.readAllBytes(), StandardCharsets.UTF_8),
                    new tools.jackson.core.type.TypeReference<>() { });
        }
    }

    /**
     * The Redactor's outputs for every text and harmless entry of the shared corpus and for the seeded fuzz corpus
     * ({@link FuzzCorpus}), committed as the agreement grid: replay/test/leaks.test.mjs runs the scanner over each output
     * (#377 criterion 2).
     */
    @Test
    void recordsItsOutputsForTheCorpusAndTheFuzzCorpusForTheScannerAgreement() throws java.io.IOException {
        JsonNode corpus;
        try (java.io.InputStream in = RedactorTest.class.getResourceAsStream("/redaction-corpus.json")) {
            corpus = JSON.readTree(in);
        }
        List<String[]> pairs = new ArrayList<>();
        for (String section : List.of("text", "harmless")) {
            for (JsonNode entry : corpus.get(section)) {
                String input = entry.get("input").asString();
                pairs.add(new String[] {input, Redactor.redact(input)});
            }
        }
        for (String input : FuzzCorpus.texts(377, 5_000)) {
            pairs.add(new String[] {input, Redactor.redact(input)});
        }
        assertEquals(135 + 5_000, pairs.size());
        assertScannerGrid("agreement-grid", pairs);
    }

    /**
     * Checks that the committed {@code src/test/resources/scanner-grids/<name>.json.gz} holds exactly these input and
     * output pairs. replay/test/leaks.test.mjs checks that the scanner accepts every output; it reads the committed file
     * because the publish job runs that suite without Maven, where a build output under target/ does not exist (#357).
     * After a change to the Redactor, rewrite the files with
     * {@code ./mvnw -pl workbench-core test -Dtest=RedactorTest -Dredactor.grids.update=true} and commit them.
     */
    static void assertScannerGrid(String name, List<String[]> pairs) throws java.io.IOException {
        java.nio.file.Path grid = java.nio.file.Path.of("src", "test", "resources", "scanner-grids", name + ".json.gz");
        String json = JSON.writeValueAsString(pairs);
        if (Boolean.getBoolean("redactor.grids.update")) {
            java.nio.file.Files.createDirectories(grid.getParent());
            try (var out = new java.util.zip.GZIPOutputStream(java.nio.file.Files.newOutputStream(grid))) {
                out.write(json.getBytes(StandardCharsets.UTF_8));
            }
        }
        String committed;
        try (var in = new java.util.zip.GZIPInputStream(java.nio.file.Files.newInputStream(grid))) {
            committed = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        List<List<String>> expected = pairs.stream().map(List::of).toList();
        List<List<String>> actual = JSON.readValue(committed, new tools.jackson.core.type.TypeReference<>() { });
        int first = 0;
        while (first < Math.min(expected.size(), actual.size()) && expected.get(first).equals(actual.get(first))) {
            first++;
        }
        int at = first;
        assertTrue(expected.equals(actual), () -> grid + " is stale (" + actual.size() + " pairs, the Redactor gives "
                + expected.size() + "; first difference at " + at + "): rewrite it with ./mvnw -pl workbench-core test"
                + " -Dtest=RedactorTest -Dredactor.grids.update=true and commit it");
    }

    /** Whether {@code text} is valid JSON with no member a secret name names, at any depth. */
    private static boolean isValidWithoutSecretNames(String text) {
        JsonNode tree;
        try {
            tree = JSON.readTree(text);
        } catch (RuntimeException notJson) {
            return false;
        }
        ArrayDeque<JsonNode> nodes = new ArrayDeque<>(List.of(tree));
        while (!nodes.isEmpty()) {
            JsonNode node = nodes.pop();
            for (String name : node.propertyNames()) {
                if (Redactor.isSecretField(name) || Redactor.isSensitiveHeader(name)) {
                    return false;
                }
            }
            node.forEach(nodes::push);
        }
        return true;
    }

    /**
     * What {@code wrap} makes of a text whose output is {@code out}. A field no strict reading reads is masked to the end of
     * the text bare (Codex round 5 on 8e6f207), and, wrapped in JSON strings, to the end of the outermost one: the strings
     * and objects the wraps open inside it lose their closing quotes and braces with the rest of the value. Any other
     * output is wrapped as it is.
     */
    private static String wrapped(UnaryOperator<String> wrap, String out) {
        if (!out.matches("(?s).*\\[REDACTED]\\\\*+(?:\"|u0022)")) {
            return wrap.apply(out);
        }
        String text = wrap.apply(out + "@END@");
        int end = text.indexOf("@END@");
        return end + "@END@".length() == text.length() ? out : text.substring(0, end) + "\"}";
    }

    /** {@code text} with each {@code ~} a backslash and each {@code Q} a quote spelled {@code \\u0022}. */
    private static String withEscapes(String text) {
        return text.replace("~", "\\").replace("Q", "\\u0022");
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
    void masksSecretNamesQuotedThroughLongEscapeChainsInLinearTime() {
        // Review on a7a1eef: a quote spelled through a chain of \\u005c escapes counts at any depth of the chain. About
        // 1 MB each: one chain of 200,000 escapes, 40,000 openers quoted with a chain, 8,000 quotes spelled with chains
        // of 20, and 20,000 names spelled with a chain, nested; each quote's run is read back once and decoded at most NESTED_LEVELS times, so time stays linear.
        List<String> texts = List.of("{\"password\\" + "u005c".repeat(200_000) + "u0022:\"s3cr3t\"}",
                "{\"password\\u005cu005cu0022:\"s3cr3t\",".repeat(40_000),
                ("\"" + "\\u005c".repeat(20) + "u0022").repeat(8_000) + "{\"password\\u005cu0022:\"s3cr3t\"}",
                nested("{\"pass\\u005cu0077ord\\u005cu0022:\"s3cr3t\",".repeat(20_000)));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(text ->
                assertFalse(Redactor.redact(text).contains("s3cr3t"), () -> text.substring(0, 60))));
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

    @Test
    void readsTheRestOfASecretFieldsObjectOnceForAllItsSecretFieldsInLinearTime() {
        // Automated review on b00189e: each secret field's strict reading read the rest of its object again, so an object
        // of n secret fields cost n squared (8,000 fields took 4.8 s). About 1 MB of them, bare and nested, in time that
        // grows with the text. Since #377 the structural path reads JSON whose names repeat as JSON it will not read, and
        // masks it whole; with the names spelled apart, each value is masked and every other byte kept.
        int n = 60_000;
        String fields = "{" + "\"password\":\"s3cr3t\",".repeat(n) + "\"n\":1}";
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            assertEquals(Redactor.MASK, Redactor.redact(fields));
            assertEquals("{\"body\":\"" + Redactor.MASK + "\"}", Redactor.redact(nested(fields)));
        });
        StringBuilder distinct = new StringBuilder("{");
        StringBuilder masked = new StringBuilder("{");
        for (int i = 0; i < 1 << "password".length(); i++) {
            StringBuilder name = new StringBuilder();
            for (int c = 0; c < "password".length(); c++) {
                char letter = "password".charAt(c);
                name.append((i >> c & 1) == 1 ? Character.toUpperCase(letter) : letter);
            }
            distinct.append('"').append(name).append("\":\"s3cr3t\",");
            masked.append('"').append(name).append("\":\"[REDACTED]\",");
        }
        String spelledApart = distinct.append("\"n\":1}").toString();
        String spelledApartMasked = masked.append("\"n\":1}").toString();
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            assertRedactsTo(spelledApartMasked, spelledApart);
            assertRedactsTo(nested(spelledApartMasked), nested(spelledApart));
        });
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
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // Codex security round 6: the stray quote inside the block closes "note" early, so the JWK read of the text as
        // it came never sees d as a member; masking the block takes the quote away, and 6304ec0 (PEM first) masked d.
        String pem = "{\"kty\":\"RSA\",\"note\":\"-----BEGIN PRIVATE KEY-----\"-----END PRIVATE KEY-----\",\"d\":\"FAKE_PRIVATE_KEY_293\"}";
        String pgp = pem.replace("PRIVATE KEY-----", "PGP PRIVATE KEY BLOCK-----");
        // 6304ec0 masked the block and d in the two raw inputs. Since #377 (review round 7) the structural path rejects
        // them (the stray quote is a read error) after decoding a string that opens the block, so the whole text is the
        // mask: the key material may sit in a later string.
        assertEquals(Redactor.MASK, Redactor.redact(pem));
        assertEquals(Redactor.MASK, Redactor.redact(pgp));
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
        cases.forEach((leaked, kept) -> assertRedactsTo(kept, leaked));
        // Ten repetitions do not spend it: d is in no object, and is kept.
        String few = "\"kty\":\"".repeat(10) + d;
        assertRedactsTo(few, few);
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
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342: the leak scanner must accept this as it is.
        String text = "{\"note\":\"a\nb\",\"body\":\"" + "\"kty\":\"RSA\",\"d\":\"dimension\"".replace("\"", "\\u0022") + "\"}";
        assertEquals(Redactor.MASK, Redactor.redact(text));
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
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342: the leak scanner's escaped-JWK test uses this output as its masked form.
        for (String before : List.of("he said \"\n", "he said \"\r\n")) {
            assertEquals(Redactor.MASK,
                    Redactor.redact(before + escapedEverything("{\"kty\":\"oct\",\"k\":\"FAKE_JWK_K_342\"}")));
        }
    }

    @Test
    void masksAJwkPrivateMemberWhoseNameIsQuotedWithUnicodeEscapesInAPlainQuotedJwk() {
        // #352: the name's quotes spelled ", the rest of the JWK plain-quoted; also the value's quotes only. Each is
        // masked with every other byte kept, bare and nested once and twice. The leak scanner's test of the same name
        // uses these outputs as its masked forms.
        String u = "\\u0022";
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("{\"kty\":\"oct\"," + u + "d" + u + ":\"PRIVD352\"}",
                "{\"kty\":\"oct\"," + u + "d" + u + ":\"[REDACTED]\"}");
        cases.put("{\"kty\":\"oct\"," + u + "d" + u + ":[\"PRIVD352\"]}",
                "{\"kty\":\"oct\"," + u + "d" + u + ":" + u + "[REDACTED]" + u + "}");
        cases.put("{\"kty\":\"oct\",\"d\":" + u + "PRIVD352" + u + "}",
                "{\"kty\":\"oct\",\"d\":" + u + "[REDACTED]" + u + "}");
        cases.put("{\"kty\":\"RSA\",\"n\":\"N1\"," + u + "d" + u + ":\"PRIVD352\"," + u + "p" + u + ":\"PRIVP352\",\"e\":\"AQAB\"}",
                "{\"kty\":\"RSA\",\"n\":\"N1\"," + u + "d" + u + ":\"[REDACTED]\"," + u + "p" + u + ":\"[REDACTED]\",\"e\":\"AQAB\"}");
        for (Map.Entry<String, String> c : cases.entrySet()) {
            String leaked = c.getKey();
            String masked = c.getValue();
            for (int depth = 0; depth < 3; depth++) {
                assertEquals(masked, Redactor.redact(leaked), "depth " + depth);
                assertEquals(masked, Redactor.redact(masked), "depth " + depth);
                leaked = nested(leaked);
                masked = nested(masked);
            }
        }
    }

    @Test
    void readsJwksWithUnicodeQuotedMembersInLinearTimeWithinTheNestedBudget() {
        // #352: the flattened view is read in the same walk of the levels as the other views, and spends its level's
        // nested budget, so each level's reads continue one budget and the work stays linear. About 1 MB each: JWKs with a
        // "-quoted member, names and values opening and closing on such quotes, and both nested once.
        String u = "\\u0022";
        String jwks = "[" + ("{\"kty\":\"oct\"," + u + "k" + u + ":\"PRIVK352\"},").repeat(30_000) + "{}]";
        // Security round 1: values read past an escaped quote, or quoted a level down, with whitespace escaped a level down.
        String b = String.valueOf((char) 92);
        String escapedQuotes = "{\"kty\":\"oct\"," + ("" + u + "k" + u + ":" + u + "PRIVK352" + b + b + u + "x" + u + ",").repeat(25_000)
                + "\"e\":1}";
        List<String> texts = List.of(jwks, nested(jwks), ("{\"kty\":\"oct\"," + u + "d" + u + ":[" + u).repeat(40_000),
                (u + "kty" + u + ":\"oct\",\"d\":" + u).repeat(60_000), escapedQuotes, nested(escapedQuotes),
                ("{\"kty\":\"oct\"," + u + "d" + u + ":" + b + "\"").repeat(40_000),
                nested(("{\"kty\":\"oct\"," + u + "d" + u + "\n:" + u).repeat(30_000)),
                // Security round 2: kty after a value quoted a level down, names quoted through an escape chain, and
                // values and structures that never close, read in the canonical form.
                ("{" + u + "d" + u + ":" + b + "\"PRIVK352" + b + "\",\"kty\":\"oct\"},").repeat(30_000),
                nested(("{\"kty\":\"oct\"," + b + "u005c" + u.substring(1) + "k" + u + ":[\"PRIVK352\"]},").repeat(20_000)),
                ("{\"kty\":\"oct\",\"d\":[\"PRIVK352").repeat(40_000), ("\"kty\":\"d\":\"PRIVK352").repeat(50_000),
                // Automated review on 697c3c9: a value opening on a long escape chain, then many quotes that might close it.
                "{\"kty\":\"oct\",\"d\":" + b + "u005c".repeat(60_000) + "u0022PRIVK352" + (b + "\",").repeat(60_000) + "\"}",
                // Automated review on 418139a: a JWK, then many strings each holding a delimiter that reads ambiguously.
                "[{\"kty\":\"oct\",\"d\":\"PRIVK352\"}," + ("\"" + b + b + "u002c\",").repeat(250_000) + "1]");
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> texts.forEach(text -> {
            List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
            String out = Redactor.redact(text, reads);
            assertFalse(out.contains("PRIVK352"), () -> text.substring(0, 60));
            Map<String, Integer> left = new LinkedHashMap<>();
            for (Redactor.DiscoveryRead read : reads) {
                Integer before = left.put(read.level(), read.after());
                assertTrue(before == null || before == read.before(), () -> "a fresh budget for " + read + " in " + reads);
                assertTrue(read.before() <= 4 * text.length() + 1024, () -> read + " in " + reads);
            }
        }));
        assertEquals(jwks.replace("PRIVK352", "[REDACTED]"), Redactor.redact(jwks));
    }

    @Test
    void masksAJwkValueThroughAnEscapedQuoteQuotedALevelDownOrAfterEscapedWhitespace() {
        // Security round 1 on #352, one of each shape the matrix covers (jwkSpellingInputs). A quote spelled as a unicode
        // escape after an escaped backslash, inside a unicode-quoted value, is an escaped quote a level down: the value
        // goes on to the quote that closes it there, and is masked whole.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String head = "{\"kty\":\"oct\"," + u + "d" + u + ":";
        assertEquals(head + u + "[REDACTED]" + u + "}", Redactor.redact(head + u + "PRIVSTART" + b + b + u + "PRIVTAIL" + u + "}"));
        // A value quoted a level down, which no reading of the JWK's level reads: masked to the end of the string holding
        // it (fail closed), quoted as the member's name is.
        assertEquals(head + u + "[REDACTED]" + u, Redactor.redact(head + b + "\"PRIVSTART" + b + "\"}"));
        assertEquals(head + u + "[REDACTED]" + u, Redactor.redact(head + b + "\"PRIVSTART" + b + "\",\"e\":\"AQAB\"}"));
        // Whitespace a level down, escaped there: a string keeps the text's quotes, an object is quoted as the name is.
        String nestedHead = "{\"body\":\"{" + b + "\"kty" + b + "\":" + b + "\"oct" + b + "\"," + b + u + "d" + b + u + ":";
        assertEquals(nestedHead + b + "n" + b + "\"[REDACTED]" + b + "\"}\"}",
                Redactor.redact(nestedHead + b + "n" + b + "\"PRIVSTART" + b + "\"}\"}"));
        assertEquals(nestedHead + b + "t" + b + u + "[REDACTED]" + b + u + "}\"}",
                Redactor.redact(nestedHead + b + "t{" + b + "\"x" + b + "\":" + b + "\"PRIVSTART" + b + "\"}}\"}"));
    }

    @Test
    void masksAJwkValueAfterANameQuotedThroughAnEscapeChainOrBeforeTheJwksKty() {
        // Security round 2 on #352, one of each shape the matrix adds (jwkSpellingInputs). A name quoted through an escape
        // chain: the value is masked whole, quoted as the name opens.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String chainHead = "{\"kty\":\"oct\"," + b + "u005c" + u.substring(1) + "d" + u + ":";
        String chainQuote = b + "u005c" + u.substring(1);
        assertEquals(chainHead + chainQuote + "[REDACTED]" + chainQuote + "}", Redactor.redact(chainHead + "[\"PRIVSTART\"]}"));
        assertEquals(chainHead + chainQuote + "[REDACTED]" + chainQuote + "}",
                Redactor.redact(chainHead + "{\"x\":\"PRIVSTART\"}}"));
        assertEquals(chainHead + chainQuote + "[REDACTED]" + chainQuote + "}", Redactor.redact(chainHead + "\"PRIVSTART\"}"));
        // The JWK's kty after a value quoted a level down, with or without a space before it: quoted as the name is.
        for (String tail : List.of(", \"kty\":\"oct\"}", ",\"kty\":\"oct\"}")) {
            assertEquals("{" + u + "d" + u + ":" + u + "[REDACTED]" + u + tail,
                    Redactor.redact("{" + u + "d" + u + ":" + b + "\"PRIVSTART" + b + "\"" + tail));
        }
        // ...and after a value holding an escaped backslash and a unicode quote.
        assertEquals("{" + u + "d" + u + ":" + u + "[REDACTED]" + u + ",\"kty\":\"oct\"}",
                Redactor.redact("{" + u + "d" + u + ":" + u + "PRIVSTART" + b + b + u + "PRIVTAIL" + u + ",\"kty\":\"oct\"}"));
        // Every kind of whitespace Java reads after a value is kept after its mask.
        for (char space : new char[] {' ', '\t', '\n', 0x0B, '\f', '\r', 0x1C, 0x1F, 0x1680, 0x2000, 0x2006, 0x2008, 0x200A,
                0x2028, 0x2029, 0x205F, 0x3000}) {
            String head = "{\"kty\":\"oct\"," + u + "d" + u + ":";
            assertEquals(head + "\"[REDACTED]\"" + space + "}", Redactor.redact(head + "\"PRIVSTART\"" + space + "}"),
                    () -> Integer.toHexString(space));
        }
    }

    @Test
    void masksWholeTheStringHoldingAJwkWhoseQuotesOrDelimitersReadAmbiguously() {
        // The bound (#352, liaison decision): where the quote reading is ambiguous, fail closed. A value holding an escaped
        // quote and a brace is bounded by its own quote level in the structural reading too, so the kty after it stays a
        // member of the JWK; and a delimiter spelled as an escape where no string is open to decode it is no delimiter of
        // that level, so the string holding it, or the text, is masked whole.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String chain = b + "u005c" + u.substring(1);
        String quoteDepth = "{" + chain + "d" + u + ":\"PRIVA" + b + "\",{PRIVB\",\"kty\":\"oct\"}";
        for (String form : List.of(quoteDepth, nested(quoteDepth), nested(nested(quoteDepth)))) {
            String out = Redactor.redact(form);
            assertFalse(out.contains("PRIVA") || out.contains("PRIVB"), out);
        }
        // Automated review on e7e4640: an escaped quote and a brace in an ordinary string do not close the object either.
        String note = "{\"note\":\"" + b + "\"}\"," + chain + "d" + u + ":\"PRIVA\",\"kty\":\"oct\"}";
        // Automated review on a7e04ee: also after a name opened plain and closed with a unicode escape.
        String mixed = "{\"note\":\"" + b + "\"}\",\"d" + u + ":" + chain + "PRIVA" + chain + ",\"kty\":\"oct\"}";
        // Automated review on 7aeccb5: and an escaped quote, a colon and a brace in an ordinary string.
        String colon = "{\"note\":\"x" + b + "\":}\"," + chain + "d" + u + ":\"PRIVA\",\"kty\":\"oct\"}";
        // Automated review on 3d4e81e: and that note before a name opened plain and closed with a unicode escape.
        String both = "{\"note\":\"x" + b + "\":}\",\"d" + u + ":" + b + "\"PRIVA" + b + "\",\"kty\":\"oct\"}";
        for (String form : List.of(note, nested(note), nested(nested(note)), mixed, nested(mixed), nested(nested(mixed)),
                colon, nested(colon), nested(nested(colon)), both, nested(both), nested(nested(both)))) {
            String out = Redactor.redact(form);
            assertFalse(out.contains("PRIVA"), out);
        }
        // ...and a name opened plain and closed with a unicode escape before a form feed or an escaped one reads no
        // object exactly, so the private member after it fails closed (#352, security round 3: over-flags accepted).
        for (String space : List.of(b + "f", b + "u000C", b + "u2028")) {
            String mixedName = "{\"note" + u + space + ":\"x," + u + "kty" + u + ":" + u + "oct" + u + "\",\"d\":\"dimension\"}";
            assertEquals(mixedName.replace("dimension", Redactor.MASK), Redactor.redact(mixedName));
        }
        String delimiter = "{\"x\":1" + b + "u002c" + chain + "d" + u + ":\"PRIVA\nPRIVB\",\"kty\":\"oct\"}";
        assertEquals(Redactor.MASK, Redactor.redact(delimiter));
        assertEquals("{\"body\":\"" + Redactor.MASK + "\"}", Redactor.redact(nested(delimiter)));
    }

    @Test
    void masksEveryPrivateMemberWhoseNameAndValueMixQuoteSpellingsAfterAnOrdinaryStringHoldingAQuoteAColonAndABrace() {
        // Security round 3 (#352): where the quotes do not read exactly, no reading may drop a private member's object,
        // so each such member in a text holding a kty is masked whole (fail closed), bare and nested once and twice.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String note = "{\"note\":\"x" + b + "\":}\",";
        for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k")) {
            for (String text : List.of(
                    note + "\"" + member + u + ":" + u + "PRIVA352PRIVB" + b + "\"," + b + "\"kty\":\"oct\"}",
                    note + b + "\"" + member + u + ":\"PRIVA352PRIVB" + u + ",\"kty\":\"oct\"}",
                    note + "\"" + member + b + "\":" + u + "PRIVA352PRIVB" + b + "\"," + b + "\"kty\":\"oct\"}",
                    // ...and escaped quotes in an ordinary string that, in a copy, close its object before the member.
                    "{\"kty\":\"oct\",\"a\":{\"note\":\"x" + b + "\"}," + b + "\"y" + b + "\":" + b + "\"z\",\"" + member
                            + "\":\"PRIVA352PRIVB\"}}")) {
                for (String form : List.of(text, nested(text), nested(nested(text)))) {
                    if (form == text && Canonical.isJson(form)) {
                        // Bare and one JSON value: the structural path (#377, #387) reads it exactly, and no JWK holds the
                        // member. Nested in a JSON string, the text engine also reads it as spelled and fails closed.
                        assertKept(form);
                        continue;
                    }
                    String out = Redactor.redact(form);
                    assertFalse(out.contains("PRIVA") || out.contains("352") || out.contains("PRIVB"), out);
                }
            }
        }
    }

    @Test
    void masksEveryPrivateMemberWithMixedQuoteSpellingsAfterALineSeparatorInAnEarlierOrdinaryString() {
        // Security round 4 (#352): what the canonical reading skips as prose is never left unread. A line separator,
        // paragraph separator or next-line character (or a raw line feed or carriage return) in an earlier ordinary string
        // starts such a stretch; every private member in it is masked whole whenever the text holds a kty, for all eight
        // members, bare and stringified once and twice.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        for (char separator : new char[] {0x2028, 0x2029, 0x85, '\n', '\r'}) {
            String note = "{\"note\":\"a" + separator + "b\",";
            for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
                for (String text : List.of(
                        note + "\"" + member + u + ":" + u + "PRIVA352PRIVB" + b + "\"," + b + "\"kty\":\"oct\"}",
                        note + b + "\"" + member + u + ":\"PRIVA352PRIVB" + u + ",\"kty\":\"oct\"}")) {
                    for (String form : List.of(text, nested(text), nested(nested(text)))) {
                        if (form == text && Canonical.isJson(form)) {
                            // Bare and one JSON value (a raw U+2028, U+2029 or U+0085 is allowed in a JSON string): the
                            // structural path (#377, #387) reads it exactly, and no JWK holds the member. Nested in a JSON
                            // string, the text engine also reads it as spelled and fails closed.
                            assertKept(form, Integer.toHexString(separator));
                            continue;
                        }
                        String out = Redactor.redact(form);
                        assertFalse(out.contains("PRIVA") || out.contains("352") || out.contains("PRIVB"),
                                () -> Integer.toHexString(separator) + ": " + out);
                    }
                }
            }
        }
    }

    @Test
    void masksAPrivateMemberAfterWhitespaceSpelledAsAUnicodeEscapeInSkippedProse() {
        // Automated review on ab0bc7d: whitespace before a name is read as the canonical form reads it, any escape of it
        // included, bare and stringified once and twice.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        // Automated review on 063cefd: also with the whitespace's backslash spelled as an escape.
        for (String space : List.of(b + "u0020", b + "u0009", b + b + "u0020", b + "u005c" + b + "u2003", b + "u005cn",
                b + "u005c" + b + "u005ct", b + "u005cu0020", b + b + "u005cr")) {
            String text = "{\"note\":\"a\nb\"," + space + "\"d" + u + ":" + u + "PRIVA352PRIVB" + b + "\"," + b + "\"kty\":\"oct\"}";
            for (String form : List.of(text, nested(text), nested(nested(text)))) {
                String out = Redactor.redact(form);
                assertFalse(out.contains("PRIVA") || out.contains("352") || out.contains("PRIVB"), out);
            }
        }
    }

    @Test
    void masksAPrivateMemberOpeningRightAfterASkippedProseStretchStartsBehindACommaOrBrace() {
        // Automated review on bcd1db2: a skipped prose stretch keeps the member place it starts in, so a name opening right
        // after its line break, behind a comma or a brace before it, is a member's: masked whole, for every separator and
        // member, bare and stringified once and twice.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        for (char separator : new char[] {0x2028, 0x2029, 0x85, '\n', '\r'}) {
            for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
                String name = separator + u + member + u + ":\"PRIVA352PRIVB\"";
                for (String text : List.of("{\"kty\":\"oct\",\"note\":\"x" + u + "," + name + "}",
                        "{\"kty\":\"oct\",\"note\":\"x" + u + "{" + name + "}",
                        "{\"note\":\"x" + u + "," + name + "," + u + "kty" + u + ":\"oct\"}")) {
                    for (String form : List.of(text, nested(text), nested(nested(text)))) {
                        String out = Redactor.redact(form);
                        assertFalse(out.contains("PRIVA") || out.contains("352") || out.contains("PRIVB"),
                                () -> Integer.toHexString(separator) + ": " + out);
                    }
                }
            }
        }
    }

    @Test
    void readsASkippedStretchStartingInAMemberPlaceWithLongLeadingSpacesInLinearTime() {
        // Automated review on f9317af: a skipped stretch that starts behind a comma, then 200,000 spaces and 200,000 quoted
        // words in no member's place, read the leading spaces again for each quote (288 KB took 8.7 s); it is read once.
        String u = String.valueOf((char) 92) + "u0022";
        String in = "{\"kty\":\"oct\",\"note\":\"x" + u + ",\n" + " ".repeat(200_000) + "\"a\" ".repeat(200_000) + "}";
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(in));
    }

    /** A dummy secret whose characters appear nowhere else in the texts below, nor in the mask. */
    private static final String SKIP_SECRET = "JGVWXZJGVWXZ";

    /** Every line separator spelling the grids below use: raw, escaped once, and as unicode escapes. */
    private static List<String> skipSeparators() {
        String b = String.valueOf((char) 92);
        return List.of("\n", "\r", "\r\n", "\u2028", "\u2029", "\u0085", b + "n", b + "r", b + "r" + b + "n",
                b + "u000a", b + "u000d", b + "u2028", b + "u2029", b + "u0085");
    }

    /**
     * {@code text} bare and nested in a JSON string at depths 1 to 3; and for every fifth {@code index}, at one depth of
     * the band around the levels the Redactor reads (one below, at, and one past {@link Redactor#NESTED_LEVELS}) in turn,
     * so the cases of a grid cover every shape, member, separator and depth of that band between them (a text nested 16
     * levels is about a megabyte).
     */
    private static List<String> skipDepths(String text, int index) {
        List<String> forms = new ArrayList<>();
        int last = index % 5 == 0 ? Redactor.NESTED_LEVELS - 1 + index / 5 % 3 : 3;
        String form = text;
        for (int depth = 0; depth <= last; depth++) {
            if (depth <= 3 || depth == last) {
                forms.add(form);
            }
            form = depth < last ? nested(form) : form;
        }
        return forms;
    }

    private static void assertNoSecretCharacter(String in, String label) {
        assertNoSecretCharacter(in, label, false);
    }

    /**
     * With {@code bare}, {@code in} is a grid's text as written, not nested in a JSON string. Bare and one JSON value, it
     * is read exactly by the structural path (#377, #387), which skips nothing; in these grids no JWK holds the private
     * member as JSON reads it, so the text is kept. Nested in a JSON string, the text engine also reads it as spelled.
     */
    private static void assertNoSecretCharacter(String in, String label, boolean bare) {
        if (bare && Canonical.isJson(in)) {
            assertKept(in, label);
            return;
        }
        String out = Redactor.redact(in);
        for (char c : SKIP_SECRET.toCharArray()) {
            assertTrue(out.indexOf(c) < 0, () -> label + ": " + out.substring(0, Math.min(out.length(), 300)));
        }
    }

    @Test
    void masksTheWholeTextWheneverASkipPreventsCompleteAnalysisOfAnEarlierOrdinaryString() {
        // The owner's rule (#352): whenever a skip prevents complete analysis, the whole text is masked. Every separator
        // spelling in an earlier ordinary string, all eight private members, with mixed quote spellings, bare and nested
        // one to three levels and across the band around the levels read (skipDepths): no character of the secret is left.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        int index = 0;
        for (String separator : skipSeparators()) {
            String note = "{\"note\":\"a" + separator + "b\",";
            for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
                for (String text : List.of(
                        note + "\"" + member + u + ":" + u + SKIP_SECRET + b + "\"," + b + "\"kty\":\"oct\"}",
                        note + b + "\"" + member + u + ":\"" + SKIP_SECRET + u + ",\"kty\":\"oct\"}")) {
                    List<String> forms = skipDepths(text, index++);
                    for (int f = 0; f < forms.size(); f++) {
                        assertNoSecretCharacter(forms.get(f), separator.codePoints().boxed().toList() + " " + member
                                + " form " + f, f == 0);
                    }
                }
            }
        }
    }

    @Test
    void masksTheWholeTextWheneverASkipEndsAtAPrivateMemberNameOrValue() {
        // The owner's rule (#352): a skip whose stretch ends right at a private member's name, or between its name and
        // its value, still masks the whole text. Every separator spelling, all eight private members, the kty before or
        // after, bare and nested one to three levels and across the band around the levels read (skipDepths): no
        // character of the secret is left.
        String b = String.valueOf((char) 92);
        String e = b + "\"";
        int index = 0;
        for (String separator : skipSeparators()) {
            String note = "\"note\":" + e + "a" + separator + "b, ";
            for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
                String atName = "\"" + member + "\": \"" + SKIP_SECRET + "\"";
                String atValue = e + member + e + ": \"" + SKIP_SECRET + "\"";
                for (String text : List.of("{\"kty\":\"oct\"," + note + atName + "}",
                        "{\"kty\":\"oct\"," + note + atValue + "}", "{" + note + atName + ", \"kty\":\"oct\"}",
                        "{" + note + atValue + ", \"kty\":\"oct\"}")) {
                    List<String> forms = skipDepths(text, index++);
                    for (int f = 0; f < forms.size(); f++) {
                        assertNoSecretCharacter(forms.get(f), separator.codePoints().boxed().toList() + " " + member
                                + " form " + f + " " + text, f == 0);
                    }
                }
            }
        }
    }

    @Test
    void masksAPrivateMemberWhoseNameTheExactReadingStopsIn() {
        // Automated review on 755dfdd: where the exact reading of the quotes stops inside a private member's name, which
        // object it is in is not established, so it fails closed whenever the text holds a kty: all eight members, the
        // kty after or before, bare and nested once and twice.
        String b = String.valueOf((char) 92);
        for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
            String name = b + "u005cu0022" + member + b + "u0022:\"" + SKIP_SECRET + "\"";
            for (String text : List.of("{\"note\":\"x" + b + "u0022," + name + ",\"kty\":\"oct\"}",
                    "{\"kty\":\"oct\",\"note\":\"x" + b + "u0022," + name + "}")) {
                for (String form : List.of(text, nested(text), nested(nested(text)))) {
                    assertNoSecretCharacter(form, member + " " + form, form == text);
                }
            }
        }
    }

    @Test
    void masksAPrivateValueWhoseContentEndsInEscapedBackslashesBeforeItsClosingQuote() {
        // Automated review on 582cd72: backslashes escaped before a value's closing quote are its content, so a value of
        // only such backslashes is not empty and the mask followed by them is not the mask: each is masked, for all eight
        // members, with the name quoted plain or with unicode escapes, bare and nested once and twice.
        String b = String.valueOf((char) 92);
        for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth")) {
            for (String name : List.of(b + "u005cu0022" + member + b + "u0022", b + "u0022" + member + b + "u0022")) {
                for (String content : List.of(b + b, b + b + b + b, Redactor.MASK + b + b)) {
                    String text = "{\"kty\":\"oct\"," + name + ":\"" + content + "\"}";
                    for (String form : List.of(text, nested(text), nested(nested(text)))) {
                        String out = Redactor.redact(form);
                        assertFalse(out.equals(form), () -> member + " " + form);
                    }
                }
            }
        }
    }

    @Test
    void keepsAPrivateMemberOfAnObjectWithoutAKtyWhoseOrdinaryStringHoldsABrace() {
        // Automated review on e05c98c: plain JSON reads exactly, so a brace in an ordinary string closes no object and a
        // d in an object without a kty is kept, inside a JWK or not, bare and nested.
        String text = "{\"kty\":\"oct\",\"a\":{\"note\":\"}\",\"d\":\"dimension\"}}";
        for (String form : List.of(text, nested(text), nested(nested(text)))) {
            assertEquals(form, Redactor.redact(form));
        }
        // An escaped quote in that string could be the object's own in a copy, but the text is one JSON value, which the
        // structural path (#377, #387) reads exactly: the d is in an object without a kty, so it is kept.
        String escaped = "{\"kty\":\"oct\",\"a\":{\"note\":\"x\\\"}\",\"d\":\"dimension\"}}";
        assertKept(escaped);
    }

    @Test
    void readsAPrivateMembersValueThroughARawLineBreakToTheKtyAfterIt() {
        // Automated review on 4ca9093: a string opening right after a private member's colon is its value, not prose
        // quoting a copy, so a raw line break in it does not end the reading before the JWK's kty.
        String b = String.valueOf((char) 92);
        // Automated review on 697c3c9: also with the name's letter spelled as a unicode escape.
        for (String text : List.of("{" + b + "u005cu0022d" + b + "u0022:\"PRIVA\nPRIVB\",\"kty\":\"oct\"}",
                "{" + b + "u005cu0022" + b + "u0064" + b + "u0022:\"PRIVA\nPRIVB\",\"kty\":\"oct\"}",
                // Automated review on 9a86a8e: and with whitespace escaped around the colon.
                "{" + b + "u005cu0022d" + b + "u0022" + b + "n:" + b + "t\"PRIVA\nPRIVB\",\"kty\":\"oct\"}",
                // Automated review on 2ec9796: a name letter spelled through a chain, and a form feed around the colon.
                "{" + b + "u005cu0022" + b + "u005cu0064" + b + "u0022:\"PRIVA\nPRIVB\",\"kty\":\"oct\"}",
                "{\"d\"\f:\f\"PRIVA\nPRIVB\",\"kty\":\"oct\"}")) {
            for (String form : List.of(text, nested(text))) {
                String out = Redactor.redact(form);
                assertFalse(out.contains("PRIVA") || out.contains("PRIVB"), out);
            }
        }
    }

    @Test
    void boundsAValueByItsOpeningQuotesSpellingAndAStructureByItsUnclosedReading() {
        // Automated review on 253416a: an escaped quote inside a value quoted with a unicode escape is a level deeper read
        // flattened, so it does not close it; and a structure one reading leaves unclosed is masked to the end.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String chain = b + "u005c" + u.substring(1);
        for (String text : List.of("{\"kty\":\"oct\"," + chain + "d" + u + ":" + u + "PRIVSTART" + b + "\",PRIVTAIL" + u + "}",
                "{\"kty\":\"oct\"," + chain + "d" + u + ":{\"x\":\"},PRIVTAIL\"")) {
            for (String form : List.of(text, nested(text), nested(nested(text)))) {
                String out = Redactor.redact(form);
                assertFalse(out.contains("PRIVSTART") || out.contains("PRIVTAIL"), out);
            }
        }
    }

    @Test
    void readsTheMembersAfterProseInAStringClosedWithAUnicodeQuoteAndKeepsAnOddlySpelledKtyInAString() {
        // Automated review on 6ec18ce: the string holding the prose may close with a unicode escape of a quote, and a kty
        // whose quote no rule places is still no member while a string is open around it.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String text = "{\"note\":" + u + "x " + b + "\"" + b + "n" + u + "," + u + "d" + u + ":" + b + "\"VALUE352" + b
                + "\",\"kty\":\"oct\"}";
        for (String form : List.of(text, nested(text), nested(nested(text)))) {
            String out = Redactor.redact(form);
            assertFalse(out.contains("VALUE352"), out);
        }
        // A kty name opened with a quote two levels down inside a one-level string, and a name holding unicode quotes and
        // colons, read no object exactly in the text engine: the private member after them fails closed (#352, security
        // round 3) wherever the text engine reads the text as it is spelled, so nested in a JSON string. Bare, each text
        // is one JSON value, which the structural path (#377, #387) reads exactly: the kty is inside a string and the d
        // is kept.
        String chained = "{\"note\":\"x," + b + "u005c" + u + "kty" + u + ":" + u + "oct" + u + "\",\"d\":\"dimension\"}";
        String name = "{\"note" + u + ": x," + u + "kty" + u + ":" + u + "oct" + u + "\":1,\"d\":\"dimension\"}";
        for (String bare : List.of(chained, name)) {
            assertKept(bare);
            assertRedactsTo(nested(bare).replace("dimension", Redactor.MASK), nested(bare));
        }
    }

    @Test
    void readsTheMembersAfterAStringHoldingAStrayQuoteAndALineBreakALevelDown() {
        // Automated review on 9192663: a stray quote and a line break escaped inside one string end what the canonical
        // reading skips at that string's close, so the members after it are read; and a unicode quote that a colon follows
        // closes only a name, not a value, so a kty inside the note is still no member.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String text = "{\"note\":\"x " + b + "\"" + b + "n\"," + u + "d" + u + ":" + b + "\"PRIVSTART" + b + "\",\"kty\":\"oct\"}";
        for (String form : List.of(text, nested(text), nested(nested(text)))) {
            String out = Redactor.redact(form);
            assertFalse(out.contains("PRIVSTART"), out);
        }
        // A kty name whose opening quote closes the note's inner string reads no name exactly in the text engine, so it
        // fails closed nested in a JSON string (#352, security round 3). Bare, the text is one JSON value, which the
        // structural path (#377, #387) reads exactly: the kty is inside the note and the d is kept.
        String stray = "{\"note\":\"x" + u + ": x," + u + "kty" + u + ":" + u + "oct" + u + "\",\"d\":\"dimension\"}";
        assertKept(stray);
        assertRedactsTo(nested(stray).replace("dimension", Redactor.MASK), nested(stray));
    }

    @Test
    void masksAPrivateMemberAfterANameClosedWithAUnicodeEscapeAndKeepsAKtyInsideAStringAtAnyDepth() {
        // Automated review on 45b52d4: a name opened plain and closed with a unicode escape closes the string its opening
        // quote opened, so a unicode-quoted d after it is a member of the JWK; and a kty inside a note is no member however
        // deep the text is nested.
        String b = String.valueOf((char) 92);
        String u = b + "u0022";
        String text = "{\"note" + u + ":" + b + "\"text" + b + "\"," + u + "d" + u + ":\"PRIVD352\",\"kty\":\"oct\"}";
        for (String form : List.of(text, nested(text), nested(nested(text)))) {
            String out = Redactor.redact(form);
            assertFalse(out.contains("PRIVD352"), out);
            assertTrue(out.contains("[REDACTED]"), out);
        }
        // A kty spelled with quotes a level down inside a note may be the object's own in a copy, so the d after it fails
        // closed however deep the text is nested in JSON strings, which the text engine also reads as spelled (#352,
        // security round 3: over-flags accepted). Bare, the text is one JSON value, which the structural path (#377, #387)
        // reads exactly: the kty is inside the note and the d is kept.
        String copied = "{\"note\":\"x," + u + "kty" + u + ":" + u + "oct" + u + "\",\"d\":\"dimension\"}";
        assertKept(copied);
        for (int depth = 1; depth <= 6; depth++) {
            copied = nested(copied);
            assertRedactsTo(copied.replace("dimension", Redactor.MASK), copied, "depth " + depth);
        }
    }

    @Test
    void keepsAPrivateMemberWhoseObjectHoldsAKtyOnlyInsideAString() {
        // Automated review on 469b848 and 84fe061: a kty quoted a level down inside a string value is no member of the
        // object as JSON reads it, but in a copy those quotes may be the object's own, so which object the d is in is not
        // established and it fails closed wherever the text engine reads the text as spelled, nested in a JSON string
        // (#352, security round 3: over-flags accepted). Bare, each text is one JSON value, which the structural path
        // (#377, #387) reads exactly, so the d is kept. With no kty in the text, it is kept.
        String b = String.valueOf((char) 92);
        for (String text : List.of("{\"note\":\"x," + b + "\"kty" + b + "\":" + b + "\"oct" + b + "\"\",\"d\":\"dimension\"}",
                "{\"note\":\"x, " + b + "\"kty" + b + "\": " + b + "\"oct" + b + "\"\", \"d\": \"dimension\"}",
                // ...also spelled with unicode escapes, a quote of the level below inside the note.
                "{\"note\":\"x," + b + "u0022kty" + b + "u0022:" + b + "u0022oct" + b + "u0022\",\"d\":\"dimension\"}")) {
            assertKept(text);
            assertRedactsTo(nested(text).replace("dimension", Redactor.MASK), nested(text));
            String noKty = text.replace("kty", "kid");
            assertKept(noKty);
            assertKept(nested(noKty));
        }
    }

    @Test
    void masksEveryUnicodeQuotedPrivateMemberOnceTheFlattenedViewSpendsItsBudget() {
        // #352: repeated kty syntax spends the JWK search's budget, as in readsJwksAfterPrivateKeyBlocksWithinTheBudgetLeft,
        // and then every private member name in the flattened view is masked, in a JWK or not: this d is in none.
        String u = "\\u0022";
        String text = "\"kty\":\"".repeat(200) + u + "d" + u + ":\"PRIVD352\"";
        List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
        String out = Redactor.redact(text, reads);
        assertFalse(out.contains("PRIVD352"), () -> out.substring(out.length() - 80));
        assertTrue(out.endsWith(u + "d" + u + ":\"[REDACTED]\""), () -> out.substring(out.length() - 80));
        // The plain read spends its budget too, but finds no plain-quoted d; the flattened view's read masks it.
        assertTrue(reads.stream().anyMatch(read -> read.level().equals("nested 1") && read.after() < 0), reads::toString);
    }

    @Test
    void keepsAPrivateMemberQuotedWithUnicodeEscapesOutsideAJwk() {
        // #352: with no kty in the text, a d quoted with " is an ordinary name and is kept.
        String u = "\\u0022";
        String text = "{\"kid\":\"oct\"," + u + "d" + u + ":\"dimension\"}";
        assertEquals(text, Redactor.redact(text));
        assertEquals(nested(text), Redactor.redact(nested(text)));
        // With a kty elsewhere in the text, a name quoted with unicode escapes where no string is open reads no object
        // exactly, so it fails closed (#352, security round 3: over-flags accepted).
        String elsewhere = "{\"a\":{\"kty\":\"oct\"},\"b\":{" + u + "d" + u + ":\"dimension\"}}";
        assertEquals("{\"a\":{\"kty\":\"oct\"},\"b\":{" + u + "d" + u + ":" + u + Redactor.MASK + u + "}}",
                Redactor.redact(elsewhere));
        assertFalse(Redactor.redact(nested(elsewhere)).contains("dimension"));
    }

    /**
     * The JWK spelling matrix (#352, security rounds 1 and 2): every private member, with its name's and its value's
     * quotes each spelled plain, as a unicode escape, escaped one level down or through an escape chain, whitespace
     * around its colon and after its value, the JWK's plain-quoted kty before or after it, bare and nested once and
     * twice. The inputs, in order; the scanner's test reads them from the grid this test writes.
     */
    private static List<String> jwkSpellingInputs() {
        String bs = String.valueOf((char) 92);
        String u = bs + "u0022";
        // A quote escaped through a chain: an escaped backslash spelled as a unicode escape, then a unicode quote.
        String chain = bs + "u005c" + u.substring(1);
        List<String[]> nameQuotes = List.of(new String[] {"\"", "\""}, new String[] {u, u}, new String[] {"\"", u},
                new String[] {chain, u});
        List<String> values = List.of(
                "\"PRIVSTART\"",
                u + "PRIVSTART" + u,
                bs + "\"PRIVSTART" + bs + "\"",
                // An escaped backslash and a unicode quote inside a unicode-quoted value: the flattened view reads that
                // quote as an escaped one a level down, so the value goes on to PRIVTAIL.
                u + "PRIVSTART" + bs + bs + u + "PRIVTAIL" + u,
                "\"PRIVSTART" + u + "PRIVTAIL\"",
                u + "PRIVSTART\"",
                "{\"x\":\"PRIVSTART\"}",
                "[\"PRIVSTART\"]",
                // A value quoted \" holding an escaped quote a level further down, then a comma (automated review on
                // 469b848): that quote does not close the value.
                bs + "\"PRIVSTART" + bs + bs + u + ",PRIVTAIL" + bs + "\"");
        // Before the colon, after it, and after the value (every other kind of whitespace Java reads there:
        // masksAJwkValueAfterANameQuotedThroughAnEscapeChainOrBeforeTheJwksKty).
        List<String[]> spaces = List.of(new String[] {"", "", ""}, new String[] {"\n", "", "\n"},
                new String[] {"", "\t", " "}, new String[] {"\r", " ", "\t"});
        List<String> inputs = new ArrayList<>();
        for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k")) {
            for (String[] quote : nameQuotes) {
                for (String value : values) {
                    for (String[] space : spaces) {
                        String field = quote[0] + member + quote[1] + space[0] + ":" + space[1] + value + space[2];
                        for (String raw : List.of("{\"kty\":\"oct\"," + field + "}", "{" + field + ",\"kty\":\"oct\"}")) {
                            inputs.add(raw);
                            inputs.add(nested(raw));
                            inputs.add(nested(nested(raw)));
                        }
                    }
                }
            }
        }
        // The bound (#352, liaison decision): a name quoted through an escape chain that decodes at the last level read
        // (NESTED_LEVELS) and one past it, and a JWK nested NESTED_LEVELS levels deep and one past it. Inside the bound
        // the value is masked where it is; past it the string holding it is masked whole.
        String atBound = bs + "u005c".repeat(Redactor.NESTED_LEVELS - 1) + "u0022";
        String pastBound = bs + "u005c".repeat(Redactor.NESTED_LEVELS) + "u0022";
        for (String member : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k")) {
            for (String boundChain : List.of(atBound, pastBound)) {
                String field = boundChain + member + u + ":\"PRIVSTART\"";
                inputs.add("{\"kty\":\"oct\"," + field + "}");
                inputs.add("{" + field + ",\"kty\":\"oct\"}");
            }
        }
        String deep = "{\"kty\":\"oct\",\"d\":\"PRIVSTART\"}";
        for (int depth = 0; depth < Redactor.NESTED_LEVELS + 1; depth++) {
            deep = nested(deep);
            if (depth >= Redactor.NESTED_LEVELS - 1) {
                inputs.add(deep);
            }
        }
        return inputs;
    }

    @Test
    void masksEveryJwkPrivateMemberHoweverItsQuotesAndWhitespaceAreSpelledAndWritesTheOutputsForTheScanner()
            throws Exception {
        // Security round 1 on #352: a unicode-quoted name with a value quoted \" one level down, escaped whitespace around
        // the colon a level down, and an escaped quote inside a unicode-quoted value each left the value, or the part of
        // it after that quote, unmasked. Round 2: so did a name quoted through an escape chain, and a kty after the value. No byte of any value may survive; the outputs must match the committed
        // scanner-grids/jwk-spelling-grid.json.gz, where replay/test/leaks.test.mjs checks that the scanner flags every
        // input, accepts every output, and rejects each output with a secret continuation after its mask.
        List<String[]> pairs = new ArrayList<>();
        List<String> wrong = new ArrayList<>();
        for (String input : jwkSpellingInputs()) {
            String out = Redactor.redact(input);
            pairs.add(new String[] {input, out});
            if (out.contains("PRIVSTART") || out.contains("PRIVTAIL") || !out.contains(Redactor.MASK)) {
                wrong.add(input + " => " + out);
            }
        }
        assertEquals(List.of(), wrong, () -> wrong.size() + " of " + pairs.size() + " texts are wrong, first: "
                + wrong.subList(0, Math.min(5, wrong.size())));
        assertScannerGrid("jwk-spelling-grid", pairs);
    }

    @Test
    void masksACopiedJwkWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                    assertEquals(Redactor.MASK,
                            Redactor.redact(before + form.apply("FAKE_JWK_K_342") + after));
                }
            }
        }
    }

    @Test
    void keepsALooseKtyInACopiedValueWithMixedQuoteEscapesAfterAStrayQuoteAndARawLineBreak() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on c4ffeef and 39dd7ff): the leak scanner must accept each as it is.
        String u = "\\u0022";
        String b = "\\\"";
        List<String> before = List.of("", u + "a" + u + ":0,", u + "a" + u + ":0," + u + "b" + u + ":" + u + "x" + u + ",",
                u + "a" + u + ":{" + u + "x" + u + ":1},", u + "a" + u + ":[1," + u + "y" + u + "],");
        for (String lb : List.of("\n", "\r\n")) {
            for (String members : before) {
                String text = "he said \"" + lb + "{" + b + "body" + b + ":" + b + members + u + "kty" + u + ":" + u + "RSA" + u
                        + "," + u + "d" + u + ":" + u + "dimension" + u + b + "}";
                // #352 security round 4: a private member in prose the canonical reading skips fails closed when the
                // text holds a kty name (over-flags accepted), masked as its name is quoted.
                // With nothing before it, the kty opens no member (it follows the body's opening quote), so the d is kept.
                assertEquals(Redactor.MASK, Redactor.redact(text));
            }
        }
    }

    @Test
    void keepsAKtyThatOpensNoMemberInACopiedValueAfterAStrayQuote() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 0ab5aeb): only the first string after { or , is a member name, so a kty after a
        // value with no comma makes no JWK. The leak scanner's test of the same form uses these outputs.
        String b = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String mid : List.of("0 ", b + "a" + b + " ", "{" + b + "y" + b + ":1} ", "[1] ")) {
                String text = "he said \"" + lb + "{" + b + "x" + b + ":" + mid + b + "kty" + b + ":" + b + "RSA" + b + ","
                        + b + "d" + b + ":" + b + "dimension" + b + "}";
                assertEquals(Redactor.MASK, Redactor.redact(text));
            }
            for (String mid : List.of("0,", "0 , ", "0, x ", "{" + b + "y" + b + ":1},", "[1],")) {
                String form = "he said \"" + lb + "{" + b + "x" + b + ":" + mid + b + "kty" + b + ":" + b + "RSA" + b + ","
                        + b + "d" + b + ":" + b + "%s" + b + "}";
                assertEquals(Redactor.MASK, Redactor.redact(form.formatted("FAKE_PRIVATE_KEY_342")));
            }
        }
    }

    @Test
    void keepsAKtyThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                    assertEquals(Redactor.MASK, Redactor.redact(text));
                }
                for (String mid : List.of("0,", "0, x ")) {
                    String form = "{\"x\":" + mid + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals(Redactor.MASK,
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void keepsAKtyAfterAnOddNumberOfQuotesInAnEscapedCopyAfterAStrayQuote() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 9a3e247): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String before : List.of("\"\"a\":0,", "\"a\":\"b\"c\",")) {
                    String text = "he said \"" + lb + encode.apply("{" + before + "\"kty\":\"RSA\",\"d\":\"dimension\"}");
                    // #352 security round 4: a private member in prose the canonical reading skips fails closed when the
                    // text holds a kty name (over-flags accepted), masked as its name is quoted.
                    assertEquals(Redactor.MASK, Redactor.redact(text));
                }
                for (String before : List.of("\"a\":0,", "")) {
                    String form = "{" + before + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals(Redactor.MASK,
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void keepsAPrivateMemberThatOpensNoMemberInAnEscapedCopyAfterAStrayQuote() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated reviews on fa4fd1d and 223512b): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String mid : List.of("0 ", "\"a\" ", "{\"y\":1} ", "[1] ", "\"\"a\":0,", "\"b\"c\",")) {
                    String text = "he said \"" + lb + encode.apply("{\"kty\":\"RSA\",\"x\":" + mid + "\"d\":\"dimension\"}");
                    // #352 security round 4: a private member in prose the canonical reading skips fails closed when the
                    // text holds a kty name (over-flags accepted), masked as its name is quoted.
                    // A d after a value and a space is in no member's place, so it is still kept.
                    assertEquals(Redactor.MASK, Redactor.redact(text));
                }
                for (String mid : List.of("0,", "0, y ", "[1],", "\"b\"c\"\",")) {
                    String form = "{\"kty\":\"RSA\",\"x\":" + mid + "\"d\":\"%s\"}";
                    assertEquals(Redactor.MASK,
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
            }
        }
    }

    @Test
    void readsJwksInAnEscapedCopyAfterAStrayQuoteAsItsSearchFindsThem() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 65e1e7f): the leak scanner's test of the same name uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"),
                text -> text.replace("\"", "\\\\u0022"),
                text -> escapedForJson(escapedForJson(text)));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String before : List.of("\"{\":\"\"a\":0,", "\"[\":\"\"a\":0,\"b\":{", "\"a\":\"{\",")) {
                    String form = "{" + before + "\"kty\":\"RSA\",\"d\":\"%s\"}";
                    assertEquals(Redactor.MASK,
                            Redactor.redact("he said \"" + lb + encode.apply(form.formatted("FAKE_PRIVATE_KEY_342"))));
                }
                String colons = "he said \"" + lb + encode.apply("{\"kty\":\"RSA\",\"d\"::\"dimension\"}");
                assertEquals(Redactor.MASK, Redactor.redact(colons));
            }
        }
    }

    @Test
    void readsAPrivateMemberValueThroughItsLineBreaksAndOnlyAsciiWhitespaceAroundAColon() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 7050fef): the leak scanner's test of the same form uses these outputs.
        List<java.util.function.UnaryOperator<String>> encodings = List.of(
                text -> text.replace("\"", "\\u0022"), text -> text.replace("\"", "\\\\u0022"));
        for (String lb : List.of("\n", "\r\n")) {
            for (var encode : encodings) {
                for (String value : List.of("\\nTAIL", "\\r\\nTAIL", "\\n")) {
                    String text = "he said \"" + lb + encode.apply("{\"kty\":\"oct\",\"k\":\"" + value + "\"}");
                    assertEquals(Redactor.MASK, Redactor.redact(text));
                }
                for (String space : List.of("\u00a0", "\u2003", "\u3000")) {
                    for (String form : List.of("{\"kty\"" + space + ":\"oct\",\"k\":\"dimension\"}",
                            "{\"kty\":\"oct\",\"k\"" + space + ":\"dimension\"}", "{\"kty\":\"oct\",\"k\":" + space + "\"dimension\"}")) {
                        String text = "he said \"" + lb + encode.apply(form);
                        // #352 security round 4: a private member in prose the canonical reading skips fails closed when the
                        // text holds a kty name (over-flags accepted), masked as its name is quoted.
                        // A no-break space is no whitespace to Java, so with it no kty or k name reads and the d is kept.
                        assertEquals(Redactor.MASK,
                                Redactor.redact(text));
                    }
                }
            }
        }
    }

    @Test
    void masksAJwkCopiedAfterTwoStrayQuotesAndEndsAValueAtABackslashBeforeALineBreak() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 5173e8e): the leak scanner's test of the same form uses these outputs.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\"}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String before : List.of("he said \"" + lb + "he said \"" + lb, "he said \"" + lb + "x\"" + lb + "more" + lb, "\"" + lb + "\"" + lb)) {
                assertEquals(Redactor.MASK,
                        Redactor.redact(before + escapedForJson(jwk.formatted("FAKE_JWK_K_342"))));
            }
            // #352 security round 4: a k value cut at a line break in skipped prose is masked to its close (fail closed).
            String cut = "he said \"" + lb + escapedForJson("{\"kty\":\"oct\",\"k\":\"[REDACTED]\\" + lb + "TAIL\"}");
            assertEquals(Redactor.MASK, Redactor.redact(cut));
        }
    }

    @Test
    void masksACopiedValueAfterABackslashAndARawUnicodeLineBreakAndReadsNoFormFeedEscapeAsWhitespace() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                    assertEquals(Redactor.MASK, Redactor.redact(in));
                }
            }
            for (String value : List.of("true", "1", "{}", b + "FAKE_JWK_K_342" + b)) {
                for (String form : List.of("{%1$skty%1$s:%1$soct%1$s,%1$sk%1$s:\\f%2$s}", "{%1$skty%1$s:%1$soct%1$s,%1$sk%1$s\\f:%2$s}",
                        "{%1$skty%1$s\\f:%1$soct%1$s,%1$sk%1$s:%2$s}")) {
                    // #352 security round 4: in prose the canonical reading skips, a k after a kty fails closed (over-flags
                    // accepted): its value is masked, quoted as its name is.
                    String kept = "he said \"" + lb + form.formatted(b, value);
                    assertEquals(Redactor.MASK, Redactor.redact(kept));
                }
            }
            String formFeed = "he said \"" + lb + "{" + b + "kty" + b + ":" + b + "oct" + b + "," + b + "k" + b + ":\\u000ctrue}";
            assertEquals(Redactor.MASK,
                    Redactor.redact(formFeed));
        }
    }

    @Test
    void readsPastALineBreakSpelledAsAUnicodeEscapeInAValueAndMasksACopyAfterAPairedStrayString() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                        assertEquals(Redactor.MASK, Redactor.redact("he said \"" + lb + jwk.apply(q, k)));
                    }
                }
                // #352 security round 4: a value holding more than the mask in skipped prose is masked to its close.
                String tail = "he said \"" + lb + jwk.apply(q, "[REDACTED]\\u005c\\nTAIL");
                assertEquals(Redactor.MASK, Redactor.redact(tail));
            }
            for (String before : List.of("\"" + lb + "\",\"body\":", "\"" + lb + "\",\"b\":1,\"body\":", "x\"" + lb + "\",\"body\":")) {
                assertEquals(before.startsWith("x") ? before + jwk.apply(b, "[REDACTED]") : Redactor.MASK, Redactor.redact(before + jwk.apply(b, "FAKE_JWK_K_342")));
            }
        }
    }

    @Test
    void masksACopyCutOffInHalfAnEscapeAndANestOfPairedStrayStrings() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 5ca573a): the leak scanner's test of the same form relies on these outputs.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\"}";
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\", "\\u0", "\\u00", "\\u002", "\\\\\\")) {
                String masked = "he said \"" + lb + escapedForJson(jwk.formatted("[REDACTED]")) + tail;
                assertEquals(Redactor.MASK, Redactor.redact("he said \"" + lb + escapedForJson(jwk.formatted("FAKE_JWK_K_342")) + tail));
                assertEquals(Redactor.MASK, Redactor.redact(masked));
            }
            for (int pad : List.of(500, 2000, 10000)) {
                String leaked = "{\"kty\":\"oct\",\"k\":\"FAKE_JWK_K_342\",\"pad\":\"" + "x".repeat(pad) + "\"}";
                String masked = "{\"kty\":\"oct\",\"k\":\"[REDACTED]\",\"pad\":\"" + "x".repeat(pad) + "\"}";
                for (int i = 0; i < 3; i++) {
                    leaked = "\"" + lb + "\"" + lb + escapedForJson(leaked);
                    masked = "\"" + lb + "\"" + lb + escapedForJson(masked);
                }
                assertEquals(Redactor.MASK, Redactor.redact(leaked));
                assertEquals(Redactor.MASK, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksAJwkPrivateMemberWhoseOpeningQuoteIsEscapedOneLevelMore() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 32194d8): the leak scanner's test of the same form uses these outputs.
        List<String> forms = List.of("{\"kty\":\"oct\",\\\"k\":\"%1$s\"}", "{\"kty\":\"oct\", \\\"d\":\"%1$s\"}",
                "{\"kty\":\"RSA\",\"n\":\"AQAB\",\\\"d\":\"%1$s\",\\\"p\":\"%1$s\"}");
        for (String lb : List.of("\n", "\r\n")) {
            for (String form : forms) {
                String masked = "he said \"" + lb + escapedForJson(form.formatted("[REDACTED]"));
                assertEquals(Redactor.MASK, Redactor.redact("he said \"" + lb + escapedForJson(form.formatted("FAKE_JWK_K_342"))));
                assertEquals(Redactor.MASK, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksACopyThatEndsInAMalformedUnicodeEscape() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 92f3ad6): the leak scanner's test of the same form uses these outputs.
        List<String> forms = List.of("{\"kty\":\"oct\",\"k\":\"%s\"}", "{\"password\":\"%s\"}");
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String form : forms) {
                    String masked = "he said \"" + lb + escapedForJson(form.formatted("[REDACTED]")) + tail;
                    assertEquals(form.contains("kty") ? Redactor.MASK : masked, Redactor.redact("he said \"" + lb + escapedForJson(form.formatted("FAKE_JWK_K_342")) + tail));
                    assertEquals(form.contains("kty") ? Redactor.MASK : masked, Redactor.redact(masked));
                }
            }
        }
    }

    @Test
    void readsAFormFeedEscapeAfterARepairedMalformedUnicodeEscape() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on a7d0f8f): the leak scanner's test of the same form relies on these outputs.
        String q = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String pre : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String value : List.of("true", q + "FAKE_JWK_K_342" + q)) {
                    String colon = "he said \"" + lb + pre + "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":\\f" + value + "}";
                    String kty = "he said \"" + lb + pre + "{" + q + "kty" + q + "\\f:" + q + "oct" + q + "," + q + "k" + q + ":" + value + "}";
                    // #352 security round 4: in skipped prose the k after a kty fails closed (over-flags accepted).
                    assertEquals(Redactor.MASK, Redactor.redact(colon));
                    assertEquals(Redactor.MASK, Redactor.redact(kty));
                }
                String masked = "he said \"" + lb + pre + "{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q + "[REDACTED]" + q + "}";
                assertEquals(Redactor.MASK, Redactor.redact(masked.replace("[REDACTED]", "FAKE_JWK_K_342")));
                assertEquals(Redactor.MASK, Redactor.redact(masked));
            }
        }
    }

    @Test
    void masksANestedCopyThatEndsInAMalformedUnicodeEscape() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                    assertEquals(Redactor.MASK, Redactor.redact(leaked + tail));
                    assertEquals(Redactor.MASK, Redactor.redact(masked + tail));
                }
            }
        }
    }

    @Test
    void masksACopiedSecretValueCutOffInAMalformedUnicodeEscape() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on 058e89a): the leak scanner's test of the same form relies on these outputs.
        String q = "\\\"";
        for (String lb : List.of("\n", "\r\n")) {
            for (String tail : List.of("\\uZ", "\\u0Z", "\\u00G")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + q;
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact("he said \"" + lb + head + "[REDACTED]" + tail));
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact("he said \"" + lb + head + "FAKE_JWK_K_342" + tail));
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact(masked));
                }
            }
        }
    }

    @Test
    void masksACopiedSecretValueCutOffInHalfAUnicodeEscape() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (Codex security round 2 at 8a06f7e): the leak scanner's test of the same form relies on these outputs.
        // Half an escape inside a value still open at the end is masked with it. After a closed secret value it is masked
        // too, as no strict reading reads past it (Codex round 5 on 8e6f207); after a JWK member's value it is kept, and
        // after a close brace it is kept everywhere.
        String q = "\\\"";
        for (String tail : List.of("\\u", "\\u0", "\\u00", "\\u005")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + q;
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact("he said \"" + lb + head + "[REDACTED]" + tail));
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact("he said \"" + lb + head + tail));
                    // #352 security round 4: after a JWK member's value too, as the skipped prose reads it unclosed.
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked, Redactor.redact(masked + tail));
                    assertEquals(head.contains("kty") ? Redactor.MASK : masked + "}" + tail, Redactor.redact(masked + "}" + tail));
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
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342 (automated review on b9d6038): the leak scanner's test of the same form relies on these outputs. An
        // escaped backslash before half an escape at the end leaves the cut value unmatched, so the text is kept after a JWK
        // member's name. After a secret name no strict reading reads the value, so it is masked from the colon to the
        // end (Codex round 5 on 8e6f207, fail closed).
        String q = "\\\"";
        String b = "\\\\";
        for (String tail : List.of("\\u", "\\u0", "\\u005")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String head : List.of("{" + q + "kty" + q + ":" + q + "oct" + q + "," + q + "k" + q + ":" + q, "{" + q + "password" + q + ":" + q)) {
                    String masked = "he said \"" + lb + head + "[REDACTED]" + b + tail;
                    String closed = "he said \"" + lb + head + "[REDACTED]" + q;
                    // #352 security round 4: after a JWK member's name in prose the canonical reading skips, the open value
                    // is masked to the end as well (fail closed, over-flags accepted).
                    assertEquals(head.contains("kty") ? Redactor.MASK : closed, Redactor.redact(masked));
                    String empty = "he said \"" + lb + head + b + tail;
                    assertEquals(head.contains("kty") ? Redactor.MASK : closed, Redactor.redact(empty));
                }
            }
        }
    }

    @Test
    void masksAnEscapedJwkCopyAtTheStartCutOffMidEscape() {
        // #350: the leak scanner's test of the same form relies on these outputs. A JWK copied from inside a string, once
        // or twice, with no stray quote before it, whose open private member ends the text mid-escape: the member's
        // value is masked, cut escape and all, and closed.
        // The owner's rule (#352): where a cut-off prevents complete analysis, the text is masked. A copy cut after a lone
        // backslash (an odd run at the end) is masked from its first member on, its value open and already the mask, or
        // its object closed; a
        // copy whose value is closed but not its object, cut in half a unicode escape, keeps the copy and drops the half
        // escape. Any other cut copy is kept.
        List<String> heads = List.of("{\"kty\":\"oct\",\"k\":\"", "{\"kty\":\"RSA\",\"n\":\"AQAB\",\"d\":\"",
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"");
        List<String> tails = List.of("\\", "\\u", "\\u0", "\\u00", "\\u005", "\\uZ", "\\u0Z", "\\u00G", "\\\\\\");
        for (String head : heads) {
            String once = escapedForJson(head + "[REDACTED]\"");
            String twice = escapedForJson(once);
            for (String tail : tails) {
                boolean loneBackslash = !tail.contains("u");
                for (String value : List.of("FAKE_JWK_K_350", "[REDACTED]", "")) {
                    boolean masked = loneBackslash && value.equals(Redactor.MASK);
                    assertEquals(masked ? "{\\\"" + Redactor.MASK : once, Redactor.redact(escapedForJson(head + value) + tail));
                    assertEquals(masked ? "{\\\\\\\"" + Redactor.MASK : twice,
                            Redactor.redact(escapedForJson(escapedForJson(head + value)) + tail));
                }
                for (String close : List.of("\"", "\"}")) {
                    String copy = escapedForJson(head + "[REDACTED]" + close);
                    String copyTwice = escapedForJson(copy);
                    boolean closesObject = close.length() == 2;
                    assertEquals(loneBackslash && closesObject ? "{\\\"" + Redactor.MASK
                            : !loneBackslash && !closesObject ? copy : copy + tail, Redactor.redact(copy + tail));
                    assertEquals(loneBackslash && closesObject ? "{\\\\\\\"" + Redactor.MASK
                            : !loneBackslash && !closesObject ? copyTwice : copyTwice + tail, Redactor.redact(copyTwice + tail));
                }
            }
        }
    }

    @Test
    void masksAPlainJwkPrivateMemberCutOffAfterALoneBackslash() {
        // #350: the leak scanner's test of the same form relies on these outputs. A private member's value open at the
        // end of the text, then one backslash, is masked, backslash and all, and closed. The owner's rule (#352): a closed
        // value cut off after a lone backslash prevents complete analysis, so that text is masked whole.
        List<String> heads = new ArrayList<>();
        for (String name : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k")) heads.add("{\"kty\":\"RSA\",\"" + name + "\":\"");
        heads.addAll(List.of("{\"kty\":\"oct\",\"k\":\"", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"", "{\"keys\":[{\"kty\":\"oct\",\"k\":\""));
        for (String head : heads) {
            for (String value : List.of("FAKE_JWK_K_350", "[REDACTED]", "")) {
                assertEquals(head + "[REDACTED]\"", Redactor.redact(head + value + "\\"));
            }
            assertEquals(head + "[REDACTED]\"\\", Redactor.redact(head + "[REDACTED]\"\\"));
            assertEquals(Redactor.MASK, Redactor.redact(head + "[REDACTED]\"}\\"));
        }
    }

    @Test
    void masksACopiedSecretFieldCutOffInHalfAUnicodeEscapeAfterAUnicodeBackslash() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                    // #352 security round 4: the k value open to the end of skipped prose is masked to the end too.
                    assertEquals(Redactor.MASK, Redactor.redact(jwk + "[REDACTED]" + backslash + tail));
                    assertEquals(Redactor.MASK, Redactor.redact(jwk + backslash + tail));
                }
            }
        }
    }

    @Test
    void masksACopiedJwkWithMixedQuoteEscapesAfterAnEscapedQuoteInAValue() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                assertEquals(Redactor.MASK, Redactor.redact(before + form.apply("FAKE_JWK_K_342")));
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
    void keepsALoosePrivateMemberNextToAnyNumberOfMaskedJwks() {
        // #341: a valid JWKS of 3 to 33 masked keys and a sibling "d" in no JWK, with kty first or last in each key, bare
        // and nested one to three levels deep. Redactor keeps each form, and so does the text engine on its own, whose
        // JWK search never spends a level's budget: each key costs it the read back to its open bracket and one read
        // forward through it. The leak scanner's r10 tests use these as accepted forms.
        String rest = "\"kid\":\"%s\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
                + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA".repeat(4) + "\",\"e\":\"AQAB\",\"d\":\"[REDACTED]\","
                + "\"p\":\"[REDACTED]\",\"q\":\"[REDACTED]\",\"dp\":\"[REDACTED]\",\"dq\":\"[REDACTED]\",\"qi\":\"[REDACTED]\"";
        for (int keys : new int[] {3, 4, 5, 8, 33}) {
            for (boolean last : new boolean[] {false, true}) {
                String jwk = last ? "{" + rest + ",\"kty\":\"RSA\"}" : "{\"kty\":\"RSA\"," + rest + "}";
                String text = "{\"keys\":[" + java.util.stream.IntStream.range(0, keys)
                        .mapToObj(i -> jwk.formatted("key-" + i)).collect(java.util.stream.Collectors.joining(","))
                        + "],\"d\":\"dimension\"}";
                // Beside a string with an escaped backslash before a word that starts with u (no unicode escape): kept.
                String plain = text.replace("{\"keys\"", "{\"note\":\"user\\\\unit\",\"keys\"");
                assertEquals(plain, Redactor.redact(plain), keys + " keys beside a backslash and u");
                assertEquals(nested(plain), Redactor.redact(nested(plain)), keys + " keys beside a backslash and u, nested");
                // Beside a unicode escape (a control character, printable ones, a hex digit, a u, a letter of kty, a
                // bracket, a colon) in a sibling value, a member name or a string of a JWK, bare and nested: each is kept,
                // written as the encoder spells the character.
                for (String code : List.of("0000", "001f", "0041", "00e9", "0034", "0075", "006b", "007b", "003a", "2028")) {
                    for (String escaped : List.of(
                            text.replace("{\"keys\"", "{\"note\":\"a\\u" + code + "b\",\"keys\""),
                            text.replace("{\"keys\"", "{\"no\\u" + code + "te\":1,\"keys\""),
                            text.replace("\"kid\":\"key-0\"", "\"kid\":\"key\\u" + code + "0\""))) {
                        String at = escaped;
                        for (int levels = 0; levels <= 3; levels++) {
                            assertEquals(Canonical.of(at), Redactor.redact(at), keys + " keys beside \\u" + code + ", " + levels + " levels");
                            at = nested(at);
                        }
                    }
                }
                // With the letters kty in ordinary strings (a key identifier, a value, a longer member name): none is
                // a kty member at any level, so each text is kept, bare and nested.
                for (String ordinary : List.of(
                        text.replace("\"kid\":\"key-", "\"kid\":\"kty-"),
                        text.replace("\"use\":\"sig\"", "\"use\":\"kty\""),
                        text.replace("\"alg\":", "\"x-kty\":"),
                        text.replace("\"kid\":\"key-", "\"kid\":\"kty-").replace("\"use\":\"sig\"", "\"use\":\"kty kty\""))) {
                    assertFalse(text.equals(ordinary));
                    String at = ordinary;
                    for (int levels = 0; levels <= 3; levels++) {
                        assertEquals(at, Redactor.redact(at), keys + " keys with kty in ordinary strings, " + levels + " levels");
                        at = nested(at);
                    }
                }
                String form = text;
                for (int levels = 0; levels <= 3; levels++) {
                    String label = keys + " keys, kty " + (last ? "last" : "first") + ", " + levels + " levels";
                    assertEquals(form, Redactor.redact(form), label);
                    List<Redactor.DiscoveryRead> reads = new java.util.ArrayList<>();
                    assertEquals(form, Redactor.redact(form, reads), label);
                    assertTrue(reads.stream().allMatch(read -> read.after() >= 0), () -> label + ": " + reads);
                    String leaked = form.replace("dimension", "x").replaceFirst("\\[REDACTED\\]", "FAKE_PRIVATE_KEY_341");
                    assertFalse(Redactor.redact(leaked).contains("FAKE_PRIVATE_KEY_341"), label);
                    form = nested(form);
                }
            }
        }
    }

    /**
     * Seeded texts for the JWK search budget grid (#341): a JSON object with a JWKS of masked keys (kty first, in the
     * middle or last), a private-member name in no JWK, and beside them a string of other kty names: loose ones that
     * no object holds (also after backslashes before a u that spell no unicode escape, or spelled with unicode
     * escapes), a nested JWKS, a cut or
     * repeated-name object, a name that only ends in kty, or plain words (with quotes after them, or alone in a string
     * with no escape). The
     * loose member sits beside the keys or in that string, and a second JWKS may sit in a string of its own. Each text
     * comes bare, nested one to three levels deep, also with quotes spelled as unicode escapes, after prose, or cut
     * before its last bracket; a third of them spell ordinary characters as unicode escapes, and a third hold the
     * letters kty in the keys' identifiers and in a value of each key.
     */
    static List<String> jwkSearchBudgetTexts(long seed, int count) {
        java.util.Random random = new java.util.Random(seed);
        String masked = ",\"d\":\"[REDACTED]\",\"p\":\"[REDACTED]\",\"q\":\"[REDACTED]\"";
        List<String> texts = new ArrayList<>();
        while (texts.size() < count) {
            int position = random.nextInt(3);
            int pad = new int[] {1, 2, 6}[random.nextInt(3)];
            java.util.function.IntFunction<String> jwks = keys -> "{\"keys\":[" + java.util.stream.IntStream.range(0, keys)
                    .mapToObj(i -> {
                        String rest = "\"kid\":\"key-" + i + "\",\"n\":\"" + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA".repeat(pad)
                                + "\",\"e\":\"AQAB\"";
                        return position == 0 ? "{\"kty\":\"RSA\"," + rest + masked + "}"
                                : position == 1 ? "{" + rest + ",\"kty\":\"RSA\"" + masked + "}"
                                : "{" + rest + masked + ",\"kty\":\"RSA\"}";
                    }).collect(java.util.stream.Collectors.joining(",")) + "]";
            String loose = "\"d\":\"dimension\"";
            int names = new int[] {1, 2, 3, 4, 5, 6, 7, 9, 12, 24, 63}[random.nextInt(11)];
            boolean looseInside = random.nextInt(3) == 0;
            String inside = looseInside ? loose : "\"e\":\"AQAB\"";
            String other = switch (random.nextInt(14)) {
                case 0 -> "";
                case 1 -> "\"kty\":\"".repeat(names) + inside;
                case 2 -> "x".repeat(new int[] {100, 300, 900, 2500}[random.nextInt(4)]) + " " + "\"kty\":\"".repeat(names) + inside;
                case 3 -> jwks.apply(1 + random.nextInt(5)) + "," + inside + "}";
                case 4 -> jwks.apply(1 + random.nextInt(5)) + "," + inside;
                case 5 -> "{\"kty\":\"oct\",\"kty\":\"RSA\"," + inside + "}";
                case 6 -> "{\"x\\\"kty\":1," + "\"y\\\"kty\":1,".repeat(names) + inside + "}";
                case 7 -> "kty ".repeat(names) + inside;
                case 8 -> "dir\\unit\\u12 " + "\"kty\":\"".repeat(names) + inside;
                case 9 -> "\"k\\u0074y\":\"".repeat(names) + inside;
                case 10 -> "\\u0022kty\\u0022:\\u0022".repeat(names) + inside;
                case 11 -> "kty ".repeat(names).trim();
                case 12 -> "kty-" + "kty:kty,".repeat(names) + "x".repeat(new int[] {0, 300, 2500}[random.nextInt(3)]);
                default -> "{\"a\":[" + "{\"kty\":\"oct\"},".repeat(names) + "1]," + inside + ",\"b\":\"" + "\\\"kty\\\":\\\"".repeat(names) + "\"}";
            };
            StringBuilder object = new StringBuilder("{");
            if (random.nextBoolean()) {
                object.append("\"note\":").append(JSON.writeValueAsString(other)).append(',');
            }
            object.append(jwks.apply(new int[] {2, 3, 4, 6, 12}[random.nextInt(5)]).substring(1));
            if (!looseInside || random.nextBoolean()) {
                object.append(',').append(loose);
            }
            if (object.indexOf("\"note\"") < 0) {
                object.append(",\"note\":").append(JSON.writeValueAsString(other));
            }
            // A JWKS in a string of its own, at the level of the other names.
            if (random.nextInt(3) == 0) {
                String body = JSON.writeValueAsString(jwks.apply(new int[] {1, 3, 8, 20}[random.nextInt(4)]) + "}");
                if (random.nextBoolean()) {
                    object.insert(1, "\"body\":" + body + ",");
                } else {
                    object.append(",\"body\":").append(body);
                }
            }
            String text = object.append('}').toString();
            // Unicode escapes of ordinary characters, in the keys' strings and names and in the other string.
            if (random.nextInt(3) == 0) {
                text = text.replace("key-", "key\\u002d").replace("\"e\":", "\"\\u0065\":").replace("AQAB", "\\u0041QAB");
            }
            // The letters kty in ordinary strings: the key identifiers, and a value of each key.
            if (random.nextInt(3) == 0) {
                text = text.replace(":\"key", ":\"kty").replace(":\\\"key", ":\\\"kty").replace("\"AQAB\"", "\"kty\"");
            }
            texts.add(switch (random.nextInt(9)) {
                case 0 -> text;
                case 1 -> nested(text);
                case 2 -> nested(nested(text));
                case 3 -> "payer said: " + text;
                case 4 -> text.substring(0, text.length() - 1);
                case 5 -> nestedEscapingQuotes(text);
                case 6 -> "payer said: " + nested(text);
                case 7 -> nested(nestedEscapingQuotes(text));
                default -> nested(nested(nested(text)));
            });
        }
        return texts;
    }

    @Test
    void recordsItsOutputsForTheJwkSearchBudgetGrid() throws java.io.IOException {
        // #341: the Redactor's output for each seeded text, committed as scanner-grids/jwk-search-budget-grid.json.gz,
        // where replay/test/leaks.test.mjs checks that the scanner flags every text the Redactor changes and accepts
        // every output: the scanner's bound on the JWK search stays at least as strict as the search itself.
        List<String[]> pairs = new ArrayList<>();
        int kept = 0;
        for (String input : jwkSearchBudgetTexts(341, 1500)) {
            String out = Redactor.redact(input);
            pairs.add(new String[] {input, out});
            kept += out.equals(input) ? 1 : 0;
        }
        // Both kinds are in the grid: texts the Redactor keeps, and texts it changes.
        assertTrue(kept > 50 && pairs.size() - kept > 100, kept + " of " + pairs.size() + " kept");
        assertScannerGrid("jwk-search-budget-grid", pairs);
    }

    @Test
    void masksAPrivateMemberAfterEscapedLooseKtyNamesBesideMaskedJwks() {
        // #341: kty names no object holds, enough to spend the JWK search's budget, in a string beside three masked
        // JWKs, with their quotes or letters spelled as unicode escapes of the string's level or the one above: the
        // private member after them is masked, bare and nested. The leak scanner's r10 test flags each form.
        String jwk = "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"" + "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA".repeat(4)
                + "\",\"e\":\"AQAB\",\"d\":\"[REDACTED]\"}";
        String loose = "\"kty\":\"".repeat(63) + "\"d\":\"FAKE_PRIVATE_KEY_341\"";
        String quoted = JSON.writeValueAsString(loose);
        String content = quoted.substring(1, quoted.length() - 1);
        StringBuilder every = new StringBuilder();
        loose.chars().forEach(c -> every.append(String.format("\\u%04x", c)));
        for (String junk : List.of(content.replace("kty", "\\\\u006bty"), content.replace("kty", "k\\\\u0074y"),
                loose.replace("\"", "\\u0022"), every.toString(), content.replace("kty", "\\u006bty"))) {
            String form = "{\"note\":\"" + junk + "\",\"keys\":[" + jwk.formatted("a") + "," + jwk.formatted("b") + ","
                    + jwk.formatted("c") + "],\"d\":\"dimension\"}";
            for (int levels = 0; levels <= 2; levels++) {
                assertFalse(Redactor.redact(form).contains("FAKE_PRIVATE_KEY_341"), levels + " levels: " + junk.substring(0, 40));
                form = nested(form);
            }
        }
    }

    @Test
    void keepsALoosePrivateMemberNextToMaskedJwksCopiedAfterAStrayQuoteAndARawLineBreak() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
                // #352 security round 4: a private member in prose the canonical reading skips fails closed when the
                // text holds a kty name (over-flags accepted), masked as its name is quoted.
                assertEquals(Redactor.MASK, Redactor.redact(text));
                assertEquals(Redactor.MASK,
                        Redactor.redact(text.replaceFirst("\\[REDACTED]", "FAKE_PRIVATE_KEY_342")));
            }
        }
    }

    /** #349: a JWK copied twice over, its quotes \\u0022, with {@code inner} in its x and y values. */
    private static String doubleEscapedJwk349(String name, String inner, boolean privateFirst) {
        java.util.function.UnaryOperator<String> v = s -> "\\\\u0022" + s + "\\\\u0022";
        String kty = v.apply("kty") + ":0";
        String x = v.apply("x") + ":" + v.apply(inner);
        String y = v.apply("y") + ":" + v.apply(inner);
        String secret = v.apply(name) + ":" + v.apply("dimension");
        return "{" + String.join(",", privateFirst ? List.of(kty, secret, x, y) : List.of(kty, x, y, secret)) + "}";
    }

    @Test
    void keepsADoubleEscapedJwkWithAQuoteInsideItsValuesAfterAStrayQuoteAndARawLineBreak() {
        // #349: one level down, each \u0022 in x and y is a bare quote inside a string the copy's quote opened, where the
        // JWK reading stops, so the k (or d) after it is in no JWK and the text is kept. The stray quote is glued to the
        // word before it, so the canonical reading does not skip it as prose (#352). The leak scanner flags these kept
        // forms: the over-flag class the owner accepted on #349. Escaped once more (\\\u0022), or with the private member
        // before them, the inner quotes stop nothing, and the member is masked.
        for (String prefix : List.of("x\"", "he said\"", "{\"a\":\"b\"}\"", "{\"a\":\"x\"y\"")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String name : List.of("k", "d")) {
                    for (String inner : List.of("@", "a@b", "@@")) {
                        String text = prefix + lb + doubleEscapedJwk349(name, inner.replace("@", "\\u0022"), false);
                        assertEquals(text, Redactor.redact(text));
                        String nested = "{\"body\":\"" + text.replace("\\", "\\\\").replace("\"", "\\\"")
                                .replace("\n", "\\n").replace("\r", "\\r") + "\"}";
                        assertEquals(nested, Redactor.redact(nested));
                        String once = prefix + lb + doubleEscapedJwk349(name, inner.replace("@", "\\\\\\u0022"), false);
                        assertNotEquals(once, Redactor.redact(once));
                        String first = prefix + lb + doubleEscapedJwk349(name, inner.replace("@", "\\u0022"), true);
                        assertNotEquals(first, Redactor.redact(first));
                    }
                }
            }
        }
    }

    @Test
    void masksADoubleEscapedJwkWithAMemberBetweenItsInnerQuotesAndItsPrivateMember() {
        // #349: the member right after the value whose inner quotes stop the JWK reading is not read, but a member after
        // it is, so the private member is masked. Any scanner change for #349 must keep flagging these.
        java.util.function.UnaryOperator<String> v = s -> "\\\\u0022" + s + "\\\\u0022";
        List<List<String>> betweens = List.of(List.of(v.apply("other") + ":" + v.apply("x")), List.of(v.apply("other") + ":1"),
                List.of(v.apply("a") + ":{" + v.apply("b") + ":1}"),
                List.of(v.apply("o1") + ":" + v.apply("x"), v.apply("o2") + ":" + v.apply("x")));
        for (String prefix : List.of("x\"", "he said\"", "{\"a\":\"b\"}\"", "{\"a\":\"x\"y\"")) {
            for (String lb : List.of("\n", "\r\n")) {
                for (String name : List.of("k", "d")) {
                    for (String inner : List.of("@", "a@b", "@@")) {
                        for (List<String> between : betweens) {
                            List<String> members = new java.util.ArrayList<>(List.of(v.apply("kty") + ":0",
                                    v.apply("x") + ":" + v.apply(inner), v.apply("y") + ":" + v.apply(inner)));
                            members.addAll(between);
                            members.add(v.apply(name) + ":" + v.apply("dimension"));
                            String text = (prefix + lb + "{" + String.join(",", members) + "}").replace("@", "\\u0022");
                            assertNotEquals(text, Redactor.redact(text));
                        }
                    }
                }
            }
        }
    }

    @Test
    void readsAFormFeedOrVerticalTabAroundTheMemberAfterTheInnerQuotesAsWhitespace() {
        // #349: Java's \\s holds a form feed and a vertical tab, so around the member after the inner quotes they read as
        // whitespace: the first form is kept, the second masked.
        java.util.function.UnaryOperator<String> v = s -> "\\\\u0022" + s + "\\\\u0022";
        for (String prefix : List.of("x\"", "{\"a\":\"b\"}\"")) {
            for (String space : List.of("\f", "\u000B")) {
                for (String inner : List.of("@", "@@")) {
                    String head = v.apply("kty") + ":0," + v.apply("x") + ":" + v.apply(inner) + "," + v.apply("y") + ":" + v.apply(inner);
                    String kept = (prefix + "\n{" + head + "," + space + v.apply("k") + ":" + v.apply("dimension") + "}").replace("@", "\\u0022");
                    assertEquals(kept, Redactor.redact(kept));
                    String masked = (prefix + "\n{" + head + "," + space + v.apply("o") + ":" + v.apply("x") + "," + space + v.apply("k") + ":"
                            + v.apply("dimension") + "}").replace("@", "\\u0022");
                    assertNotEquals(masked, Redactor.redact(masked));
                }
            }
        }
    }

    @Test
    void masksAJwkCopiedAfterAStrayQuoteAndARawLineBreakNestedEightDeep() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
        // #342: the leak scanner's test reading this form within its scan budget uses this output as its masked form.
        String jwk = "{\"kty\":\"oct\",\"k\":\"%s\",\"pad\":\"" + "x".repeat(100) + "\"}";
        for (String lb : List.of("\n", "\r\n")) {
            String masked = jwk.formatted("[REDACTED]");
            String leaked = jwk.formatted("FAKE_JWK_K_342");
            for (int i = 0; i < 8; i++) {
                masked = "he said \"" + lb + escapedForJson(masked);
                leaked = "he said \"" + lb + escapedForJson(leaked);
            }
            assertEquals(Redactor.MASK, Redactor.redact(masked));
            assertEquals(Redactor.MASK, Redactor.redact(leaked));
        }
    }

    @Test
    void masksAJwkWithALongPadCopiedAfterAStrayQuoteNestedThreeDeep() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
            assertEquals(Redactor.MASK, Redactor.redact(masked));
            assertEquals(Redactor.MASK, Redactor.redact(leaked));
        }
    }

    @Test
    void masksAJwkAfterALongPadCopiedAndClosedThreeDeep() {
        // The owner's rule (#352): where a skip prevents complete analysis, the whole text is masked; each form that
        // skips here is now expected masked whole.
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
            assertEquals(Redactor.MASK, Redactor.redact(masked));
            assertEquals(Redactor.MASK, Redactor.redact(leaked));
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
        // Since #377 criterion 2 the block is masked whole, its armor too.
        assertEquals("\"kty\":\"".repeat(63) + "\"d\":\"[REDACTED]\"[REDACTED]", Redactor.redact(key));
        assertEquals("\"kty\":\"".repeat(63) + "\"d\":\"[REDACTED]\"[REDACTED]", Redactor.redact(pgp));
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
        assertEquals(Redactor.MASK.repeat(64_001), out, out.substring(out.length() - 80));
    }

    /**
     * Guards the whole-block key search (#390): it must take time that grows about linearly with the text for the
     * armor shapes of {@link #keyBlockShapes}. Timed as {@link #findsJwksInLinearTime} times its shapes, by the growth
     * of CPU time over eight times the length; the timeout only ends a hang.
     */
    @Test
    void findsKeyBlocksInLinearTime() {
        List<String> small = keyBlockShapes(SMALL / 2);
        List<String> large = keyBlockShapes(4 * SMALL);
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2),
                () -> growthBeyondLinear(small, large));
        assertTrue(tooSlow.isEmpty(), "time grows more than " + MAX_GROWTH_PER_DOUBLING + " times per doubling of the text: "
                + tooSlow);
    }

    /** The shapes that {@link #findsKeyBlocksInLinearTime} times, each made of about {@code n} armor lines. */
    private static List<String> keyBlockShapes(int n) {
        StringBuilder labels = new StringBuilder();
        StringBuilder sameHash = new StringBuilder();
        for (int i = 0; i < n; i++) {
            labels.append("-----BEGIN LABEL ").append(i).append("-----\n");
            // Distinct labels with one shared prefix and the same String hash: AO and B0 hash alike.
            StringBuilder label = new StringBuilder("KEY ".repeat(16));
            for (int bit = 0; bit < 16; bit++) {
                label.append((i >> bit & 1) == 0 ? "AO" : "B0");
            }
            sameHash.append("-----END ").append(label).append("-----\n-----BEGIN ").append(label).append("-----\n");
        }
        return List.of(
                sameHash.toString(),
                "-----BEGIN CERTIFICATE-----\n".repeat(n),
                labels.toString(),
                "-----BEGIN CERTIFICATE-----\n-----END PUBLIC KEY-----\n".repeat(n / 2),
                ("-----BEGIN CERTIFICATE-----\n" + "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").repeat(n / 2),
                "-----BEGIN CERTIFICATE-----".repeat(n) + "-----END CERTIFICATE-----",
                "-----BEGIN PRIVATE KEY-----\n".repeat(n));
    }

    /** The whole-block key search before #390, which {@link Redactor#keyBlocks} must match block for block. */
    private static final java.util.regex.Pattern LAZY_KEY_BLOCK = java.util.regex.Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \\1-----", java.util.regex.Pattern.DOTALL);

    @Test
    void findsTheSameKeyBlocksAsTheLazySearch() {
        // Seeded texts of armor pieces: headers and footers of a few labels (also empty, spaced, or lower case), extra
        // and missing dashes, headers inside headers, and filler, so blocks nest, overlap, share footers and go unclosed.
        List<String> pieces = List.of("-----BEGIN ", "-----END ", "-----", "-", "A", "B", "AB", " ", "a", "\n", "x",
                "BEGIN ", "END ", "PRIVATE KEY", "-----BEGIN A-----", "-----END A-----", "-----BEGIN B-----",
                "-----END B-----", "-----BEGIN AB-----", "-----END AB-----", "------END A------", "AO", "B0",
                "-----BEGIN AOB0-----", "-----END B0AO-----", "-----END AOB0-----");
        java.util.Random random = new java.util.Random(390);
        int withBlocks = 0;
        for (int i = 0; i < 50_000; i++) {
            StringBuilder text = new StringBuilder();
            for (int n = random.nextInt(24); n > 0; n--) {
                text.append(pieces.get(random.nextInt(pieces.size())));
            }
            List<String> expected = new ArrayList<>();
            java.util.regex.Matcher block = LAZY_KEY_BLOCK.matcher(text);
            while (block.find()) {
                expected.add(block.start() + "-" + block.end());
            }
            List<String> found = Redactor.keyBlocks(text.toString()).stream().map(b -> b[0] + "-" + b[1]).toList();
            assertEquals(expected, found, text::toString);
            withBlocks += expected.isEmpty() ? 0 : 1;
        }
        assertTrue(withBlocks > 5_000, "too few texts with blocks: " + withBlocks);
    }

    /**
     * Guards the structural open-key check (#396), {@link Redactor#opensAnUnterminatedKey}, which a JSON string's text
     * reaches: it must take time that grows about linearly with the text for the footer label shapes of
     * {@link #openKeyShapes}. Timed as {@link #findsJwksInLinearTime} times its shapes, by the growth of CPU time over
     * eight times the length; the timeout only ends a hang.
     */
    @Test
    void findsUnterminatedKeysInLinearTime() {
        List<String> small = openKeyShapes(SMALL);
        List<String> large = openKeyShapes(8 * SMALL);
        // Each shape reaches the open-key check through the structural path, which masks the whole text.
        for (String shape : java.util.stream.Stream.concat(small.stream(), large.stream()).toList()) {
            String content = shape.substring(1, shape.length() - 1).replace("\\n", "\n");
            assertTrue(Redactor.opensAnUnterminatedKey(content), () -> shape.substring(0, 80));
            assertEquals(Redactor.MASK, Redactor.redact(shape), () -> shape.substring(0, 80));
        }
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2),
                () -> growthBeyondLinear(small, large));
        assertTrue(tooSlow.isEmpty(), "time grows more than " + MAX_GROWTH_PER_DOUBLING + " times per doubling of the text: "
                + tooSlow);
    }

    /**
     * The shapes that {@link #findsUnterminatedKeysInLinearTime} times, each a JSON string of about {@code n} footer
     * lines: an unterminated private key header and many private key footers of adversarial label shapes, of one
     * label, or of labels that are prefixes of one another, and many headers.
     */
    private static List<String> openKeyShapes(int n) {
        int lines = (int) Math.round(Math.sqrt(n) * 8);
        String prefix = "A".repeat(lines);
        StringBuilder sameHash = new StringBuilder();
        StringBuilder distinct = new StringBuilder();
        StringBuilder nestedLabels = new StringBuilder();
        for (int i = 0; i < lines; i++) {
            StringBuilder label = new StringBuilder(prefix);
            for (int bit = 0; bit < 16; bit++) {
                label.append((i >> bit & 1) == 0 ? "AO" : "B0");
            }
            sameHash.append("-----END ").append(label).append(" PRIVATE KEY-----\\n");
            distinct.append("-----END ").append(prefix).append(i).append(" PRIVATE KEY-----\\n");
            nestedLabels.append("-----END ").append("A".repeat(i)).append(" PRIVATE KEY-----\\n");
        }
        String header = "-----BEGIN Z PRIVATE KEY-----\\n";
        return List.of(
                "\"" + header + sameHash + "\"",
                "\"" + header + distinct + "\"",
                "\"" + header + nestedLabels + "\"",
                "\"" + header + "-----END PRIVATE KEY-----\\n".repeat(n) + "\"",
                "\"" + "-----BEGIN PRIVATE KEY-----\\n".repeat(n) + "\"",
                "\"" + sameHash + header.replace("BEGIN", "END").repeat(n / 8) + header + "\"");
    }

    /**
     * Guards the open-key check (#399) on texts where most headers are closed: every shape of {@link #closedKeyShapes}
     * makes {@link Redactor#opensAnUnterminatedKey} find a footer for many headers in turn before its answer, so work
     * done again for each closed header (a search on from the header, a walk along its label's footers, or the footer
     * index built again) grows with the square of the text. {@link #findsUnterminatedKeysInLinearTime} cannot see that:
     * each of its shapes is answered at its first header that is found. Timed as {@link #findsJwksInLinearTime} times
     * its shapes, by the growth of CPU time over eight times the length; the timeout only ends a hang.
     */
    @Test
    void findsFootersForManyClosedHeadersInLinearTime() {
        List<String> small = closedKeyShapes(SMALL / 4);
        List<String> large = closedKeyShapes(2 * SMALL);
        for (List<String> shapes : List.of(small, large)) {
            int lines = shapes == small ? SMALL / 4 : 2 * SMALL;
            for (int shape = 0; shape < shapes.size(); shape++) {
                String json = shapes.get(shape);
                String content = json.substring(1, json.length() - 1).replace("\\n", "\n");
                // Shapes 1 and 2 close every header; 3 and 4 end with one header no footer closes.
                boolean open = shape >= 2;
                assertEquals(open, opensAnUnterminatedKeyByHash(content), () -> json.substring(0, 80));
                assertEquals(open, Redactor.opensAnUnterminatedKey(content), () -> json.substring(0, 80));
                assertTrue(closedHeaders(content) >= lines, () -> json.substring(0, 80));
                if (open) {
                    assertEquals(Redactor.MASK, Redactor.redact(json), () -> json.substring(0, 80));
                }
            }
        }
        List<String> tooSlow = assertTimeoutPreemptively(Duration.ofMinutes(2),
                () -> growthBeyondLinear(small, large));
        assertTrue(tooSlow.isEmpty(), "time grows more than " + MAX_GROWTH_PER_DOUBLING + " times per doubling of the text: "
                + tooSlow);
    }

    /**
     * The shapes that {@link #findsFootersForManyClosedHeadersInLinearTime} times, each a JSON string of {@code n}
     * private key headers and then {@code n} footers that close them: of one label, or of a distinct label each; then,
     * in the last two, one more header after every footer of its label.
     */
    private static List<String> closedKeyShapes(int n) {
        StringBuilder distinctHeaders = new StringBuilder();
        StringBuilder distinctFooters = new StringBuilder();
        for (int i = 0; i < n; i++) {
            distinctHeaders.append("-----BEGIN K").append(i).append(" PRIVATE KEY-----\\n");
            distinctFooters.append("-----END K").append(i).append(" PRIVATE KEY-----\\n");
        }
        String oneLabel = "-----BEGIN PRIVATE KEY-----\\n".repeat(n) + "-----END PRIVATE KEY-----\\n".repeat(n);
        String distinct = distinctHeaders.toString() + distinctFooters;
        return List.of(
                "\"" + oneLabel + "\"",
                "\"" + distinct + "\"",
                "\"" + oneLabel + "-----BEGIN PRIVATE KEY-----\\n" + "\"",
                "\"" + distinct + "-----BEGIN K0 PRIVATE KEY-----\\n" + "\"");
    }

    /** The private key headers of {@code text} that a footer of the same label after them closes. */
    private static int closedHeaders(String text) {
        Map<String, Integer> lastFooter = new java.util.HashMap<>();
        java.util.regex.Matcher footer = PRIVATE_KEY_FOOTER.matcher(text);
        while (footer.find()) {
            lastFooter.put(footer.group(1), footer.start());
        }
        int closed = 0;
        java.util.regex.Matcher header = PRIVATE_KEY_HEADER.matcher(text);
        while (header.find()) {
            closed += lastFooter.getOrDefault(header.group(1), -1) >= header.end() ? 1 : 0;
        }
        return closed;
    }

    /**
     * The armor-label index (#396, #399) takes no hash of a label: a hashed index costs a log factor more on labels
     * chosen to collide, which {@link #findsUnterminatedKeysInLinearTime} cannot tell from noise on this path, so the
     * absence of hashing is checked in the code. {@link #labelIndexViolations} reads the code as the compiler does, so
     * comments and literals play no part: {@link Redactor#opensAnUnterminatedKey} and {@link Redactor#keyBlocks} must
     * each add and find labels through {@code ArmorLabels}, and they, and every method or constructor of
     * {@link Redactor} they reach, may call only {@link #LABEL_INDEX_CALLEES}, never a hashing method.
     */
    @Test
    void indexesFooterLabelsWithoutHashing() throws java.io.IOException {
        List<String> found = labelIndexViolations(redactorSource());
        assertTrue(found.isEmpty(), () -> String.join("\n", found));
    }

    @Test
    void hashFreeGuardIgnoresCommentsAndLiterals() throws java.io.IOException {
        String source = redactorSource();
        String named = "        // A HashMap, HashSet, Hashtable or Objects.hash here would hash the labels.\n"
                + "        String hashing = \"new java.util.HashMap<>().put(label.hashCode(), label)\";\n";
        String variant = replaceOnce(source, "    static boolean opensAnUnterminatedKey(String text) {\n",
                "    static boolean opensAnUnterminatedKey(String text) {\n" + named);
        variant = replaceOnce(variant, "    static List<int[]> keyBlocks(String text) {\n",
                "    static List<int[]> keyBlocks(String text) {\n" + named);
        List<String> found = labelIndexViolations(variant);
        assertTrue(found.isEmpty(), () -> String.join("\n", found));
    }

    @Test
    void hashFreeGuardFailsWhenTheIndexStopsGoingThroughArmorLabels() throws java.io.IOException {
        String source = redactorSource();
        // The open-key check looks its headers up in a hash map instead of the trie.
        assertViolations(replaceOnce(source,
                """
                            int node = labels.find(text, header.start(1), header.end(1));
                            if (node < 0 || labels.last.get(node) < header.end()) {
                """,
                """
                            Integer node = new HashMap<String, Integer>().get(header.group(1));
                            if (node == null || node < header.end()) {
                """),
                "opensAnUnterminatedKey does not call Redactor.ArmorLabels.find",
                "calls java.util.HashMap.<init>", "calls java.util.HashMap.get");
        // The block search looks its headers up in a sorted map: no hash, but not the trie either.
        assertViolations(replaceOnce(source,
                "            int node = labels.find(text, labelStart, labelEnd);\n",
                "            int node = new TreeMap<String, Integer>().getOrDefault(text.substring(labelStart, labelEnd), -1);\n"),
                "keyBlocks does not call Redactor.ArmorLabels.find", "calls java.util.TreeMap.<init>",
                "calls java.util.Map.getOrDefault");
        // The trie hands each label to a helper outside it that hashes it.
        String delegated = replaceOnce(source,
                """
                        int find(String text, int start, int end) {
                            int node = 0;
                """,
                """
                        int find(String text, int start, int end) {
                            int node = labelSlot(text.substring(start, end)) < 0 ? -1 : 0;
                """);
        delegated = replaceOnce(delegated, "    /** A growable list of ints, without boxing. */\n",
                "    static int labelSlot(String label) {\n        return Math.floorMod(java.util.Objects.hash(label), 64);\n    }\n\n"
                        + "    /** A growable list of ints, without boxing. */\n");
        assertViolations(delegated, "in Redactor.labelSlot(java.lang.String): hashes with java.util.Objects.hash");
        // A switch on a label hashes it with no call in the source.
        assertViolations(replaceOnce(source,
                "            int node = labels.find(text, header.start(1), header.end(1));\n",
                "            int node = switch (header.group(1)) { case \"PRIVATE KEY\" -> 0; default -> labels.find(text, header.start(1), header.end(1)); };\n"),
                "switches on a String");
        // The trie takes a hash code itself.
        assertViolations(replaceOnce(source,
                """
                        private int child(int node, char c) {
                            int child = firstChild.get(node);
                """,
                """
                        private int child(int node, char c) {
                            int child = firstChild.get(node) + edge.toString().hashCode() * 0;
                """),
                "hashes with java.lang.String.hashCode");
    }

    /** The source of {@link Redactor}, read from this module. */
    private static String redactorSource() throws java.io.IOException {
        return CompiledSource.read("Redactor");
    }

    /** {@code source} with its one {@code target} replaced, failing if {@code target} is not there exactly once. */
    private static String replaceOnce(String source, String target, String replacement) {
        return CompiledSource.replaceOnce(source, target, replacement);
    }

    /** Asserts that {@link #labelIndexViolations} reports each of {@code expected} (as a substring) for {@code source}. */
    private static void assertViolations(String source, String... expected) {
        List<String> found = labelIndexViolations(source);
        for (String violation : expected) {
            assertTrue(found.stream().anyMatch(f -> f.contains(violation)),
                    () -> "missing \"" + violation + "\" in:\n" + String.join("\n", found));
        }
    }

    /** The classes whose methods the armor-label index code may call: none of them hashes what it is given. */
    private static final Set<String> LABEL_INDEX_CALLEES = Set.of("java.lang.Object", "java.lang.String",
            "java.lang.StringBuilder", "java.lang.AbstractStringBuilder", "java.lang.Math", "java.util.regex.Pattern", "java.util.regex.Matcher",
            "java.util.List", "java.util.ArrayList", "java.util.Arrays");
    /** Methods that hash, or look up a hash table, whatever class declares them. */
    private static final Set<String> HASHING_METHODS = Set.of("hashCode", "identityHashCode", "intern", "hash");

    /**
     * What breaks the hash-free rule in {@code source}, a version of {@code Redactor.java}, as compiled by the JDK's
     * compiler against this module's classes. From {@code opensAnUnterminatedKey} and {@code keyBlocks} it follows
     * every method and constructor of {@link Redactor} or its nested classes that they call, with the field
     * initializers of each class whose constructor is called, and reports: a root that does not call
     * {@code ArmorLabels.add} and {@code ArmorLabels.find}; a call or method reference to any other class not in
     * {@link #LABEL_INDEX_CALLEES}; a call to one of {@link #HASHING_METHODS}; and a switch on a {@code String}, which
     * compiles to a hash code. Comments and literals are not part of the tree it reads.
     */
    private static List<String> labelIndexViolations(String source) {
        CompiledSource compiled = CompiledSource.compile("Redactor", source);
        com.sun.source.util.Trees trees = compiled.trees();
        javax.lang.model.util.Elements elements = compiled.elements();
        javax.lang.model.element.TypeElement redactor = elements.getTypeElement(Redactor.class.getName());
        String labelsClass = Redactor.class.getName() + ".ArmorLabels";

        List<String> violations = new ArrayList<>();
        Map<javax.lang.model.element.Element, Set<String>> calls = new LinkedHashMap<>();
        ArrayDeque<javax.lang.model.element.Element> pending = new ArrayDeque<>();
        Set<javax.lang.model.element.Element> seen = new LinkedHashSet<>();
        List<javax.lang.model.element.ExecutableElement> roots = new ArrayList<>();
        for (String name : List.of("opensAnUnterminatedKey", "keyBlocks")) {
            javax.lang.model.element.ExecutableElement root = redactor.getEnclosedElements().stream()
                    .filter(e -> e.getKind() == javax.lang.model.element.ElementKind.METHOD
                            && e.getSimpleName().contentEquals(name))
                    .map(javax.lang.model.element.ExecutableElement.class::cast).findFirst()
                    .orElseThrow(() -> new AssertionError("Redactor has no method " + name));
            roots.add(root);
            pending.add(root);
        }
        while (!pending.isEmpty()) {
            javax.lang.model.element.Element next = pending.poll();
            if (!seen.add(next)) {
                continue;
            }
            Set<String> called = calls.computeIfAbsent(next, e -> new LinkedHashSet<>());
            String where = next instanceof javax.lang.model.element.TypeElement type
                    ? simpleName(type) + " fields"
                    : simpleName((javax.lang.model.element.TypeElement) next.getEnclosingElement()) + "." + next;
            List<com.sun.source.util.TreePath> bodies = new ArrayList<>();
            if (next instanceof javax.lang.model.element.TypeElement type) {
                // The instance field initializers and initializer blocks that a constructor of the class runs.
                com.sun.source.util.TreePath typePath = trees.getPath(type);
                for (com.sun.source.tree.Tree member : ((com.sun.source.tree.ClassTree) typePath.getLeaf()).getMembers()) {
                    boolean instance = member instanceof com.sun.source.tree.VariableTree variable
                            ? !variable.getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)
                            : member instanceof com.sun.source.tree.BlockTree block && !block.isStatic();
                    if (instance) {
                        bodies.add(new com.sun.source.util.TreePath(typePath, member));
                    }
                }
            } else {
                com.sun.source.util.TreePath path = trees.getPath(next);
                com.sun.source.tree.Tree leaf = path == null ? null : path.getLeaf();
                if (!(leaf instanceof com.sun.source.tree.MethodTree method) || method.getBody() == null) {
                    violations.add("in " + where + ": no body to follow");
                    continue;
                }
                bodies.add(new com.sun.source.util.TreePath(path, method.getBody()));
            }
            com.sun.source.util.TreePathScanner<Void, Void> scanner = new com.sun.source.util.TreePathScanner<>() {
                @Override
                public Void visitMethodInvocation(com.sun.source.tree.MethodInvocationTree node, Void unused) {
                    reach(trees.getElement(getCurrentPath()), node);
                    return super.visitMethodInvocation(node, unused);
                }

                @Override
                public Void visitNewClass(com.sun.source.tree.NewClassTree node, Void unused) {
                    reach(trees.getElement(getCurrentPath()), node);
                    return super.visitNewClass(node, unused);
                }

                @Override
                public Void visitMemberReference(com.sun.source.tree.MemberReferenceTree node, Void unused) {
                    reach(trees.getElement(getCurrentPath()), node);
                    return super.visitMemberReference(node, unused);
                }

                @Override
                public Void visitSwitch(com.sun.source.tree.SwitchTree node, Void unused) {
                    selector(node.getExpression());
                    return super.visitSwitch(node, unused);
                }

                @Override
                public Void visitSwitchExpression(com.sun.source.tree.SwitchExpressionTree node, Void unused) {
                    selector(node.getExpression());
                    return super.visitSwitchExpression(node, unused);
                }

                private void selector(com.sun.source.tree.ExpressionTree expression) {
                    javax.lang.model.type.TypeMirror type = trees.getTypeMirror(
                            new com.sun.source.util.TreePath(getCurrentPath(), expression));
                    if (type != null && type.toString().equals("java.lang.String")) {
                        violations.add("in " + where + ": switches on a String, which hashes it");
                    }
                }

                private void reach(javax.lang.model.element.Element target, com.sun.source.tree.Tree node) {
                    if (!(target instanceof javax.lang.model.element.ExecutableElement method)) {
                        violations.add("in " + where + ": cannot resolve " + node);
                        return;
                    }
                    javax.lang.model.element.TypeElement owner =
                            (javax.lang.model.element.TypeElement) method.getEnclosingElement();
                    String ownerName = owner.getQualifiedName().toString();
                    String name = method.getSimpleName().toString();
                    called.add(ownerName + "." + name);
                    if (HASHING_METHODS.contains(name)) {
                        violations.add("in " + where + ": hashes with " + ownerName + "." + name);
                    } else if (ownerName.equals(Redactor.class.getName())
                            || ownerName.startsWith(Redactor.class.getName() + ".")) {
                        pending.add(method);
                        if (method.getKind() == javax.lang.model.element.ElementKind.CONSTRUCTOR) {
                            pending.add(owner);
                        }
                    } else if (!LABEL_INDEX_CALLEES.contains(ownerName)) {
                        violations.add("in " + where + ": calls " + ownerName + "." + name);
                    }
                }
            };
            bodies.forEach(body -> scanner.scan(body, null));
        }
        for (javax.lang.model.element.ExecutableElement root : roots) {
            for (String operation : List.of("add", "find")) {
                if (!calls.get(root).contains(labelsClass + "." + operation)) {
                    violations.add(root.getSimpleName() + " does not call Redactor.ArmorLabels." + operation);
                }
            }
        }
        return violations;
    }

    /** {@code type}'s name inside its package, such as {@code Redactor.ArmorLabels}. */
    private static String simpleName(javax.lang.model.element.TypeElement type) {
        String qualified = type.getQualifiedName().toString();
        return qualified.substring(qualified.lastIndexOf('.', qualified.lastIndexOf("Redactor")) + 1);
    }

    /** The private key header and footer patterns of {@link Redactor}, for {@link #opensAnUnterminatedKeyByHash}. */
    private static final java.util.regex.Pattern PRIVATE_KEY_HEADER = java.util.regex.Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----");
    private static final java.util.regex.Pattern PRIVATE_KEY_FOOTER = java.util.regex.Pattern.compile(
            "-----END ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----");

    /** The open-key check before #396, with its footer labels in a hash map, which the trie must match. */
    private static boolean opensAnUnterminatedKeyByHash(String text) {
        if (!text.contains("-----BEGIN ")) {
            return false;
        }
        Map<String, Integer> lastFooter = new java.util.HashMap<>();
        java.util.regex.Matcher footer = PRIVATE_KEY_FOOTER.matcher(text);
        while (footer.find()) {
            lastFooter.put(footer.group(1), footer.start());
        }
        java.util.regex.Matcher header = PRIVATE_KEY_HEADER.matcher(text);
        while (header.find()) {
            if (lastFooter.getOrDefault(header.group(1), -1) < header.end()) {
                return true;
            }
        }
        return false;
    }

    @Test
    void opensTheSameKeysAsTheHashIndex() {
        // Seeded texts of armor pieces: private key headers and footers of a few labels (also prefixes of one another,
        // PGP blocks, lower case or spaced), extra and missing dashes, and filler, so footers come before, after and
        // between headers, overlap the dashes of the one before, and close other labels.
        List<String> pieces = List.of("-----BEGIN ", "-----END ", "-----", "-", "A", "B", " ", "a", "\n", "x",
                "PRIVATE KEY", " BLOCK", "PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
                "-----BEGIN A PRIVATE KEY-----", "-----END A PRIVATE KEY-----", "-----BEGIN AA PRIVATE KEY-----",
                "-----END AA PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "-----END PGP PRIVATE KEY BLOCK-----", "------END PRIVATE KEY------", "-----END PRIVATE KEY BLOCK-----",
                "-----BEGIN AO PRIVATE KEY-----", "-----END B0 PRIVATE KEY-----", "-----END AO PRIVATE KEY-----");
        java.util.Random random = new java.util.Random(396);
        int open = 0;
        int closed = 0;
        for (int i = 0; i < 50_000; i++) {
            StringBuilder text = new StringBuilder();
            for (int n = random.nextInt(16); n > 0; n--) {
                text.append(pieces.get(random.nextInt(pieces.size())));
            }
            boolean expected = opensAnUnterminatedKeyByHash(text.toString());
            assertEquals(expected, Redactor.opensAnUnterminatedKey(text.toString()), text::toString);
            boolean hasHeader = text.indexOf("PRIVATE KEY") >= 0 && text.indexOf("-----BEGIN ") >= 0;
            open += expected ? 1 : 0;
            closed += !expected && hasHeader ? 1 : 0;
        }
        assertTrue(open > 5_000 && closed > 2_000, "too few texts of one kind: " + open + " open, " + closed + " closed");
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
            assertKept(text);
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
        // Masked whole, armor too (#377 criterion 2); a public key's lone header is masked, its body kept.
        assertEquals(Redactor.MASK, Redactor.redact("-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFAKEKEYMATERIAL\n=abcd"));
        String terminated = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFAKE\n-----END PGP PRIVATE KEY BLOCK-----";
        assertEquals(Redactor.MASK, Redactor.redact(terminated));
        String publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENBFAKEPUBLIC";
        assertEquals(Redactor.MASK + "\nmQENBFAKEPUBLIC", Redactor.redact(publicKey));
    }

    record Echoed(String summary, String clientSecret, Integer apiKey, int password, List<String> notes) {
    }

    @Test
    void redactsEveryStringOfATreeAndMasksSecretFields() {
        String token = randomToken();
        // A tree is JSON-shaped plain data (#377, typed tree): a record is given as the map of its components.
        Map<String, Object> card = new LinkedHashMap<>();
        card.put("summary", "Bearer " + token);
        card.put("clientSecret", token);
        card.put("apiKey", 918273645);
        card.put("password", 918273646);
        card.put("notes", List.of("Bearer " + token));
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("summary", "Echo: Bearer " + token);
        tree.put("requestHeaders", Map.of("Authorization", List.of("Bearer " + token), "Cookie", List.of("c=" + token)));
        tree.put("tags", List.of("Bearer " + token));
        tree.put("card", card);
        tree.put("count", 3);
        tree.put("FAIL", 1L);
        tree.put("missing", null);

        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);

        assertEquals(List.copyOf(tree.keySet()), List.copyOf(out.keySet()));
        assertEquals("Echo: Bearer [REDACTED]", out.get("summary"));
        // Each secret-named value is masked as it is in the JSON text of the same tree (RedactorTreeTest).
        assertEquals(Redactor.redact(JSON.writeValueAsString(tree.get("requestHeaders"))),
                JSON.writeValueAsString(out.get("requestHeaders")));
        assertEquals(List.of("Bearer [REDACTED]"), out.get("tags"));
        Map<String, Object> redactedCard = new LinkedHashMap<>();
        redactedCard.put("summary", "Bearer [REDACTED]");
        redactedCard.put("clientSecret", "[REDACTED]");
        redactedCard.put("apiKey", "[REDACTED]");
        redactedCard.put("password", "[REDACTED]");
        redactedCard.put("notes", List.of("Bearer [REDACTED]"));
        assertEquals(redactedCard, out.get("card"));
        assertEquals(List.copyOf(card.keySet()), List.copyOf(((Map<?, ?>) out.get("card")).keySet()));
        assertEquals(3, out.get("count"));
        assertEquals(1L, out.get("FAIL"));
        assertTrue(out.containsKey("missing"));
        assertNull(out.get("missing"));
        assertNull(Redactor.redactTree(null));
        Map<String, Object> lists = Map.of("access_token", List.of("x", "Basic dXNlcjpwYXNz"),
                "Proxy-Authorization", List.of("x", "Basic dXNlcjpwYXNz"));
        assertEquals(Redactor.redact(JSON.writeValueAsString(lists)), JSON.writeValueAsString(Redactor.redactTree(lists)));
        assertFalse(String.valueOf(out).contains(token), String.valueOf(out));
        // The record, a set and an enum key are not JSON-shaped: the whole tree is the mask.
        Map<Object, Object> typed = new LinkedHashMap<>(tree);
        typed.put("card", new Echoed("Bearer " + token, token, 918273645, 918273646, List.of("Bearer " + token)));
        assertEquals(Redactor.MASK, Redactor.redactTree(typed));
        assertEquals(Redactor.MASK, Redactor.redactTree(Map.of("tags", new LinkedHashSet<>(List.of("Bearer " + token)))));
        assertEquals(Redactor.MASK, Redactor.redactTree(Map.of(Severity.FAIL, 1L)));
    }

    @Test
    void redactsMapKeysArraysOptionalsAndValuesOfOtherTypesInATree() {
        String token = randomToken();
        String echo = "Bearer " + token;
        Map<String, Object> tree = new LinkedHashMap<>();
        tree.put("key: " + echo, "v");
        tree.put("nested", List.of(List.of(echo), 7));
        JsonNode node = JSON.readTree("{\"echo\":\"" + echo + "\",\"n\":[1,true,null]}");
        // A Jackson tree is converted to plain data first (#377, typed tree).
        tree.put("node", JSON.convertValue(node, Object.class));

        Map<?, ?> out = (Map<?, ?>) Redactor.redactTree(tree);

        assertEquals("v", out.get("key: Bearer [REDACTED]"));
        assertEquals(List.of(List.of("Bearer [REDACTED]"), 7), out.get("nested"));
        List<Object> n = new ArrayList<>(List.of(1, true));
        n.add(null);
        assertEquals(Map.of("echo", "Bearer [REDACTED]", "n", n), out.get("node"));
        assertFalse(String.valueOf(out).contains(token), String.valueOf(out));
        // An array, a collection that is not a list, an optional, a Jackson tree and any other type are not JSON-shaped
        // (#377, typed tree): each makes the whole tree the mask, so its own code never runs and nothing of it is kept.
        for (Object other : List.of(new String[] {echo}, new Object[] {List.of(echo), 7}, new ArrayDeque<>(List.of(echo)),
                Optional.of(echo), Optional.empty(), new StringBuilder(echo), node, Instant.EPOCH, Duration.ofSeconds(3),
                'x')) {
            assertEquals(Redactor.MASK, Redactor.redactTree(Map.of("v", other)), other.getClass().getName());
            assertEquals(Redactor.MASK, Redactor.redactTree(other), other.getClass().getName());
        }
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
