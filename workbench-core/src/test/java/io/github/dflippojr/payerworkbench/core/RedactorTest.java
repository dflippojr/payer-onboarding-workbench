package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Keys and tokens are generated at runtime; nothing secret-shaped is committed. */
class RedactorTest {

    private static final SecureRandom RANDOM = new SecureRandom();

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
    void masksJwtSignatureButKeepsClaims() {
        String header = b64url("{\"alg\":\"RS384\",\"typ\":\"JWT\"}");
        String payload = b64url("{\"iss\":\"synthetic-client\",\"aud\":\"https://payer.example.test/token\"}");
        byte[] sig = new byte[256];
        RANDOM.nextBytes(sig);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        String jwt = header + "." + payload + "." + signature;

        String out = Redactor.redact("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                + "&client_assertion=" + jwt);

        assertFalse(out.contains(signature));
        assertTrue(out.contains("client_assertion=" + header + "." + payload + "." + Redactor.MASK));
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

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String b64url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
