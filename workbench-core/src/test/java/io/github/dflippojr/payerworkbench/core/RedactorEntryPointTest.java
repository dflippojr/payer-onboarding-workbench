package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * Every entry point of {@link Redactor}, {@link StepResult} and {@link HttpExchange} that keeps caller text sends it
 * through the whole-text rule (#360, security round 3 on #361): an Authorization-style value keeps only a registered
 * scheme word, and a map key, a header name, an exchange's method and URL, a step's id and the message of a failed
 * record rebuild are redacted as any other text is. Each case puts a JWK with a private member, stringified 0 to 17
 * times (within the levels the Redactor reads, at the last one and past it), in the kept place and checks that no
 * character of the dummy secret is left there.
 */
class RedactorEntryPointTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A dummy secret whose letters appear nowhere else in the texts checked below, nor in the mask. */
    private static final String SECRET = "JGVWXZJGVWXZ";

    private static final List<String> MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth");

    /** Each member's JWK, stringified 0 to 17 times, with a label naming the member and the depth only. */
    private static Map<String, String> jwkTexts() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String m : MEMBERS) {
            String text = "{\"kty\":\"oct\",\"" + m + "\":\"" + SECRET + "\"}";
            for (int depth = 0; depth <= Redactor.NESTED_LEVELS + 1; depth++) {
                out.put("member " + m + " depth " + depth, text);
                text = "{\"body\":" + JSON.writeValueAsString(text) + "}";
            }
        }
        return out;
    }

    private static void assertNoSecret(Object kept, String label) {
        String text = String.valueOf(kept);
        for (char c : SECRET.toCharArray()) {
            assertTrue(text.indexOf(c) < 0, () -> label + ": a character of the secret is left");
        }
    }

    @Test
    void keepsOnlyARegisteredSchemeWordOfAnAuthorizationStyleValue() {
        jwkTexts().forEach((label, jwk) -> {
            for (String name : List.of("Authorization", "Proxy-Authorization", "authorization")) {
                String value = jwk + " tail";
                assertNoSecret(Redactor.redactHeaders(Map.of(name, List.of(value))), label + ", headers " + name);
                HttpExchange exchange = new HttpExchange("GET", "https://payer.example/x", 200, Duration.ZERO,
                        Map.of(name, List.of(value)), null, Map.of(name, List.of(value)), null, null);
                assertNoSecret(exchange.requestHeaders(), label + ", exchange request " + name);
                assertNoSecret(exchange.responseHeaders(), label + ", exchange response " + name);
                assertNoSecret(Redactor.redactTree(Map.of(name, value)), label + ", tree field " + name);
                assertNoSecret(Redactor.redactTree(Map.of("a", List.of(Map.of(name, List.of(value))))),
                        label + ", nested tree field " + name);
            }
        });
        // A registered scheme is still kept, in any case; any other first word is not.
        assertEquals(Map.of("Authorization", List.of("Bearer " + Redactor.MASK)),
                Redactor.redactHeaders(Map.of("Authorization", List.of("Bearer abc.def"))));
        assertEquals(Map.of("authorization", "dpop " + Redactor.MASK), Redactor.redactTree(Map.of("authorization", "dpop abc")));
        assertEquals(Map.of("Proxy-Authorization", List.of(Redactor.MASK)),
                Redactor.redactHeaders(Map.of("Proxy-Authorization", List.of("Custom abc"))));
    }

    @Test
    void redactsANonStringMapKeyAsText() {
        jwkTexts().forEach((label, jwk) -> {
            Map<Object, Object> map = new LinkedHashMap<>();
            map.put(new StringBuilder(jwk), 1);
            assertNoSecret(Redactor.redactTree(map), label + ", tree key");
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("nested", List.of(map));
            StepResult step = new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "ok", details);
            assertNoSecret(step.details(), label + ", step details key");
        });
        // Field-name and JWK decisions read the key's text, whatever holds it.
        Map<Object, Object> jwk = new LinkedHashMap<>();
        jwk.put(new StringBuilder("kty"), "oct");
        jwk.put(new StringBuilder("d"), SECRET);
        jwk.put(new StringBuilder("password"), SECRET);
        Object out = Redactor.redactTree(jwk);
        assertNoSecret(out, "text-bearing kty, private member and secret field names");
        assertEquals(Map.of("kty", "oct", "d", Redactor.MASK, "password", Redactor.MASK), out);
        // Keys that hold no text stay as they are.
        assertEquals(Map.of(1, "a", true, "b"), Redactor.redactTree(Map.of(1, "a", true, "b")));
    }

    @Test
    void redactsHeaderNamesAnExchangesMethodAndUrlAndAStepsId() {
        jwkTexts().forEach((label, jwk) -> {
            assertNoSecret(Redactor.redactHeaders(Map.of(jwk, List.of("x"))).keySet(), label + ", header name");
            HttpExchange exchange = new HttpExchange(jwk, jwk, 200, Duration.ZERO, Map.of(jwk, List.of("x")), null,
                    Map.of(jwk, List.of("x")), null, null);
            assertNoSecret(exchange.method(), label + ", method");
            assertNoSecret(exchange.url(), label + ", url");
            assertNoSecret(exchange.requestHeaders(), label + ", request header name");
            assertNoSecret(exchange.responseHeaders(), label + ", response header name");
            StepResult step = new StepResult(jwk, Instant.EPOCH, Duration.ZERO, true, "ok", Map.of());
            assertNoSecret(step.stepId(), label + ", step id");
        });
        // Ordinary values are unchanged.
        HttpExchange plain = new HttpExchange("POST", "https://payer.example/cds-services/order-sign?x=1", 200,
                Duration.ZERO, Map.of("Content-Type", List.of("application/json")), null, null, null, null);
        assertEquals("POST", plain.method());
        assertEquals("https://payer.example/cds-services/order-sign?x=1", plain.url());
        assertEquals(Map.of("Content-Type", List.of("application/json")), plain.requestHeaders());
        assertEquals("discovery", new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "ok", null).stepId());
    }

    /** A record whose accessor fails with a message that quotes what it holds. */
    record Failing(String body) {
        @Override
        public String body() {
            throw new IllegalStateException("cannot read " + body);
        }
    }

    @Test
    void keepsNoCallerTextInTheErrorOfARecordItCannotRebuild() {
        jwkTexts().forEach((label, jwk) -> {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Redactor.redactTree(new Failing(jwk)));
            List<String> messages = new ArrayList<>();
            for (Throwable t = e; t != null; t = t.getCause()) {
                messages.add(String.valueOf(t.getMessage()));
            }
            assertNoSecret(messages, label + ", error");
        });
    }
}
