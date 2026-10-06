package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Runs the shared corpus ({@code redaction-corpus.json}) through {@link Redactor}. The replay leak
 * scanner's test reads the same file, so the two stay in step. Everything in it is synthetic.
 */
class RedactorCorpusTest {

    private static final JsonNode CORPUS = load();

    private static JsonNode load() {
        try (InputStream in = RedactorCorpusTest.class.getResourceAsStream("/redaction-corpus.json")) {
            return JsonMapper.builder().build().readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @TestFactory
    Stream<DynamicTest> secretsAreMasked() {
        return CORPUS.get("text").valueStream().map(e -> DynamicTest.dynamicTest(e.get("id").asString(), () -> {
            String out = Redactor.redact(e.get("input").asString());
            if (e.path("scannerOnly").asBoolean(false)) {
                assertEquals(e.get("input").asString(), out, "Redactor now masks this; drop scannerOnly from the corpus entry");
                return;
            }
            assertSecretsGone(e, out);
            assertTrue(out.contains(Redactor.MASK), "no mask in: " + out);
        }));
    }

    @TestFactory
    Stream<DynamicTest> harmlessTextIsUntouched() {
        return CORPUS.get("harmless").valueStream().map(e -> DynamicTest.dynamicTest(e.get("id").asString(), () -> {
            String input = e.get("input").asString();
            assertEquals(input, Redactor.redact(input));
        }));
    }

    @TestFactory
    Stream<DynamicTest> sensitiveHeadersAreMasked() {
        return CORPUS.get("headers").valueStream().map(e -> DynamicTest.dynamicTest(e.get("name").asString(), () -> {
            String name = e.get("name").asString();
            assertTrue(Redactor.isSensitiveHeader(name));
            String out = Redactor.redactHeaders(Map.of(name, List.of(e.get("value").asString()))).get(name).get(0);
            assertSecretsGone(e, out);
            assertTrue(out.contains(Redactor.MASK), "no mask in: " + out);
        }));
    }

    @TestFactory
    Stream<DynamicTest> harmlessHeadersAreUntouched() {
        return CORPUS.get("harmlessHeaders").valueStream().map(e -> DynamicTest.dynamicTest(e.get("name").asString(), () -> {
            String name = e.get("name").asString();
            String value = e.get("value").asString();
            assertFalse(Redactor.isSensitiveHeader(name));
            assertEquals(List.of(value), Redactor.redactHeaders(Map.of(name, List.of(value))).get(name));
        }));
    }

    private static void assertSecretsGone(JsonNode entry, String out) {
        for (JsonNode secret : entry.get("secrets")) {
            assertFalse(out.contains(secret.asString()), "secret survived: " + out);
        }
    }
}
