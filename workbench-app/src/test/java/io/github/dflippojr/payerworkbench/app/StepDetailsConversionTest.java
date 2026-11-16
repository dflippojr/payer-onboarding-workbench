package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Redactor;
import io.github.dflippojr.payerworkbench.core.StepResult;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * The runner's conversion of a step's details to their JSON form sits inside the outermost fail-closed boundary (#360,
 * owner amendment of 2026-11-16 after security round 5 on #361): whatever converting a detail throws, a record accessor,
 * a key's string form, a value nested deep in the details, the step is recorded with its details masked, and no
 * exception, message or cause leaves. Each case quotes a JWK with a private member, stringified 0 to 17 times, in what it
 * throws, and checks that no character of the dummy secret reaches the step or escapes in an exception.
 */
class StepDetailsConversionTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A dummy secret whose letters appear nowhere else in the texts checked below, nor in the mask. */
    private static final String SECRET = "JGVWXZJGVWXZ";

    /** The escape levels the Redactor reads (its package-private {@code NESTED_LEVELS}). */
    private static final int LEVELS = 16;

    private static final List<String> MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth");

    private static Map<String, String> jwkTexts() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String m : MEMBERS) {
            String text = "{\"kty\":\"oct\",\"" + m + "\":\"" + SECRET + "\"}";
            for (int depth = 0; depth <= LEVELS + 1; depth++) {
                out.put("member " + m + " depth " + depth, text);
                text = "{\"body\":" + JSON.writeValueAsString(text) + "}";
            }
        }
        return out;
    }

    private static boolean leaks(Object kept) {
        String text = String.valueOf(kept);
        return SECRET.chars().anyMatch(c -> text.indexOf(c) >= 0);
    }

    /** A record whose accessor throws, quoting what it holds in the message and the cause. */
    public record FailingAccessor(String body) {
        @Override
        public String body() {
            throw new IllegalStateException("cannot read " + body, new IllegalArgumentException(body));
        }
    }

    /** A map key whose string form throws, quoting what it holds. */
    static final class FailingKey {
        private final String text;

        FailingKey(String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            throw new IllegalStateException("cannot show " + text);
        }
    }

    /** What the runner records for a step with these details: their conversion, then {@link StepResult}, as its step() does. */
    private static StepResult recorded(Map<String, Object> details) {
        return new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "ok", OnboardingRunner.asJson(details));
    }

    @Test
    void masksADetailWhoseConversionThrowsAndLetsNoExceptionOrItsMessageOut() {
        List<String> misses = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, String> jwk : jwkTexts().entrySet()) {
            Map<String, Function<String, Map<String, Object>>> forms = new LinkedHashMap<>();
            forms.put("accessor", t -> details("record", new FailingAccessor(t)));
            forms.put("key", t -> details("nested", Map.of(new FailingKey(t), 1)));
            forms.put("nested accessor", t -> details("nested", List.of(Map.of("deep", List.of(new FailingAccessor(t))))));
            for (Map.Entry<String, Function<String, Map<String, Object>>> form : forms.entrySet()) {
                total++;
                String label = jwk.getKey() + ", " + form.getKey();
                try {
                    StepResult step = recorded(form.getValue().apply(jwk.getValue()));
                    if (leaks(step.stepId()) || leaks(step.summary()) || leaks(step.details())) {
                        misses.add(label + ": a character of the secret is left");
                    }
                } catch (Throwable e) {
                    List<String> messages = new ArrayList<>();
                    for (Throwable t = e; t != null; t = t.getCause()) {
                        messages.add(String.valueOf(t.getMessage()));
                    }
                    misses.add(label + ": threw " + e.getClass().getSimpleName()
                            + (leaks(messages) ? ", with a character of the secret in its messages" : ""));
                }
            }
        }
        int count = total;
        assertTrue(misses.isEmpty(), () -> misses.size() + " of " + count + " cases leaked or threw, first: "
                + misses.subList(0, Math.min(5, misses.size())));
        // Details that convert keep their JSON form, and the step's status survives a conversion that throws.
        assertEquals(Map.of("services", 2, "status", "passed"),
                recorded(details("services", 2)).details());
        assertEquals("passed", recorded(details("record", new FailingAccessor("x"))).details().get("status"));
    }

    private static Map<String, Object> details(String key, Object value) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(key, value);
        details.put("status", "passed");
        return details;
    }
}
