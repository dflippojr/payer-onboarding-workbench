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

    // ---- round 6 class: a key whose type carries JWK context, through a conversion that succeeds ----

    /** A map key whose type declares a {@code kty} field while its text names a private member. */
    static final class TypedKey {
        @SuppressWarnings("unused") // Its declaration is the JWK context the key carries.
        private final String kty = "oct";
        private final String name;

        TypedKey(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /** The dummy secret as a JSON string value stringified {@code depth} times more. */
    private static String secretAt(int depth) {
        String text = SECRET;
        for (int i = 0; i < depth; i++) {
            text = JSON.writeValueAsString(text);
        }
        return text;
    }

    @Test
    void keepsTheJwkContextAKeysTypeCarriesThroughTheRunnersConversion() {
        List<String> misses = new ArrayList<>();
        int total = 0;
        for (String m : MEMBERS) {
            for (int depth = 0; depth <= LEVELS + 1; depth++) {
                String value = secretAt(depth);
                Map<String, Map<String, Object>> forms = new LinkedHashMap<>();
                Map<Object, Object> own = new LinkedHashMap<>();
                own.put(new TypedKey(m), value);
                forms.put("in a nested map", details("nested", own));
                forms.put("in a map in a list", details("nested", List.of(Map.of("deep", own))));
                Map<String, Object> top = new LinkedHashMap<>();
                rawPut(top, new TypedKey(m), value);
                top.put("status", "passed");
                forms.put("in the details", top);
                for (Map.Entry<String, Map<String, Object>> form : forms.entrySet()) {
                    for (boolean runner : List.of(true, false)) {
                        total++;
                        String label = "member " + m + " depth " + depth + ", " + form.getKey()
                                + (runner ? ", through the runner" : ", straight to the step");
                        try {
                            StepResult step = runner ? recorded(form.getValue())
                                    : new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "ok", form.getValue());
                            if (leaks(step.details()) || leaks(JSON.writeValueAsString(step.details()))) {
                                misses.add(label + ": a character of the secret is left");
                            }
                        } catch (Throwable e) {
                            misses.add(label + ": threw " + e.getClass().getSimpleName());
                        }
                    }
                }
            }
        }
        int count = total;
        assertTrue(misses.isEmpty(), () -> misses.size() + " of " + count + " cases leaked or threw, first: "
                + misses.subList(0, Math.min(5, misses.size())));
    }

    @SuppressWarnings("unchecked")
    private static void rawPut(Map<String, Object> map, Object key, Object value) {
        ((Map<Object, Object>) (Map<?, ?>) map).put(key, value);
    }

    // ---- general: the runner's conversion runs each caller method at most once and keeps no caller object ----

    /** A caller object that counts its calls and holds text. */
    static final class CountingText {
        private final Map<String, Integer> calls;
        private final String text;

        CountingText(Map<String, Integer> calls, String text) {
            this.calls = calls;
            this.text = text;
        }

        @Override
        public String toString() {
            calls.merge("toString", 1, Integer::sum);
            return text;
        }

        @Override
        public int hashCode() {
            calls.merge("hashCode", 1, Integer::sum);
            return 1;
        }

        @Override
        public boolean equals(Object o) {
            calls.merge("equals", 1, Integer::sum);
            return o == this;
        }
    }

    @Test
    void runsEachCallerMethodOfTheDetailsAtMostOnceAndKeepsNoCallerObject() {
        List<String> misses = new ArrayList<>();
        for (Map.Entry<String, String> jwk : jwkTexts().entrySet()) {
            Map<String, Integer> calls = new LinkedHashMap<>();
            CountingText value = new CountingText(calls, jwk.getValue());
            Map<String, Object> details = details("nested", List.of(value));
            StepResult step = recorded(details);
            Map<String, Integer> during = Map.copyOf(calls);
            String shown = String.valueOf(step.details()) + step.details().hashCode() + JSON.writeValueAsString(step.details());
            if (during.values().stream().anyMatch(n -> n > 1)) {
                misses.add(jwk.getKey() + ": a caller method ran more than once: " + during);
            } else if (!calls.equals(during)) {
                misses.add(jwk.getKey() + ": a caller method ran after the conversion returned");
            } else if (leaks(shown)) {
                misses.add(jwk.getKey() + ": a character of the secret is left");
            } else if (step.details().get("nested") instanceof List<?> list && list.stream().anyMatch(o -> o == value)) {
                misses.add(jwk.getKey() + ": a caller object is kept");
            }
        }
        assertTrue(misses.isEmpty(), () -> misses.size() + " cases missed, first: " + misses.subList(0, Math.min(5, misses.size())));
    }
}
