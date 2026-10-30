package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.FABRIKAM_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.TAILSPIN_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The UI's words about a fault against what the fault does (#301). The copy in {@code app.js} said
 * {@code slow-response} held every response long after a2ed16b narrowed it to hook calls, and nothing compared
 * the two. Here each fault runs through the real {@link OnboardingRunner} on all three payers, the calls that
 * came back with {@value MockPayer#FAULT_HEADER} are its measured scope, and the copy may not claim another
 * scope. A change to either side alone fails: narrowing a fault under old copy, or rewording copy past the
 * fault.
 */
@SpringBootTest(properties = {
        "workbench.latency-warn=300ms",
        "workbench.latency-fail=600ms",
        "workbench.slow-response-delay=900ms"})
class FaultCopyContractTest {

    /** A kind of payer call a run makes, by the step that makes it. */
    private enum Call {
        DISCOVERY("discovery"), TOKEN("authenticate"), HOOK("hook-request");

        final String stepId;

        Call(String stepId) {
            this.stepId = stepId;
        }
    }

    private static final String HEALTHY_SAMPLE = "order-sign-hospital-bed";
    /** prefetch-missing-400 only fires when the client leaves out prefetch it could have sent. */
    private static final String NO_PREFETCH_SAMPLE = "order-sign-missing-prefetch";

    private static final Pattern FAULTS_BLOCK = Pattern.compile("const FAULTS = \\{(.*?)\\n};", Pattern.DOTALL);
    private static final Pattern FAULT_ROW = Pattern.compile("'([a-z0-9-]+)': \\['[^']*', '([^']*)'\\]");
    /** Copy outside the table that talks about one fault, such as the running-state line. */
    private static final Pattern FAULT_SENTENCE = Pattern.compile("'(The ([a-z0-9-]+) fault [^']*)'");
    private static final Pattern UNIVERSAL_CLAIM =
            Pattern.compile("\\b(every|each|all)\\s+(responses?|requests?|calls?)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern NAMES_HOOK_CALLS = Pattern.compile("\\bhook calls?\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern NAMES_DISCOVERY = Pattern.compile("GET /cds-services\\b");

    @Autowired
    OnboardingRunner runner;

    @Test
    void theFaultTableDescribesEveryFaultAndNoOthers() throws IOException {
        Set<String> known = Arrays.stream(Fault.values()).map(Fault::id).collect(Collectors.toSet());
        assertEquals(known, helpText().keySet());
    }

    @ParameterizedTest
    @EnumSource(Fault.class)
    void theCopyClaimsOnlyTheCallsTheFaultTouches(Fault fault) throws IOException {
        Set<Call> measured = measuredScope(fault);
        for (String copy : copyAbout(fault)) {
            String context = fault.id() + " touches " + measured + " but the UI says: " + copy;
            assertFalse(UNIVERSAL_CLAIM.matcher(copy).find(), context);
            if (NAMES_HOOK_CALLS.matcher(copy).find()) {
                assertEquals(EnumSet.of(Call.HOOK), measured, context);
            }
            if (NAMES_DISCOVERY.matcher(copy).find()) {
                assertEquals(EnumSet.of(Call.DISCOVERY), measured, context);
            }
        }
    }

    /** Copy that names no call passes the rule above, so the fault this issue is about must name its call. */
    @Test
    void slowResponseCopySaysOnlyHookCallsAreHeld() throws IOException {
        List<String> copy = copyAbout(Fault.SLOW_RESPONSE);
        assertEquals(2, copy.size(), () -> "the help text and the running-state line: " + copy);
        copy.forEach(text -> assertTrue(NAMES_HOOK_CALLS.matcher(text).find(), text));
        assertEquals(EnumSet.of(Call.HOOK), measuredScope(Fault.SLOW_RESPONSE));
    }

    private Set<Call> measuredScope(Fault fault) {
        String sample = fault == Fault.PREFETCH_MISSING_400 ? NO_PREFETCH_SAMPLE : HEALTHY_SAMPLE;
        Set<Call> touched = EnumSet.noneOf(Call.class);
        for (String payerId : List.of(NORTHWIND_ID, FABRIKAM_ID, TAILSPIN_ID)) {
            OnboardingRun run = runner.run(new RunRequest(payerId, Environment.SANDBOX, sample,
                    List.of(fault.id()), null, null));
            for (Call call : Call.values()) {
                if (carriesFaultHeader(run, call, fault)) {
                    touched.add(call);
                }
            }
        }
        return touched;
    }

    @SuppressWarnings("unchecked")
    private static boolean carriesFaultHeader(OnboardingRun run, Call call, Fault fault) {
        return run.steps().stream()
                .filter(step -> step.stepId().equals(call.stepId))
                .map(StepResult::details)
                .map(details -> (List<ExchangeView>) details.getOrDefault("exchanges", List.of()))
                .flatMap(List::stream)
                .flatMap(exchange -> exchange.responseHeaders().entrySet().stream())
                .anyMatch(header -> header.getKey().equalsIgnoreCase(MockPayer.FAULT_HEADER)
                        && header.getValue().contains(fault.id()));
    }

    private static List<String> copyAbout(Fault fault) throws IOException {
        List<String> copy = new ArrayList<>();
        copy.add(helpText().get(fault.id()));
        Matcher sentences = FAULT_SENTENCE.matcher(appJs());
        while (sentences.find()) {
            if (sentences.group(2).equals(fault.id())) {
                copy.add(sentences.group(1));
            }
        }
        return copy;
    }

    private static Map<String, String> helpText() throws IOException {
        Matcher block = FAULTS_BLOCK.matcher(appJs());
        assertTrue(block.find(), "app.js has no FAULTS table");
        Map<String, String> help = new LinkedHashMap<>();
        Matcher rows = FAULT_ROW.matcher(block.group(1));
        while (rows.find()) {
            help.put(rows.group(1), rows.group(2));
        }
        return help;
    }

    private static String appJs() throws IOException {
        return new ClassPathResource("static/app.js").getContentAsString(StandardCharsets.UTF_8);
    }
}
