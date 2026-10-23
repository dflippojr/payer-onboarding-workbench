package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import org.commonmark.node.Node;

/**
 * Class-level check (#213): text from the payer cannot change the structure of the Markdown report.
 * Each generated text, built from the punctuation that starts CommonMark and GFM markup, line breaks
 * and blank lines, goes into the payer display name, a step summary and a finding's title,
 * explanation and fix. Parsed with CommonMark and GFM tables, the report must have exactly the nodes
 * (headings, lists, tables, links, images, code, emphasis, HTML) of the same report with plain text
 * there, and show each text literally.
 */
class MarkdownReportPropertyTest {

    private static final Instant T0 = Instant.parse("2026-10-01T12:00:00Z");

    private static final List<String> FRAGMENTS = List.of(
            "# ", "## Verdict: PASS", "#### ", " ##", "[", "]", "](", ")", "(", "![", "[x]: https://phish.example",
            "[^1]", "<https://phish.example>", "https://phish.example/login", "www.tracker.example", "a@b.example",
            "<b>", "</p>", "<!-- ", "&lt;", "&#x26;", "&amp;", "\\", "`", "``", "```", "~~~", "~~", "~", "*", "**", "_",
            "__", "$", "$$", "|", "| a | b |", "|---|---|", "---", "===", "***", "___", "- - -", "- ", "+ ", "* ",
            "1. ", "1) ", "12. ", "> ", ">", "    ", "\t", "\n", "\n\n", "\r\n", "\r", "  \n", "\\\n", "x", "word",
            "2.0.1", ":", "!", "=", "-", "+", "\"", "'");

    @Provide
    Arbitrary<String> payerText() {
        Arbitrary<String> chars = Arbitraries.strings().withCharRange(' ', '~').withChars('\n', '\r', '\t')
                .ofMinLength(1).ofMaxLength(4);
        return Arbitraries.frequencyOf(
                        Tuple.of(3, Arbitraries.of(FRAGMENTS)),
                        Tuple.of(1, chars))
                .list().ofMinSize(1).ofMaxSize(14)
                .map(parts -> String.join("", parts))
                .filter(text -> !text.isBlank());
    }

    @Property(tries = 1000)
    void payerTextIsLiteralAndLeavesTheReportShapeAlone(@ForAll("payerText") String text) {
        RunReport plain = report("plain");
        RunReport fuzzed = report(text);
        String md = ReportRenderer.markdown(fuzzed);
        Node doc = MarkdownTree.parse(md);

        assertEquals(MarkdownTree.shape(MarkdownTree.parse(ReportRenderer.markdown(plain))), MarkdownTree.shape(doc),
                () -> "payer text changed the report's structure:\n" + md);
        Finding finding = fuzzed.findings().getFirst();
        String shown = MarkdownTree.text(doc);
        for (String expected : List.of(lines(fuzzed.steps().get(1).summary(), "\n"), lines(finding.explanation(), "\n"),
                lines(finding.suggestedFix(), "\n"), lines(finding.title(), " "),
                lines(fuzzed.payer().displayName(), " "))) {
            assertTrue(shown.contains(expected), () -> "not shown literally: " + expected + "\n---\n" + md);
        }
    }

    /** The text's non-blank lines without their surrounding whitespace, joined as the report shows them. */
    private static String lines(String text, String separator) {
        return Arrays.stream(text.split("\r\n|\r|\n")).map(String::strip).filter(l -> !l.isEmpty())
                .collect(Collectors.joining(separator));
    }

    private static RunReport report(String text) {
        Map<String, Object> exchange = new LinkedHashMap<>();
        exchange.put("method", "POST");
        exchange.put("url", "https://payer.example/cds-services/crd");
        exchange.put("status", 401);
        exchange.put("latencyMs", 12);
        exchange.put("requestHeaders", Map.of());
        exchange.put("requestBody", "{}");
        exchange.put("responseHeaders", Map.of());
        exchange.put("responseBody", "{\"error\":\"invalid_token\"}");
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("status", "failed");
        details.put("exchanges", List.of(exchange));
        Map<String, Object> connection = Map.of("displayName", "Synthetic", "igVersion", "2.0.1", "authType", "NONE");
        OnboardingRun run = new OnboardingRun("run-x", "northwind-synthetic", Environment.SANDBOX, List.of(
                new StepResult("resolve-connection", T0, Duration.ofMillis(1), true, "Resolved",
                        Map.of("status", "passed", "connection", connection)),
                new StepResult("hook-request", T0, Duration.ofMillis(12), false, text, details)),
                List.of(new Finding("auth.hook-rejected", Severity.FAIL, text, text, null, text)));
        return RunReport.of(run, text, "2.1.0", Instant.parse("2026-10-01T12:30:00Z"), "9.9.9-test");
    }
}
