package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
import org.commonmark.ext.gfm.tables.TableCell;
import org.commonmark.node.Heading;
import org.commonmark.node.Node;
import org.commonmark.node.Paragraph;

/**
 * Class-level check (#213): text from the payer cannot change the structure of the Markdown report.
 * Generated texts, built from the punctuation that starts CommonMark and GFM markup, line breaks
 * and blank lines, go into the payer display name, a step summary and a finding's title,
 * explanation and fix, one text each. Parsed with CommonMark and GFM tables, the report must have
 * exactly the nodes (headings, lists, tables, links, images, code, emphasis, HTML) of the same
 * report with a marker word in each field, and the node that shows each marker there must show the
 * field's text literally instead.
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

    /** The payer's text in each field the report shows; markers in the plain report. */
    record Texts(String name, String summary, String title, String explanation, String fix) {
    }

    private static final Texts PLAIN = new Texts("plainname", "plainsummary", "plaintitle", "plainexplanation", "plainfix");

    @Property(tries = 1000)
    void payerTextIsLiteralAndLeavesTheReportShapeAlone(@ForAll("payerText") String name,
            @ForAll("payerText") String summary, @ForAll("payerText") String title,
            @ForAll("payerText") String explanation, @ForAll("payerText") String fix) {
        RunReport plain = report(PLAIN);
        RunReport fuzzed = report(new Texts(name, summary, title, explanation, fix));
        String md = ReportRenderer.markdown(fuzzed);
        Node doc = MarkdownTree.parse(md);
        Node plainDoc = MarkdownTree.parse(ReportRenderer.markdown(plain));

        assertEquals(MarkdownTree.shape(plainDoc), MarkdownTree.shape(doc),
                () -> "payer text changed the report's structure:\n" + md);
        Finding finding = fuzzed.findings().getFirst();
        // Each value as the renderer gets it; the report title, which holds the name, is replaced first.
        Map<String, String> shown = new LinkedHashMap<>();
        shown.put(plain.title(), fuzzed.title());
        shown.put(PLAIN.name(), fuzzed.payer().displayName());
        shown.put(PLAIN.summary(), fuzzed.steps().get(1).summary());
        shown.put(PLAIN.title(), finding.title());
        shown.put(PLAIN.explanation(), finding.explanation());
        shown.put(PLAIN.fix(), finding.suggestedFix());
        // Same shape, so the n-th block of one report is the n-th block of the other.
        List<Node> plainNodes = blocks(plainDoc);
        List<Node> nodes = blocks(doc);
        int checked = 0;
        for (int i = 0; i < plainNodes.size(); i++) {
            Node node = plainNodes.get(i);
            // A paragraph keeps the text's line breaks; a heading or a table cell has it on one line.
            String separator = node instanceof Paragraph ? "\n" : " ";
            String expected = MarkdownTree.text(node);
            for (Map.Entry<String, String> field : shown.entrySet()) {
                expected = expected.replace(field.getKey(), lines(field.getValue(), separator));
            }
            if (!expected.equals(MarkdownTree.text(node))) {
                checked++;
                String actual = MarkdownTree.text(nodes.get(i));
                assertEquals(expected, actual, () -> "not shown literally:\n---\n" + md);
            }
        }
        // The title heading and the Payer cell show the name; one node each for the other four fields.
        assertEquals(6, checked);
    }

    /** The paragraphs, headings and table cells, in document order. */
    private static List<Node> blocks(Node doc) {
        return MarkdownTree.nodes(doc).stream()
                .filter(n -> n instanceof Paragraph || n instanceof Heading || n instanceof TableCell).toList();
    }

    /** The text's non-blank lines without their surrounding whitespace, joined as the report shows them. */
    private static String lines(String text, String separator) {
        return Arrays.stream(text.split("\r\n|\r|\n")).map(String::strip).filter(l -> !l.isEmpty())
                .collect(Collectors.joining(separator));
    }

    private static RunReport report(Texts text) {
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
                new StepResult("hook-request", T0, Duration.ofMillis(12), false, text.summary(), details)),
                List.of(new Finding("auth.hook-rejected", Severity.FAIL, text.title(), text.explanation(), null,
                        text.fix())));
        return RunReport.of(run, text.name(), "2.1.0", Instant.parse("2026-10-01T12:30:00Z"), "9.9.9-test");
    }
}
