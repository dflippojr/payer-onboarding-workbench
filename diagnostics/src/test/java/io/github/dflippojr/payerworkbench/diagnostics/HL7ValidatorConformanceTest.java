package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.AllowedItem;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.AllowlistEntry;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.Issue;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.Verdict;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The differential conformance test: for every corpus response, the verdicts of
 * {@code response.schema}, {@code response.coverage-information} and
 * {@code response.coverage-location} must agree with the official HL7 FHIR Validator's errors
 * and warnings, mapped by {@link ConformanceMapping}. A disagreement fails the test with both
 * outputs unless {@code conformance-allowlist.json} records it. Run it with
 * {@code bash scripts/hl7-validator.sh warm test}; it writes {@code target/hl7-validator/report.md}.
 */
@Tag("hl7-validator")
class HL7ValidatorConformanceTest {

    private static final Path PINS = Path.of("../scripts/hl7-validator.env");
    private static final Path OUT = Path.of("target/hl7-validator");

    private record Comparison(String item, DiagnosticCheck check, Verdict workbench, Verdict validator,
                              List<Finding> findings, List<Issue> issues) {
        boolean agrees() {
            return workbench == validator;
        }

        String key() {
            return item + " / " + check.id();
        }

        String describe() {
            StringBuilder sb = new StringBuilder(key()).append(": workbench ").append(workbench)
                    .append(", HL7 validator ").append(validator).append('\n');
            sb.append("  workbench findings:\n");
            findings.forEach(f -> sb.append("    ").append(f.severity()).append(' ').append(f.title()).append('\n')
                    .append(indent(f.evidence())));
            sb.append("  validator issues mapped to ").append(check.id()).append(":\n");
            issues.forEach(i -> sb.append("    ").append(i).append('\n'));
            return sb.toString();
        }
    }

    @Test
    void workbenchVerdictsAgreeWithTheHl7Validator() throws Exception {
        String jar = System.getenv("HL7_VALIDATOR_JAR");
        String home = System.getenv("HL7_VALIDATOR_HOME");
        assertNotNull(jar, "HL7_VALIDATOR_JAR is not set; run: bash scripts/hl7-validator.sh warm test");
        assertNotNull(home, "HL7_VALIDATOR_HOME is not set; run: bash scripts/hl7-validator.sh warm test");
        Properties pins = new Properties();
        try (var in = Files.newBufferedReader(PINS)) {
            pins.load(in);
        }

        List<ConformanceCorpus.Item> items = ConformanceCorpus.items();
        Map<String, List<Issue>> outcomes = validate(jar, home, pins, items);

        List<Comparison> comparisons = new ArrayList<>();
        Map<String, Integer> unclaimed = new TreeMap<>();
        for (ConformanceCorpus.Item item : items) {
            List<Issue> issues = outcomes.get(item.file());
            assertNotNull(issues, "the validator reported nothing for " + item.file());
            for (DiagnosticCheck check : ConformanceMapping.CHECKS) {
                List<Finding> findings = ConformanceMapping.findings(check, item.body().toString());
                comparisons.add(new Comparison(item.id(), check, ConformanceMapping.workbenchVerdict(findings),
                        ConformanceMapping.validatorVerdict(check.id(), issues, item.body()), findings,
                        ConformanceMapping.claimed(check.id(), issues, item.body())));
            }
            issues.stream()
                    .filter(i -> i.verdict() != Verdict.OK)
                    .filter(i -> ConformanceMapping.territory(i, item.body()).equals(ConformanceMapping.UNCLAIMED))
                    .forEach(i -> unclaimed.merge(i.severity() + " " + i.messageId(), 1, Integer::sum));
        }

        List<AllowlistEntry> allowlist = ConformanceMapping.allowlist();
        List<String> unexpected = new ArrayList<>();
        List<String> stale = new ArrayList<>();
        for (Comparison c : comparisons) {
            Optional<AllowedItem> allowed = allowlist.stream()
                    .flatMap(e -> e.find(c.item(), c.check().id()).stream()).findFirst();
            boolean expected = allowed.isPresent() && allowed.get().workbench() == c.workbench()
                    && allowed.get().validator() == c.validator();
            if (!c.agrees() && !expected) {
                unexpected.add(c.describe());
            } else if (c.agrees() && allowed.isPresent()) {
                stale.add(c.key() + " is allowlisted but now agrees (" + c.workbench() + "); remove it");
            }
        }

        String report = report(pins, items.size(), comparisons, allowlist, unclaimed, unexpected, stale);
        Files.createDirectories(OUT);
        Files.writeString(OUT.resolve("report.md"), report);
        System.out.println(report);

        assertTrue(unexpected.isEmpty(), unexpected.size() + " disagreement(s) with the HL7 validator:\n"
                + String.join("\n", unexpected));
        assertTrue(stale.isEmpty(), String.join("\n", stale));
    }

    /** One validator run over every corpus file, offline. */
    private static Map<String, List<Issue>> validate(String jar, String home, Properties pins,
                                                     List<ConformanceCorpus.Item> items) throws Exception {
        Files.createDirectories(OUT);
        Path output = OUT.resolve("validator-output.json").toAbsolutePath();
        Path log = OUT.resolve("validator.log");
        List<String> command = new ArrayList<>(List.of(
                ProcessHandle.current().info().command().orElse("java"),
                "-Xmx" + System.getenv().getOrDefault("HL7_VALIDATOR_XMX", "3g"),
                "-Duser.home=" + home, "-jar", jar));
        for (ConformanceCorpus.Item item : items) {
            command.add(ConformanceCorpus.DIR.resolve(item.file()).toAbsolutePath().toString());
        }
        command.addAll(List.of("-version", pins.getProperty("FHIR_VERSION"), "-ig", pins.getProperty("IG"),
                "-profile", pins.getProperty("PROFILE"), "-tx", "n/a", "-allow-example-urls", "true",
                "-no-http-access", "-output", output.toString()));
        Files.deleteIfExists(output);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(15, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            throw new AssertionError("the HL7 validator ran for over 15 minutes; see " + log.toAbsolutePath());
        }
        // The validator exits non-zero when any input has errors; only a missing report is a failed run.
        if (!Files.exists(output) || Files.size(output) == 0) {
            throw new AssertionError("the HL7 validator wrote no report (exit " + process.exitValue() + "):\n"
                    + tail(log));
        }
        return ConformanceMapping.parseOutput(ConformanceCorpus.read(output));
    }

    private static String report(Properties pins, int itemCount, List<Comparison> comparisons,
                                 List<AllowlistEntry> allowlist, Map<String, Integer> unclaimed,
                                 List<String> unexpected, List<String> stale) {
        long agreed = comparisons.stream().filter(Comparison::agrees).count();
        StringBuilder sb = new StringBuilder("# HL7 validator conformance\n\n")
                .append("Validator ").append(pins.getProperty("VALIDATOR_VERSION")).append(", ")
                .append(pins.getProperty("IG")).append(", profile ").append(pins.getProperty("PROFILE")).append("\n\n")
                .append(String.format("**Agreement: %d of %d verdicts (%.1f%%)** over %d responses x %d checks.%n%n",
                        agreed, comparisons.size(), 100.0 * agreed / comparisons.size(), itemCount,
                        ConformanceMapping.CHECKS.size()));
        sb.append("| Response | ").append(String.join(" | ", ConformanceMapping.CHECKS.stream().map(DiagnosticCheck::id).toList()))
                .append(" |\n|---|---|---|---|\n");
        for (int i = 0; i < comparisons.size(); i += ConformanceMapping.CHECKS.size()) {
            sb.append("| ").append(comparisons.get(i).item());
            for (Comparison c : comparisons.subList(i, i + ConformanceMapping.CHECKS.size())) {
                sb.append(" | ").append(c.agrees() ? c.workbench().toString()
                        : "**" + c.workbench() + " vs " + c.validator() + "**");
            }
            sb.append(" |\n");
        }
        sb.append("\nCells read workbench vs validator where they differ.\n\n## Allowlist\n\n");
        for (AllowlistEntry e : allowlist) {
            sb.append("- **").append(e.id()).append("** (").append(e.check()).append(", ")
                    .append(e.items().size()).append(" response(s)): ").append(e.reason()).append(' ')
                    .append(e.issue()).append('\n');
            e.items().forEach(i -> sb.append("  - ").append(i.id()).append(": workbench ").append(i.workbench())
                    .append(" vs validator ").append(i.validator()).append('\n'));
        }
        sb.append("\n## Validator issues no check claims\n\n");
        unclaimed.forEach((k, v) -> sb.append("- ").append(k).append(": ").append(v).append('\n'));
        if (!unexpected.isEmpty()) {
            sb.append("\n## Unexpected disagreements\n\n```\n").append(String.join("\n", unexpected)).append("```\n");
        }
        if (!stale.isEmpty()) {
            sb.append("\n## Stale allowlist entries\n\n");
            stale.forEach(s -> sb.append("- ").append(s).append('\n'));
        }
        return sb.toString();
    }

    private static String indent(String text) {
        return text == null ? "" : text.lines().map(l -> "      " + l + "\n").reduce("", String::concat);
    }

    private static String tail(Path log) throws IOException {
        List<String> lines = Files.readAllLines(log, StandardCharsets.UTF_8);
        return String.join("\n", lines.subList(Math.max(0, lines.size() - 40), lines.size()));
    }
}
