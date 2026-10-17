package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The table in {@code conformance-corpus/README.md} that maps the HL7 FHIR Validator's issues
 * onto the workbench's three response checks, so their verdicts can be compared.
 *
 * <ul>
 *   <li><b>Where an issue belongs.</b> {@code Extension_EXTP_Context_Wrong} for the
 *       coverage-information extension belongs to {@code response.coverage-location}. An issue at or
 *       inside a coverage-information extension belongs to {@code response.coverage-information}. An
 *       issue on the CDS Hooks envelope (cards and the response itself, outside any action resource)
 *       belongs to {@code response.schema}, except card {@code source.topic} codings, which no check
 *       judges. Everything else (the rest of the echoed order) is unclaimed.</li>
 *   <li><b>Verdicts.</b> The validator's verdict for a check is its worst claimed issue: {@code error}
 *       or {@code fatal} is FAIL, {@code warning} is WARN, {@code information} is ignored. The
 *       workbench's verdict is its worst finding: FAIL is FAIL, WARN is WARN, PASS, INFO or no
 *       finding is OK.</li>
 * </ul>
 */
final class ConformanceMapping {

    enum Verdict { OK, WARN, FAIL }

    static final String UNCLAIMED = "unclaimed";

    static final List<DiagnosticCheck> CHECKS = List.of(
            new ResponseSchemaCheck(), new CoverageInformationCheck(), new CoverageLocationCheck());

    /** One validator issue: severity, message id (or invariant URL), FHIRPath location and text. */
    record Issue(String severity, String messageId, String location, String text) {
        Verdict verdict() {
            return switch (severity) {
                case "error", "fatal" -> Verdict.FAIL;
                case "warning" -> Verdict.WARN;
                default -> Verdict.OK;
            };
        }

        @Override
        public String toString() {
            return severity + " " + messageId + " at " + location + ": " + text;
        }
    }

    /** A response the allowlist expects to disagree, with the verdict pair it expects. */
    record AllowedItem(String id, Verdict workbench, Verdict validator) { }

    /**
     * One known disagreement in {@code conformance-allowlist.json}: a cause, the {@code check} it
     * affects, the responses where it shows, why, and the open issue tracking it.
     */
    record AllowlistEntry(String id, String check, List<AllowedItem> items, String reason, String issue) {
        Optional<AllowedItem> find(String item, String checkId) {
            return check.equals(checkId) ? items.stream().filter(i -> i.id().equals(item)).findFirst() : Optional.empty();
        }
    }

    static List<AllowlistEntry> allowlist() {
        List<AllowlistEntry> entries = new ArrayList<>();
        for (JsonNode e : ConformanceCorpus.read(ConformanceCorpus.DIR.resolve(ConformanceCorpus.ALLOWLIST)).path("entries")) {
            List<AllowedItem> items = new ArrayList<>();
            e.path("items").forEach(i -> items.add(new AllowedItem(i.path("id").asText(),
                    Verdict.valueOf(i.path("workbench").asText()), Verdict.valueOf(i.path("validator").asText()))));
            entries.add(new AllowlistEntry(e.path("id").asText(), e.path("check").asText(), items,
                    e.path("reason").asText(), e.path("issue").asText()));
        }
        return entries;
    }

    private static final String MESSAGE_ID = "http://hl7.org/fhir/StructureDefinition/operationoutcome-message-id";
    private static final String FILE = "http://hl7.org/fhir/StructureDefinition/operationoutcome-file";
    private static final String CONTEXT_WRONG = "Extension_EXTP_Context_Wrong";
    /** An action resource in a location: {@code ...actions[0].resource/*DeviceRequest/x*}{@code /.extension[0]}. */
    private static final String RESOURCE_OPEN = ".resource/*";
    private static final String RESOURCE_CLOSE = "*/";
    private static final Pattern URL_FILTER = Pattern.compile("\\[url='[^']*']");
    private static final Pattern STEP = Pattern.compile("^([A-Za-z]+)(?:\\[(\\d+)])?$");
    private static final Pattern OF_TYPE = Pattern.compile("^ofType\\(([A-Za-z]+)\\)$");

    private ConformanceMapping() {
    }

    /** The validator's {@code -output} (a Bundle of OperationOutcomes, or one) as issues per input file name. */
    static Map<String, List<Issue>> parseOutput(JsonNode output) {
        List<JsonNode> outcomes = new ArrayList<>();
        if ("Bundle".equals(output.path("resourceType").asText())) {
            output.path("entry").forEach(entry -> outcomes.add(entry.path("resource")));
        } else {
            outcomes.add(output);
        }
        Map<String, List<Issue>> byFile = new LinkedHashMap<>();
        for (JsonNode outcome : outcomes) {
            String file = extension(outcome, FILE).replaceAll("^.*[/\\\\]", "");
            List<Issue> issues = new ArrayList<>();
            for (JsonNode issue : outcome.path("issue")) {
                JsonNode where = issue.has("expression") ? issue.path("expression") : issue.path("location");
                String id = extension(issue, MESSAGE_ID);
                issues.add(new Issue(issue.path("severity").asText(), id.isEmpty() ? "(none)" : id,
                        where.path(0).asText(""), issue.path("details").path("text").asText("")));
            }
            byFile.put(file, issues);
        }
        return byFile;
    }

    private static String extension(JsonNode node, String url) {
        for (JsonNode ext : node.path("extension")) {
            if (url.equals(ext.path("url").asText())) {
                return ext.has("valueCode") ? ext.path("valueCode").asText() : ext.path("valueString").asText();
            }
        }
        return "";
    }

    /** The check whose rules {@code issue} is about, or {@link #UNCLAIMED}. {@code body} is the response validated. */
    static String territory(Issue issue, JsonNode body) {
        if (CONTEXT_WRONG.equals(issue.messageId()) && issue.text().contains(CoverageLocationCheck.COVERAGE_INFORMATION_URL)) {
            return CoverageLocationCheck.CHECK_ID;
        }
        String location = URL_FILTER.matcher(issue.location()).replaceAll("").replaceFirst("^CDSHooksResponse\\.?", "");
        int open = location.indexOf(RESOURCE_OPEN);
        int close = open < 0 ? -1 : location.indexOf(RESOURCE_CLOSE, open + RESOURCE_OPEN.length());
        if (close < 0) {
            return location.matches("^cards\\[\\d+]\\.source\\.topic(\\..*)?$") ? UNCLAIMED : ResponseSchemaCheck.CHECK_ID;
        }
        JsonNode node = walk(body, location.substring(0, open + ".resource".length()));
        for (JsonNode step : steps(node, location.substring(close + RESOURCE_CLOSE.length()))) {
            if (CoverageLocationCheck.COVERAGE_INFORMATION_URL.equals(step.path("url").asText())) {
                return CoverageInformationCheck.CHECK_ID;
            }
        }
        return UNCLAIMED;
    }

    private static JsonNode walk(JsonNode from, String path) {
        List<JsonNode> steps = steps(from, path);
        return steps.isEmpty() ? from : steps.get(steps.size() - 1);
    }

    /** Every node visited while following a FHIRPath-like {@code path} from {@code from}, in order. */
    static List<JsonNode> steps(JsonNode from, String path) {
        List<JsonNode> visited = new ArrayList<>();
        JsonNode parent = null;
        String name = null;
        JsonNode node = from;
        for (String segment : path.split("\\.")) {
            if (segment.isEmpty()) {
                continue;
            }
            Matcher ofType = OF_TYPE.matcher(segment);
            if (ofType.matches() && parent != null) {
                // value.ofType(code) is the JSON property valueCode.
                String type = ofType.group(1);
                node = parent.path(name + type.substring(0, 1).toUpperCase(Locale.ROOT) + type.substring(1));
            } else {
                Matcher step = STEP.matcher(segment);
                if (!step.matches()) {
                    break;
                }
                parent = node;
                name = step.group(1);
                node = node.path(name);
                if (step.group(2) != null) {
                    node = node.path(Integer.parseInt(step.group(2)));
                }
            }
            visited.add(node);
        }
        return visited;
    }

    /** The validator's verdict for {@code check}: its worst issue in that check's territory. */
    static Verdict validatorVerdict(String check, List<Issue> issues, JsonNode body) {
        Verdict worst = Verdict.OK;
        for (Issue issue : claimed(check, issues, body)) {
            if (issue.verdict().compareTo(worst) > 0) {
                worst = issue.verdict();
            }
        }
        return worst;
    }

    /** The issues in {@code check}'s territory, information level excluded. */
    static List<Issue> claimed(String check, List<Issue> issues, JsonNode body) {
        return issues.stream()
                .filter(i -> i.verdict() != Verdict.OK)
                .filter(i -> territory(i, body).equals(check))
                .toList();
    }

    /** The workbench's findings from {@code check} on a single 200 hook response carrying {@code body}. */
    static List<Finding> findings(DiagnosticCheck check, String body) {
        return check.evaluate(Fixtures.healthy().hookBody(body).build()).stream()
                .filter(f -> f.checkId().equals(check.id()))
                .toList();
    }

    static Verdict workbenchVerdict(List<Finding> findings) {
        Verdict worst = Verdict.OK;
        for (Finding finding : findings) {
            Verdict v = finding.severity() == Severity.FAIL ? Verdict.FAIL
                    : finding.severity() == Severity.WARN ? Verdict.WARN : Verdict.OK;
            if (v.compareTo(worst) > 0) {
                worst = v;
            }
        }
        return worst;
    }
}
