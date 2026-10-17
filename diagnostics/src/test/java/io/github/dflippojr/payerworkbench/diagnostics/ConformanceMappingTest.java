package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.Issue;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.Verdict;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The mapping table from HL7 validator issues to the response checks, on canned validator output. */
class ConformanceMappingTest {

    private static final String SCHEMA = ResponseSchemaCheck.CHECK_ID;
    private static final String CONTENT = CoverageInformationCheck.CHECK_ID;
    private static final String LOCATION = CoverageLocationCheck.CHECK_ID;
    private static final String CI = CoverageLocationCheck.COVERAGE_INFORMATION_URL;

    /** Coverage information on a suggestion's order, as Fabrikam sends it. */
    private static final JsonNode BODY = ConformanceCorpus.read(
            ConformanceCorpus.DIR.resolve(ConformanceCorpus.SUGGESTIONS_BASE + ".json"));
    private static final String ORDER = "CDSHooksResponse.cards[0].suggestions[0].actions[0].resource"
            + "/*DeviceRequest/devreq-hospital-bed*/";

    private static Issue issue(String severity, String id, String location, String text) {
        return new Issue(severity, id, location, text);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "CDSHooksResponse.cards[0]                                       | response.schema",
        "CDSHooksResponse.systemActions                                  | response.schema",
        "CDSHooksResponse                                                | response.schema",
        "CDSHooksResponse.cards[0].source.topic                          | unclaimed",
        "CDSHooksResponse.cards[1].source.topic.code                     | unclaimed",
        "@.extension[0]                                                  | response.coverage-information",
        "@.extension[0].extension[6][url='identifier']                   | response.coverage-information",
        "@.extension[0].extension[1].value.ofType(code)                  | response.coverage-information",
        "@.code.ofType(CodeableConcept).coding[0].system                 | unclaimed",
        "@                                                               | unclaimed",
        "@.extension[9]                                                  | unclaimed",
    })
    void issuesBelongToTheCheckWhoseRulesTheyAreAbout(String location, String expected) {
        Issue issue = issue("error", "Some_Message", location.replace("@", ORDER), "text");
        assertEquals(expected, ConformanceMapping.territory(issue, BODY));
    }

    @Test
    void misplacedCoverageInformationBelongsToTheLocationCheck() {
        String at = ORDER + ".code.ofType(CodeableConcept).coding[0]";
        assertEquals(LOCATION, ConformanceMapping.territory(issue("error", "Extension_EXTP_Context_Wrong", at,
                "The extension " + CI + " v2.2.1 is not allowed to be used at this point"), BODY));
        assertEquals(ConformanceMapping.UNCLAIMED, ConformanceMapping.territory(issue("error",
                "Extension_EXTP_Context_Wrong", at, "The extension http://example.org/other is not allowed"), BODY));
    }

    @Test
    void choiceTypesFollowTheirJsonPropertyNames() {
        List<JsonNode> steps = ConformanceMapping.steps(BODY.path("cards").path(0).path("suggestions").path(0)
                .path("actions").path(0).path("resource"), ".extension[0].extension[1].value.ofType(code)");
        assertEquals("conditional", steps.get(steps.size() - 1).asText());
        assertEquals(CI, steps.get(0).path("url").asText());
    }

    @Test
    void validatorVerdictIsTheWorstClaimedIssueAndIgnoresInformation() {
        List<Issue> issues = List.of(
                issue("information", "Details", ORDER + ".extension[0]", "matching details"),
                issue("warning", "W", ORDER + ".extension[0].extension[2]", "warned"),
                issue("error", "E", "CDSHooksResponse.cards[0].source.topic", "unclaimed error"));
        assertEquals(Verdict.WARN, ConformanceMapping.validatorVerdict(CONTENT, issues, BODY));
        assertEquals(Verdict.OK, ConformanceMapping.validatorVerdict(SCHEMA, issues, BODY));
        assertEquals(1, ConformanceMapping.claimed(CONTENT, issues, BODY).size());
        assertEquals(Verdict.FAIL, issue("fatal", "F", "", "").verdict());
    }

    @Test
    void parsesABundleOrASingleOutcomeKeyedByFileName() {
        JsonNode bundle = ConformanceCorpus.read(Path.of("src/test/resources/fixtures/validator-output.json"));
        Map<String, List<Issue>> byFile = ConformanceMapping.parseOutput(bundle);
        assertEquals(List.of("a.json", "b.json"), List.copyOf(byFile.keySet()));
        assertEquals(List.of(new Issue("error", "Validation_VAL_Profile_Minimum", "CDSHooksResponse.cards[0]",
                "summary: minimum required = 1")), byFile.get("a.json"));
        assertEquals(List.of(new Issue("warning", "(none)", "Bundle.entry[0]", "located only")), byFile.get("b.json"));
        assertEquals(List.of("b.json"), List.copyOf(ConformanceMapping.parseOutput(bundle.path("entry").path(1)
                .path("resource")).keySet()));
    }

    @Test
    void workbenchVerdictIsTheWorstFinding() {
        assertEquals(Verdict.OK, ConformanceMapping.workbenchVerdict(List.of()));
        assertEquals(Verdict.WARN, ConformanceMapping.workbenchVerdict(
                ConformanceMapping.findings(new CoverageInformationCheck(), BODY.toString())));
        assertEquals(Verdict.OK, ConformanceMapping.workbenchVerdict(
                ConformanceMapping.findings(new CoverageLocationCheck(), BODY.toString())));
    }
}
