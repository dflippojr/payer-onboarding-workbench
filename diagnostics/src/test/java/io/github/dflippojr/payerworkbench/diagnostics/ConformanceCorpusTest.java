package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.AllowedItem;
import io.github.dflippojr.payerworkbench.diagnostics.ConformanceMapping.AllowlistEntry;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The committed conformance corpus is exactly what {@link ConformanceCorpus} generates from today's
 * mock payers, and the allowlist is small, explained and still true on the workbench's side. These
 * run in every build; {@link HL7ValidatorConformanceTest} adds the validator's side.
 */
class ConformanceCorpusTest {

    @Test
    void committedCorpusMatchesTheMockPayersAndMutations() throws Exception {
        List<ConformanceCorpus.Item> items = ConformanceCorpus.items();
        if (Boolean.getBoolean("conformance.corpus.write")) {
            ConformanceCorpus.write(items);
        }
        TreeSet<String> expected = new TreeSet<>(List.of(ConformanceCorpus.INDEX, ConformanceCorpus.ALLOWLIST));
        items.forEach(item -> expected.add(item.file()));
        TreeSet<String> committed = new TreeSet<>();
        try (var files = Files.list(ConformanceCorpus.DIR)) {
            files.map(f -> f.getFileName().toString()).filter(n -> n.endsWith(".json")).forEach(committed::add);
        }
        assertEquals(expected, committed, "corpus files; regenerate with -Dconformance.corpus.write=true");
        for (ConformanceCorpus.Item item : items) {
            assertEquals(ConformanceCorpus.json(item.body()),
                    lf(Files.readString(ConformanceCorpus.DIR.resolve(item.file()))),
                    item.file() + " drifted from the mock payers; regenerate with -Dconformance.corpus.write=true");
        }
        assertEquals(ConformanceCorpus.json(ConformanceCorpus.index(items)),
                lf(Files.readString(ConformanceCorpus.DIR.resolve(ConformanceCorpus.INDEX))));
    }

    // A Windows checkout with core.autocrlf turns the committed LF files into CRLF; the generator writes LF.
    private static String lf(String text) {
        return text.replace("\r\n", "\n");
    }

    @Test
    void everyMutantChangesItsBase() {
        List<ConformanceCorpus.Item> items = ConformanceCorpus.items();
        for (ConformanceCorpus.Item item : items) {
            if (item.base() != null) {
                assertTrue(!item.body().equals(ConformanceCorpus.find(items, item.base()).body()), item.id());
            }
        }
    }

    @Test
    void allowlistIsSmallExplainedAndTrueOnTheWorkbenchSide() {
        List<ConformanceCorpus.Item> items = ConformanceCorpus.items();
        List<AllowlistEntry> allowlist = ConformanceMapping.allowlist();
        assertTrue(allowlist.size() <= 5, "the allowlist may hold at most 5 entries, has " + allowlist.size());
        Set<String> seen = new HashSet<>();
        for (AllowlistEntry entry : allowlist) {
            assertFalse(entry.reason().isBlank(), entry.id() + " needs a reason");
            assertTrue(entry.issue().matches("https://github\\.com/dflippojr/[\\w.-]+/issues/\\d+"),
                    entry.id() + " needs one issue URL, got " + entry.issue());
            DiagnosticCheck check = ConformanceMapping.CHECKS.stream().filter(c -> c.id().equals(entry.check()))
                    .findFirst().orElseThrow(() -> new AssertionError(entry.id() + ": unknown check " + entry.check()));
            assertFalse(entry.items().isEmpty(), entry.id() + " lists no responses");
            for (AllowedItem allowed : entry.items()) {
                assertTrue(seen.add(allowed.id() + "/" + entry.check()), allowed.id() + " is allowlisted twice");
                assertNotEquals(allowed.workbench(), allowed.validator(), entry.id() + "/" + allowed.id() + " agrees");
                ConformanceCorpus.Item item = ConformanceCorpus.find(items, allowed.id());
                assertEquals(allowed.workbench(), ConformanceMapping.workbenchVerdict(
                                ConformanceMapping.findings(check, item.body().toString())),
                        entry.id() + "/" + allowed.id() + ": the workbench verdict changed; rerun the HL7 validator test");
            }
        }
    }
}
