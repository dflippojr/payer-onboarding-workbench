package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TextLimitTest {

    @Test
    void cutsLongTextAndMarksTheCut() {
        String fits = "a".repeat(TextLimit.MAX_CHARS);
        assertSame(fits, TextLimit.cut(fits));
        assertNull(TextLimit.cut(null));
        assertEquals(fits + "…", TextLimit.cut(fits + "b"));
        assertEquals("abc…", TextLimit.cut("abcdef", 3));
    }

    @Test
    void neverSplitsASurrogatePair() {
        // U+1F600 is two chars; a cut through it would leave half a character.
        String text = "ab😀cd";
        assertEquals("ab…", TextLimit.cut(text, 3));
        assertEquals("ab😀…", TextLimit.cut(text, 4));
    }

    @Test
    void aFindingKeepsAtMostAFewKibOfEachTextField() {
        String huge = "x".repeat(1_000_000);
        Finding finding = new Finding("check.id", Severity.FAIL, huge, huge, huge, huge);
        for (String field : new String[] {finding.title(), finding.explanation(), finding.evidence(), finding.suggestedFix()}) {
            assertEquals(TextLimit.MAX_FINDING_CHARS + 1, field.length());
        }
    }

    @Test
    void aFindingRedactsBeforeItCuts() {
        // A secret that straddles the cut must be masked whole, not cut into a prefix the redactor misses.
        String secret = "client_secret=" + "s".repeat(64);
        String evidence = "e".repeat(TextLimit.MAX_FINDING_CHARS - 20) + "\n" + secret;
        Finding finding = new Finding("check.id", Severity.FAIL, "title", null, evidence, null);
        assertFalse(finding.evidence().contains("ssss"), finding.evidence().substring(TextLimit.MAX_FINDING_CHARS - 40));
        assertTrue(finding.evidence().length() <= TextLimit.MAX_FINDING_CHARS + 1);
    }
}
