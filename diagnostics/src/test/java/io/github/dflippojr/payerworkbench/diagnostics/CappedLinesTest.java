package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dflippojr.payerworkbench.core.TextLimit;
import org.junit.jupiter.api.Test;

class CappedLinesTest {

    @Test
    void keepsTheFirstLinesEachCutAndCountsTheRest() {
        CappedLines lines = new CappedLines();
        String quoted = "cards[0].indicator: '" + "w".repeat(100_000) + "'";
        for (int i = 0; i < CappedLines.MAX + 3; i++) {
            lines.add(quoted);
        }

        String joined = lines.join("\n");

        String kept = TextLimit.cut(quoted);
        assertEquals(TextLimit.MAX_CHARS + 1, kept.length());
        assertEquals((kept + "\n").repeat(CappedLines.MAX) + "and 3 more", joined);
    }
}
