package io.github.dflippojr.payerworkbench.diagnostics;

import java.util.ArrayList;
import java.util.List;

/**
 * Evidence lines that stop growing after the first {@value #MAX}: the rest are only counted, so a
 * response with a million bad entries still makes a finding of a few lines.
 */
final class CappedLines {

    static final int MAX = 20;

    private final List<String> kept = new ArrayList<>();
    private int dropped;

    void add(String line) {
        if (kept.size() < MAX) {
            kept.add(line);
        } else {
            dropped++;
        }
    }

    boolean isEmpty() {
        return kept.isEmpty();
    }

    /** The kept lines joined by {@code separator}, then "and N more" when any were dropped. */
    String join(String separator) {
        return dropped == 0 ? String.join(separator, kept)
                : String.join(separator, kept) + separator + "and " + dropped + " more";
    }
}
