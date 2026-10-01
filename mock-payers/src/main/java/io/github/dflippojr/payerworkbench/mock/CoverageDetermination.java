package io.github.dflippojr.payerworkbench.mock;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The coverage outcome a mock payer returns for one ordered code, expressed in
 * the codes of the CRD {@code ext-coverage-information} extension.
 *
 * @param covered {@code covered}, {@code not-covered} or {@code conditional}
 * @param paNeeded {@code no-auth}, {@code auth-needed}, {@code satisfied}, {@code performpa} or {@code conditional}
 * @param docNeeded documentation codes such as {@code clinical}; may be empty
 * @param summary one-line card text for a clinician
 */
public record CoverageDetermination(String covered, String paNeeded, List<String> docNeeded, String summary) {

    public CoverageDetermination {
        Objects.requireNonNull(covered, "covered");
        Objects.requireNonNull(paNeeded, "paNeeded");
        docNeeded = docNeeded == null ? List.of() : List.copyOf(docNeeded);
        Objects.requireNonNull(summary, "summary");
    }

    /** Looks {@code code} up in {@code rules}, falling back to {@code otherwise}. */
    static CoverageDetermination lookup(Map<String, CoverageDetermination> rules, String code,
                                        CoverageDetermination otherwise) {
        return code == null ? otherwise : rules.getOrDefault(code, otherwise);
    }
}
