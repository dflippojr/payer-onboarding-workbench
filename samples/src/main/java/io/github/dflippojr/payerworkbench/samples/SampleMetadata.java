package io.github.dflippojr.payerworkbench.samples;

import java.util.List;
import java.util.Objects;

/**
 * Describes one sample, from its {@code samples/<id>/metadata.json}.
 *
 * @param id stable identifier, also the resource directory name
 * @param title one-line name for lists and the UI
 * @param hook the CDS Hooks hook the request is for, e.g. {@code order-sign}
 * @param demonstrates what the sample is meant to show
 * @param codes the order codes it carries (HCPCS or CPT); may be empty
 * @param expected the outcome to expect from each mock payer
 */
public record SampleMetadata(
        String id,
        String title,
        String hook,
        String demonstrates,
        List<String> codes,
        ExpectedOutcome expected
) {
    public SampleMetadata {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(hook, "hook");
        Objects.requireNonNull(demonstrates, "demonstrates");
        codes = codes == null ? List.of() : List.copyOf(codes);
        Objects.requireNonNull(expected, "expected");
    }

    /**
     * @param payerA what mock payer A, "Northwind Health (synthetic)", should return
     * @param payerB what mock payer B, "Fabrikam Benefits (synthetic)", should return
     */
    public record ExpectedOutcome(String payerA, String payerB) {
        public ExpectedOutcome {
            Objects.requireNonNull(payerA, "payerA");
            Objects.requireNonNull(payerB, "payerB");
        }
    }
}
