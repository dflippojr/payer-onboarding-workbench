package io.github.dflippojr.payerworkbench.core;

/** How serious a {@link Finding} is, from least to most severe. */
public enum Severity {
    /** The check ran and the payer behaved as expected. */
    PASS,
    /** Worth knowing, but not a problem. */
    INFO,
    /** Likely to cause trouble or deviates from the spec, but the run could proceed. */
    WARN,
    /** Broken: onboarding cannot succeed until this is fixed. */
    FAIL
}
