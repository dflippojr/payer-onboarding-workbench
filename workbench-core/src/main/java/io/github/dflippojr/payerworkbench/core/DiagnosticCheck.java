package io.github.dflippojr.payerworkbench.core;

import java.util.List;

/**
 * One diagnostic rule applied to what an onboarding run observed. Implementations
 * must be side-effect free: they only read {@link RunObservations}.
 */
public interface DiagnosticCheck {

    /** Stable identifier, used as {@link Finding#checkId()}; e.g. {@code discovery.reachable}. */
    String id();

    /**
     * Evaluates the observations and returns zero or more findings. Returns an
     * empty list when the check does not apply to this run.
     */
    List<Finding> evaluate(RunObservations obs);
}
