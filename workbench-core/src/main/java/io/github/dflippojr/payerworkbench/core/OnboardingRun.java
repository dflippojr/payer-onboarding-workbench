package io.github.dflippojr.payerworkbench.core;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.util.List;
import java.util.Objects;

/**
 * A complete onboarding run against one payer connection: the steps taken and
 * the findings the diagnostic checks produced. A run against a mock payer does
 * not establish interoperability with any real payer.
 *
 * @param runId unique identifier of this run
 * @param payerId the payer the run targeted
 * @param environment which of the payer's environments the run targeted
 * @param steps steps in the order they ran
 * @param findings findings from all diagnostic checks
 */
public record OnboardingRun(
        String runId,
        String payerId,
        Environment environment,
        List<StepResult> steps,
        List<Finding> findings
) {
    public OnboardingRun {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(payerId, "payerId");
        Objects.requireNonNull(environment, "environment");
        steps = steps == null ? List.of() : List.copyOf(steps);
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}
