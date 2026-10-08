package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;

import java.util.LinkedHashMap;
import java.util.Map;

/** Shared verdict policy. Reads only severities and step status; never traverses diagnostic details. */
record RunVerdict(long fails, long warns, long infos, long passes, String brokeAt) {
    static final Map<String, String> STEP_TITLES = Map.of(
            OnboardingRunner.RESOLVE, "Resolve connection",
            OnboardingRunner.DISCOVERY, "Discovery",
            OnboardingRunner.AUTHENTICATE, "Authenticate",
            OnboardingRunner.HOOK_REQUEST, "Send sample hook request",
            OnboardingRunner.PARSE_RESPONSE, "Parse response",
            OnboardingRunner.DIAGNOSTICS, "Run diagnostics");

    static RunVerdict of(OnboardingRun run) {
        long fails = 0;
        long warns = 0;
        long infos = 0;
        long passes = 0;
        for (Finding finding : run.findings()) {
            switch (finding.severity()) {
                case FAIL -> fails++;
                case WARN -> warns++;
                case INFO -> infos++;
                case PASS -> passes++;
            }
        }
        String brokeAt = null;
        for (StepResult step : run.steps()) {
            if (!step.stepId().equals(OnboardingRunner.DIAGNOSTICS) && "failed".equals(stepStatus(step))) {
                brokeAt = step.stepId();
                break;
            }
        }
        return new RunVerdict(fails, warns, infos, passes, brokeAt);
    }

    String status() {
        if (fails > 0 || brokeAt != null) {
            return "FAIL";
        }
        return warns > 0 ? "PASS_WITH_WARNINGS" : "PASS";
    }

    static String stepStatus(StepResult step) {
        return step.details().get("status") instanceof String s ? s : (step.ok() ? "passed" : "failed");
    }

    static String title(String stepId) {
        return STEP_TITLES.getOrDefault(stepId, stepId);
    }

    Map<Severity, Long> counts() {
        Map<Severity, Long> counts = new LinkedHashMap<>();
        counts.put(Severity.FAIL, fails);
        counts.put(Severity.WARN, warns);
        counts.put(Severity.INFO, infos);
        counts.put(Severity.PASS, passes);
        return counts;
    }

    RunReport.Verdict reportVerdict() {
        String brokeAt = this.brokeAt == null ? null : title(this.brokeAt);
        String status = status();
        if ("FAIL".equals(status) && fails > 0) {
            return new RunReport.Verdict("FAIL", "Not ready: " + fails + " failing check" + (fails == 1 ? "" : "s")
                    + (brokeAt == null ? "" : "; the flow broke at " + brokeAt)
                    + ". Onboarding cannot succeed until " + (fails == 1 ? "it is" : "they are") + " fixed.", brokeAt);
        }
        if ("FAIL".equals(status)) {
            return new RunReport.Verdict("FAIL", "Not ready: the flow broke at " + brokeAt + ".", brokeAt);
        }
        if ("PASS_WITH_WARNINGS".equals(status)) {
            return new RunReport.Verdict("PASS_WITH_WARNINGS", "Every step passed, with " + warns + " warning"
                    + (warns == 1 ? "" : "s") + " to review.", null);
        }
        return new RunReport.Verdict("PASS", "Every step passed and no check failed.", null);
    }

}
