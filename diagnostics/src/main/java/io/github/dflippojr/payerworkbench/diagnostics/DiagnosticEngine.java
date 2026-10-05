package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Runs a catalog of {@link DiagnosticCheck}s over the {@link RunObservations} of
 * one onboarding run and returns their findings, most severe first.
 *
 * <p>The default catalog (see {@link #defaultChecks(DiagnosticsConfig)}) covers
 * discovery, authentication, IG version, response shape, latency and TLS. A
 * healthy run produces {@link Severity#PASS} findings for what was verified, so a
 * report can show what worked as well as what did not; checks that do not apply
 * to a run (for example token checks when no token was requested) contribute
 * nothing.
 *
 * <p>Findings are ordered by severity, {@link Severity#FAIL} first, and within a
 * severity by catalog order. A check that throws does not abort the run: the
 * engine records a {@link Severity#WARN} finding under that check's id instead.
 *
 * <p>Instances are immutable and thread-safe as long as the checks are, which the
 * built-in ones are.
 */
public final class DiagnosticEngine {

    private final List<DiagnosticCheck> checks;

    /** An engine with the default catalog and {@link DiagnosticsConfig#defaults()}. */
    public DiagnosticEngine() {
        this(DiagnosticsConfig.defaults());
    }

    /** An engine with the default catalog, tuned by {@code config}. */
    public DiagnosticEngine(DiagnosticsConfig config) {
        this(defaultChecks(config));
    }

    /** An engine that runs exactly {@code checks}, in this order. */
    public DiagnosticEngine(List<? extends DiagnosticCheck> checks) {
        this.checks = List.copyOf(checks);
    }

    /** The built-in catalog, in report order. */
    public static List<DiagnosticCheck> defaultChecks(DiagnosticsConfig config) {
        Objects.requireNonNull(config, "config");
        return List.of(
                new DiscoveryReachableCheck(),
                new DiscoveryServicesCheck(config.requiredHooks()),
                new DiscoveryPrefetchKeysCheck(),
                new AuthTokenCheck(),
                new ClientAssertionCheck(),
                new JwtAudienceCheck(),
                new HookRejectedCheck(),
                new RateLimitCheck(),
                new ClockSkewCheck(config.clockSkewTolerance()),
                new IgVersionCheck(),
                new ResponseSchemaCheck(),
                new CoverageLocationCheck(),
                new CoverageInformationCheck(),
                new LatencyCheck(config.latencyWarn(), config.latencyFail()),
                new TlsHandshakeCheck());
    }

    /** The checks this engine runs, in order. */
    public List<DiagnosticCheck> checks() {
        return checks;
    }

    /**
     * Runs every check over {@code observations}.
     *
     * @return all findings, most severe first; never {@code null}
     */
    public List<Finding> run(RunObservations observations) {
        Objects.requireNonNull(observations, "observations");
        List<Finding> findings = new ArrayList<>();
        for (DiagnosticCheck check : checks) {
            try {
                findings.addAll(check.evaluate(observations));
            } catch (RuntimeException e) {
                findings.add(new Finding(check.id(), Severity.WARN,
                        "Check " + check.id() + " could not run",
                        "The workbench hit an internal error while running this check, so this part of the run "
                                + "was not verified. The other checks are unaffected.",
                        e.getClass().getSimpleName() + ": " + e.getMessage(),
                        "Report this as a workbench bug, attaching the run's evidence."));
            }
        }
        // List.sort is stable, so catalog order is kept within a severity.
        findings.sort(Comparator.comparing(Finding::severity).reversed());
        return List.copyOf(findings);
    }
}
