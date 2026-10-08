package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;

/**
 * Micrometer meters for finished runs, exported at {@code /actuator/prometheus}.
 * Every meter is tagged with {@code payer} and {@code environment}; no tag carries a
 * run id, URL or other unbounded value.
 *
 * <ul>
 *   <li>{@value #RUNS}: counter by {@code verdict} and {@code broke_at} (a step id, or {@code none})</li>
 *   <li>{@value #STEP_DURATION}: timer by {@code step} and {@code status} ({@code passed}, {@code failed},
 *       {@code skipped})</li>
 *   <li>{@value #PAYER_REQUEST_DURATION}: timer per HTTP attempt by {@code phase} ({@code discovery},
 *       {@code token}, {@code hook}) and {@code status_class} ({@code 2xx}… or {@code error})</li>
 *   <li>{@value #FINDINGS}: counter by {@code check} and {@code severity}</li>
 * </ul>
 */
@Component
public class RunMetrics {

    static final String RUNS = "workbench.runs";
    static final String STEP_DURATION = "workbench.step.duration";
    static final String PAYER_REQUEST_DURATION = "workbench.payer.request.duration";
    static final String FINDINGS = "workbench.findings";
    static final String NONE = "none";

    private final MeterRegistry registry;

    public RunMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    /** Records one finished run and the HTTP attempts it made. */
    void record(OnboardingRun run, List<PayerExchange> exchanges) {
        Tags common = Tags.of("payer", run.payerId(), "environment", run.environment().name());
        RunVerdict verdict = RunVerdict.of(run);
        Counter.builder(RUNS)
                .description("Finished onboarding runs")
                .tags(common.and("verdict", verdict.status(), "broke_at", verdict.brokeAt() == null ? NONE : verdict.brokeAt()))
                .register(registry)
                .increment();
        for (StepResult step : run.steps()) {
            Timer.builder(STEP_DURATION)
                    .description("Time spent in each onboarding step")
                    .tags(common.and("step", step.stepId(), "status", RunVerdict.stepStatus(step)))
                    .register(registry)
                    .record(step.elapsed());
        }
        for (PayerExchange exchange : exchanges) {
            Timer.builder(PAYER_REQUEST_DURATION)
                    .description("Latency of each HTTP attempt to the payer")
                    .tags(common.and("phase", exchange.phase().name().toLowerCase(Locale.ROOT),
                            "status_class", statusClass(exchange)))
                    .register(registry)
                    .record(exchange.elapsed());
        }
        for (Finding finding : run.findings()) {
            Counter.builder(FINDINGS)
                    .description("Diagnostic findings")
                    .tags(common.and("check", finding.checkId(), "severity", finding.severity().name()))
                    .register(registry)
                    .increment();
        }
    }

    private static String statusClass(PayerExchange exchange) {
        return exchange.statusCode().isPresent() ? exchange.statusCode().getAsInt() / 100 + "xx" : "error";
    }
}
