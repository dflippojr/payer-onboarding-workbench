package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.micrometer.core.instrument.Measurement;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.stream.StreamSupport;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The first-run warm-up (issue #53) runs the real flow but leaves no trace a user could see. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FirstRunWarmupTest {

    @Autowired
    FirstRunWarmup warmup;

    @Autowired
    OnboardingRunner runner;

    @Autowired
    RunStore runs;

    @Autowired
    MeterRegistry registry;

    @Test
    void warmUpRunIsNeitherStoredNorCounted() {
        double metersBefore = workbenchMeasurements();

        OnboardingRun run = runner.warmUp(new RunRequest(NORTHWIND_ID, Environment.SANDBOX,
                FirstRunWarmup.SAMPLE_ID, List.of(), null, null));

        assertTrue(run.steps().stream().allMatch(StepResult::ok), run.steps().toString());
        assertTrue(runs.find(run.runId()).isEmpty(), "a warm-up run must not be in the run history");
        assertEquals(metersBefore, workbenchMeasurements(), "a warm-up run must not be counted in the metrics");
    }

    @Test
    void warmUpDoesNotStoreOrCountAnything() {
        double metersBefore = workbenchMeasurements();

        warmup.warmUp();

        assertEquals(metersBefore, workbenchMeasurements());
    }

    /** Sum of every workbench meter's count, so any recorded run shows up as a change. */
    private double workbenchMeasurements() {
        return registry.getMeters().stream()
                .filter(m -> m.getId().getName().startsWith("workbench."))
                .flatMap(m -> StreamSupport.stream(m.measure().spliterator(), false))
                .mapToDouble(Measurement::getValue)
                .sum();
    }
}
