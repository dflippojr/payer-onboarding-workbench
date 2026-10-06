package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.micrometer.core.instrument.Measurement;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationContext;
import tools.jackson.databind.json.JsonMapper;

import java.net.ServerSocket;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.StreamSupport;

import static io.github.dflippojr.payerworkbench.app.SyntheticPayers.NORTHWIND_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    @Autowired
    JsonMapper json;

    @Autowired
    ApplicationContext context;

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

    @Test
    void requestPathWarmUpToleratesAnUnreachableServer() throws Exception {
        FirstRunWarmup unreachable = new FirstRunWarmup(runner, json, context);
        try (ServerSocket closed = new ServerSocket(0)) {
            unreachable.webServerPort(closed.getLocalPort());
        }
        double before = workbenchMeasurements();

        unreachable.warmRequestPath(); // logs a warning and returns

        assertEquals(before, workbenchMeasurements());
    }

    @Test
    void requestPathWarmUpKeepsTheInterruptWhenInterrupted() throws Exception {
        FirstRunWarmup waiting = new FirstRunWarmup(runner, json, context); // no port is ever announced
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread thread = new Thread(() -> {
            Thread.currentThread().interrupt();
            waiting.warmRequestPath();
            interrupted.set(Thread.currentThread().isInterrupted());
        });
        thread.start();
        thread.join(10_000);

        assertTrue(interrupted.get());
    }

    @Test
    void theManagementServerDoesNotSetThePort() {
        FirstRunWarmup warm = new FirstRunWarmup(runner, json, context);
        WebServerInitializedEvent event = mock(WebServerInitializedEvent.class, RETURNS_DEEP_STUBS);
        when(event.getApplicationContext().getServerNamespace()).thenReturn("management");

        warm.onWebServerInitialized(event);

        verify(event, never()).getWebServer();
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
