package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** The most recent runs, in memory only, oldest dropped first. */
@Component
public class RunStore {

    private final int capacity;
    private final Map<String, OnboardingRun> runs;

    public RunStore(WorkbenchProperties properties) {
        this.capacity = properties.maxRuns();
        this.runs = new LinkedHashMap<>(16, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, OnboardingRun> eldest) {
                return size() > capacity;
            }
        };
    }

    public synchronized void save(OnboardingRun run) {
        runs.put(run.runId(), run);
    }

    public synchronized Optional<OnboardingRun> find(String runId) {
        return Optional.ofNullable(runs.get(runId));
    }
}
