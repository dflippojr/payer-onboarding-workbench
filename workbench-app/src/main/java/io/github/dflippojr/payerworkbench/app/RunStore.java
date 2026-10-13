package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The most recent runs, in memory only, oldest dropped first. */
@Component
public class RunStore {

    /** A run and its summary, computed once on save so listing only copies references. */
    private record Entry(OnboardingRun run, RunSummary summary) {
    }

    private final int capacity;
    private final Map<String, Entry> runs;

    public RunStore(WorkbenchProperties properties) {
        this.capacity = properties.maxRuns();
        this.runs = new LinkedHashMap<>(16, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                return size() > capacity;
            }
        };
    }

    public void save(OnboardingRun run) {
        Entry entry = new Entry(run, RunSummary.of(run));
        synchronized (this) {
            runs.put(run.runId(), entry);
        }
    }

    /** Immutable, newest-saved-first snapshot; reads do not affect insertion-order eviction. */
    public synchronized List<RunSummary> list() {
        return runs.values().stream().map(Entry::summary).toList().reversed();
    }

    public synchronized Optional<OnboardingRun> find(String runId) {
        return Optional.ofNullable(runs.get(runId)).map(Entry::run);
    }
}
