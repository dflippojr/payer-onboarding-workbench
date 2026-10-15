package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.OutputStream;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The most recent runs, in memory only, oldest dropped first: past {@code workbench.max-runs}
 * runs, or past {@code workbench.max-stored-run-bytes} of them measured as JSON, whichever
 * comes first. The newest run is always kept.
 */
@Component
public class RunStore {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A run, its summary and its size as JSON, computed once on save so listing only copies references. */
    private record Entry(OnboardingRun run, RunSummary summary, long bytes) {
    }

    private final int capacity;
    private final long budget;
    private final Map<String, Entry> runs = new LinkedHashMap<>();
    private long storedBytes;

    public RunStore(WorkbenchProperties properties) {
        this.capacity = properties.maxRuns();
        this.budget = properties.maxStoredRunBytes();
    }

    public void save(OnboardingRun run) {
        Entry entry = new Entry(run, RunSummary.of(run), sizeOf(run));
        synchronized (this) {
            Entry replaced = runs.remove(run.runId());
            runs.put(run.runId(), entry);
            storedBytes += entry.bytes() - (replaced == null ? 0 : replaced.bytes());
            Iterator<Entry> oldest = runs.values().iterator();
            while (runs.size() > 1 && (runs.size() > capacity || storedBytes > budget)) {
                storedBytes -= oldest.next().bytes();
                oldest.remove();
            }
        }
    }

    /** Immutable, newest-saved-first snapshot; reads do not affect insertion-order eviction. */
    public synchronized List<RunSummary> list() {
        return runs.values().stream().map(Entry::summary).toList().reversed();
    }

    public synchronized Optional<OnboardingRun> find(String runId) {
        return Optional.ofNullable(runs.get(runId)).map(Entry::run);
    }

    /** What the remembered runs take together, measured as JSON. */
    synchronized long storedBytes() {
        return storedBytes;
    }

    /** The run's size as JSON in UTF-8, counted without building the text. */
    static long sizeOf(OnboardingRun run) {
        long[] count = {0};
        JSON.writeValue(new OutputStream() {
            @Override
            public void write(int b) {
                count[0]++;
            }

            @Override
            public void write(byte[] b, int off, int len) {
                count[0] += len;
            }
        }, run);
        return count[0];
    }
}
