package io.github.dflippojr.payerworkbench.mock;

import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * The faults currently switched on for one {@link MockPayer}. Thread-safe;
 * changes apply to the next request.
 *
 * <p>Every state read for an audit ({@link #snapshot()}, {@link #change(Runnable)}) is taken under
 * the same lock as the mutations, so a before/after pair is never interleaved with another change.
 */
public final class FaultSettings {

    /** Delay used when {@link Fault#SLOW_RESPONSE} is enabled without an explicit duration. */
    public static final Duration DEFAULT_SLOW_RESPONSE_DELAY = Duration.ofSeconds(2);

    /** The enabled faults and the slow-response delay at one moment. */
    public record Snapshot(Set<Fault> enabled, Duration slowResponseDelay) {
        public Snapshot {
            enabled = Collections.unmodifiableSet(enabled.isEmpty() ? EnumSet.noneOf(Fault.class) : EnumSet.copyOf(enabled));
        }
    }

    /** What one mutation did: the state before and after, taken together. */
    public record Change(Snapshot before, Snapshot after) {
        public boolean changed() {
            return !before.equals(after);
        }
    }

    private final Set<Fault> enabled = EnumSet.noneOf(Fault.class);
    private Duration slowResponseDelay = DEFAULT_SLOW_RESPONSE_DELAY;
    private volatile Consumer<Change> listener;
    private final ThreadLocal<Boolean> quiet = ThreadLocal.withInitial(() -> false);

    /**
     * Called after each direct programmatic mutation. Not called inside {@link #change(Runnable)},
     * whose caller records the change itself, so nothing is recorded twice.
     */
    void onProgrammaticChange(Consumer<Change> listener) {
        this.listener = listener;
    }

    /** Turns a fault on. {@link Fault#SLOW_RESPONSE} keeps its current delay. */
    public FaultSettings enable(Fault fault) {
        Objects.requireNonNull(fault, "fault");
        return mutate(() -> enabled.add(fault));
    }

    /** Turns {@link Fault#SLOW_RESPONSE} on with the given delay. */
    public FaultSettings slowResponse(Duration delay) {
        Objects.requireNonNull(delay, "delay");
        if (delay.isNegative()) {
            throw new IllegalArgumentException("delay must not be negative");
        }
        return mutate(() -> {
            slowResponseDelay = delay;
            enabled.add(Fault.SLOW_RESPONSE);
        });
    }

    public FaultSettings disable(Fault fault) {
        return mutate(() -> enabled.remove(fault));
    }

    /** Turns every fault off and restores the default slow-response delay. */
    public FaultSettings clear() {
        return mutate(() -> {
            enabled.clear();
            slowResponseDelay = DEFAULT_SLOW_RESPONSE_DELAY;
        });
    }

    public synchronized boolean isEnabled(Fault fault) {
        return enabled.contains(fault);
    }

    public synchronized Set<Fault> enabled() {
        return Collections.unmodifiableSet(EnumSet.copyOf(enabled));
    }

    public synchronized Duration slowResponseDelay() {
        return slowResponseDelay;
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(enabled, slowResponseDelay);
    }

    /**
     * Runs {@code mutations} as one step under the lock and returns the state before and after. The
     * mutations are not reported to the programmatic listener; the caller records the returned change.
     */
    public Change change(Runnable mutations) {
        boolean wasQuiet = quiet.get();
        quiet.set(true);
        try {
            synchronized (this) {
                Snapshot before = snapshot();
                mutations.run();
                return new Change(before, snapshot());
            }
        } finally {
            quiet.set(wasQuiet);
        }
    }

    private FaultSettings mutate(Runnable mutation) {
        boolean report = !quiet.get();
        Change change;
        synchronized (this) {
            Snapshot before = snapshot();
            mutation.run();
            change = new Change(before, snapshot());
        }
        Consumer<Change> sink = listener;
        if (report && sink != null) {
            sink.accept(change);
        }
        return this;
    }
}
