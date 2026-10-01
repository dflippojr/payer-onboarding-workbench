package io.github.dflippojr.payerworkbench.mock;

import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * The faults currently switched on for one {@link MockPayer}. Thread-safe;
 * changes apply to the next request.
 */
public final class FaultSettings {

    /** Delay used when {@link Fault#SLOW_RESPONSE} is enabled without an explicit duration. */
    public static final Duration DEFAULT_SLOW_RESPONSE_DELAY = Duration.ofSeconds(2);

    private final Set<Fault> enabled = EnumSet.noneOf(Fault.class);
    private Duration slowResponseDelay = DEFAULT_SLOW_RESPONSE_DELAY;

    /** Turns a fault on. {@link Fault#SLOW_RESPONSE} keeps its current delay. */
    public synchronized FaultSettings enable(Fault fault) {
        enabled.add(Objects.requireNonNull(fault, "fault"));
        return this;
    }

    /** Turns {@link Fault#SLOW_RESPONSE} on with the given delay. */
    public synchronized FaultSettings slowResponse(Duration delay) {
        Objects.requireNonNull(delay, "delay");
        if (delay.isNegative()) {
            throw new IllegalArgumentException("delay must not be negative");
        }
        slowResponseDelay = delay;
        enabled.add(Fault.SLOW_RESPONSE);
        return this;
    }

    public synchronized FaultSettings disable(Fault fault) {
        enabled.remove(fault);
        return this;
    }

    /** Turns every fault off and restores the default slow-response delay. */
    public synchronized FaultSettings clear() {
        enabled.clear();
        slowResponseDelay = DEFAULT_SLOW_RESPONSE_DELAY;
        return this;
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
}
