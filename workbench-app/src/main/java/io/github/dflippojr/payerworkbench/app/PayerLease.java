package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.FaultSettings;
import io.github.dflippojr.payerworkbench.mock.MockPayer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * One run's turn on a synthetic payer. Faults are switched on at the mock payer for the length of one run, so runs
 * against the same payer take turns and one run's faults never leak into another's. The lease sets the run's faults
 * up, resets them when the run ends, and audits a snapshot of each change.
 */
final class PayerLease {

    /** The fair locks of one runner's synthetic payers, one per payer id. */
    static final class Locks {
        private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();
        private final Duration wait;

        /** @param wait how long a run waits its turn: {@code workbench.request-timeout} */
        Locks(Duration wait) {
            this.wait = wait;
        }

        /**
         * Waits for the payer's turn.
         *
         * @throws PayerBusyException if the payer was still held when the wait ended, or the wait was interrupted:
         *                            no run is started
         */
        PayerLease acquire(String payerId, MockPayer payer) {
            // Fair, so runs get the payer in the order they asked for it. The wait is at most request-timeout, the
            // longest one call of the run ahead can hold the payer, so a queue of slow runs refuses the runs behind
            // it instead of stalling them.
            ReentrantLock lock = locks.computeIfAbsent(payerId, id -> new ReentrantLock(true));
            boolean held;
            try {
                held = lock.tryLock(wait.toNanos(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                held = false;
            }
            if (!held) {
                throw new PayerBusyException(payerId);
            }
            return new PayerLease(payerId, payer, lock);
        }
    }

    private final String payerId;
    private final MockPayer payer;
    private final ReentrantLock lock;

    private PayerLease(String payerId, MockPayer payer, ReentrantLock lock) {
        this.payerId = payerId;
        this.payer = payer;
        this.lock = lock;
    }

    /** Switches on the run's faults and nothing else, and audits the change as one snapshot. */
    void setUp(List<Fault> faults, Duration slowResponseDelay) {
        // One atomic setup snapshot; the setters inside are quiet so nothing is recorded twice.
        FaultSettings.Change setup;
        try {
            setup = payer.faults().change(() -> {
                payer.faults().clear();
                for (Fault fault : faults) {
                    if (fault == Fault.SLOW_RESPONSE) {
                        payer.faults().slowResponse(slowResponseDelay);
                    } else {
                        payer.faults().enable(fault);
                    }
                }
            });
        } catch (RuntimeException e) {
            auditSetupRejected(payerId, payer.faults().snapshot());
            throw e;
        }
        auditFaults("fault.run_setup", payerId, setup);
    }

    /** Clears the payer's faults, audits the reset, and gives the payer to the next run, even if the reset fails. */
    void release() {
        try {
            auditFaults("fault.run_reset", payerId, payer.faults().change(payer.faults()::clear));
        } finally {
            lock.unlock();
        }
    }

    /** A setup that could not be applied changed nothing, so before and after are the same state. */
    private static void auditSetupRejected(String payerId, FaultSettings.Snapshot state) {
        AuditContext scope = AuditContext.current();
        if (scope != null) {
            scope.log.emit(scope, "fault.run_setup", "rejected", "payer", payerId, AuditEvent.Metadata.ofFaults(
                    null, "setup_failed", payerId, new FaultSettings.Change(state, state).audit()));
        }
    }

    private static void auditFaults(String action, String payerId, FaultSettings.Change change) {
        AuditContext scope = AuditContext.current();
        if (scope != null) {
            scope.log.emit(scope, action, "success", "payer", payerId,
                    AuditEvent.Metadata.ofFaults(null, null, payerId, change.audit()));
        }
    }
}
