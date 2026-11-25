package io.github.dflippojr.payerworkbench.mock;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/** The hand-rolled clocks that the mock payers' tests share. Each is moved here unchanged. */
final class TestClocks {

    private TestClocks() {
    }

    /**
     * Answers {@link #now} to every thread except held ones. A held thread gets its own instant and, on its first
     * read, signals {@code held}, waits for the rival to start, and then waits until the rival has finished or is
     * blocked waiting for the validator: so the rival's eviction either completes inside the held thread's window or
     * is shown to be excluded from it.
     */
    static final class GatedClock extends Clock {
        volatile Instant now;
        private final Map<Thread, Instant> instants = new ConcurrentHashMap<>();
        private final Map<Thread, Runnable> holds = new ConcurrentHashMap<>();

        GatedClock(Instant now) {
            this.now = now;
        }

        void holdAfterRead(Thread thread, Instant instant, CountDownLatch held, CountDownLatch rivalStarted,
                           java.util.function.Supplier<Thread> rival) {
            instants.put(thread, instant);
            holds.put(thread, () -> {
                held.countDown();
                awaitUninterruptibly(rivalStarted);
                Thread other = rival.get();
                while (true) {
                    Thread.State state = other.getState();
                    if (state == Thread.State.TERMINATED || state == Thread.State.BLOCKED
                            || state == Thread.State.WAITING) {
                        return;
                    }
                    Thread.onSpinWait();
                }
            });
        }

        @Override
        public Instant instant() {
            Thread current = Thread.currentThread();
            Instant answer = instants.getOrDefault(current, now);
            Runnable hold = holds.remove(current);
            if (hold != null) {
                hold.run();
            }
            return answer;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        private static void awaitUninterruptibly(CountDownLatch latch) {
            boolean interrupted = false;
            while (true) {
                try {
                    latch.await();
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** A clock tests can move forward. */
    static final class MutableClock extends Clock {

        private volatile Instant now = Instant.now();

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** A clock whose reads throw, so the next token request fails with an exception the mock does not expect. */
    static final class BrokenClock extends Clock {

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            throw new IllegalStateException("clock is broken");
        }
    }

    /** Answers queued instants in turn and repeats the last one. */
    static final class SteppingClock extends Clock {
        private final ArrayDeque<Instant> next = new ArrayDeque<>();
        private Instant last;

        SteppingClock(Instant start) {
            last = start;
        }

        void then(Instant... instants) {
            next.addAll(java.util.List.of(instants));
        }

        @Override
        public synchronized Instant instant() {
            if (!next.isEmpty()) {
                last = next.poll();
            }
            return last;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    /** A payer clock the test moves by hand. */
    static final class ManualClock extends Clock {
        private volatile Instant now;

        ManualClock(Instant now) {
            this.now = now;
        }

        void set(Instant to) {
            now = to;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
