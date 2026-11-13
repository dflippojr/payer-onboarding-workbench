package io.github.dflippojr.payerworkbench.mock;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Replay admission is one atomic decision per {@code iss|jti}: checking the times, evicting expired entries and
 * recording the jti cannot interleave with another request's eviction or the payer's timer sweep. Each race is forced
 * with latches and thread states, never with sleeps: a validating thread is held right after it reads the payer's
 * clock until the competing eviction has either finished or is waiting its turn.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class ClientJwtReplayAdmissionTest {

    private static final String AUDIENCE = "https://payer.example/token";
    private static final String ISSUER = "client";
    private static final Instant ISSUED = Instant.parse("2026-10-01T12:00:00Z");
    private static final Instant EXP = ISSUED.plusSeconds(300);

    private static final ClientJwtValidator.Policy POLICY = new ClientJwtValidator.Policy(
            Set.of(JWSAlgorithm.RS384), true,
            new ClientJwtValidator.Messages("missing", "not signed", alg -> "alg", iss -> "iss", "kid", "exp",
                    null, exp -> "expired", "jti", jti -> "replay " + jti),
            new ClientJwtValidator.ExpiryCap(Duration.ofMinutes(5), "too far"), null);

    private static final String ACCEPTED = "accepted";

    /** Whatever a worker thread threw; a thread's own exception never reaches JUnit through join(). */
    private final Queue<Throwable> failures = new ConcurrentLinkedQueue<>();
    private KeyPair key;
    private TestKeys.JwksServer jwks;
    private GatedClock clock;
    private ClientJwtValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        key = TestKeys.rsa();
        jwks = new TestKeys.JwksServer().publish("kid", key);
        clock = new GatedClock(ISSUED);
        validator = new ClientJwtValidator(Map.of(ISSUER, jwks.url()),
                message -> new MockPayer.HttpError(401, "rejected", message), clock, POLICY);
    }

    @AfterEach
    void tearDown() {
        jwks.close();
    }

    @Test
    void aReplayCheckedBeforeExpIsRefusedWhileTheTimerSweepEvictsAtExp() throws Exception {
        String token = sign("used-once", ISSUED, EXP);
        assertEquals(ISSUER, admit(token));
        clock.now = EXP;

        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch replayHeld = new CountDownLatch(1);
        CountDownLatch rivalStarted = new CountDownLatch(1);
        Thread[] rival = new Thread[1];
        Thread replay = validating(token, outcomes);
        clock.holdAfterRead(replay, EXP.minusMillis(1), replayHeld, rivalStarted, () -> rival[0]);
        rival[0] = guarded(validator::sweepExpired);

        race(replay, replayHeld, rival[0], rivalStarted);
        assertNoWorkerFailed();
        assertEquals(List.of("replay used-once"), List.copyOf(outcomes),
                "the assertion was already used and was still valid when the replay was checked");
    }

    @Test
    void aReplayCheckedBeforeExpIsRefusedWhileAnotherRequestEvictsAtExp() throws Exception {
        String token = sign("used-once", ISSUED, EXP);
        assertEquals(ISSUER, admit(token));
        clock.now = EXP;
        String other = sign("other", EXP.minusSeconds(10), EXP.plusSeconds(60));

        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        Queue<String> otherOutcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch replayHeld = new CountDownLatch(1);
        CountDownLatch rivalStarted = new CountDownLatch(1);
        Thread[] rival = new Thread[1];
        Thread replay = validating(token, outcomes);
        clock.holdAfterRead(replay, EXP.minusMillis(1), replayHeld, rivalStarted, () -> rival[0]);
        rival[0] = validating(other, otherOutcomes);

        race(replay, replayHeld, rival[0], rivalStarted);
        assertNoWorkerFailed();
        assertEquals(List.of("replay used-once"), List.copyOf(outcomes),
                "the assertion was already used and was still valid when the replay was checked");
        assertEquals(List.of(ACCEPTED), List.copyOf(otherOutcomes), "the unrelated assertion is new and valid");
    }

    @Test
    void concurrentReplaysOfOneJtiAreAllRefusedWhileTheTimerSweepEvictsAtExp() throws Exception {
        String token = sign("used-once", ISSUED, EXP);
        assertEquals(ISSUER, admit(token));
        clock.now = EXP;

        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch anyHeld = new CountDownLatch(1);
        CountDownLatch rivalStarted = new CountDownLatch(1);
        Thread[] rival = new Thread[1];
        List<Thread> replays = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            Thread replay = validating(token, outcomes);
            clock.holdAfterRead(replay, EXP.minusMillis(1), anyHeld, rivalStarted, () -> rival[0]);
            replays.add(replay);
        }
        rival[0] = guarded(validator::sweepExpired);

        replays.forEach(Thread::start);
        anyHeld.await();
        rival[0].start();
        rivalStarted.countDown();
        rival[0].join();
        for (Thread replay : replays) {
            replay.join();
        }
        assertNoWorkerFailed();
        assertEquals(2, outcomes.size(), outcomes::toString);
        // A replay decided before the sweep is refused as a replay; one decided after it is judged at the sweep's
        // instant, exp, and refused as expired. Neither may be accepted.
        assertTrue(outcomes.stream().allMatch(o -> o.equals("replay used-once") || o.equals("expired")),
                "every replay was checked while the first use was still valid: " + outcomes);
    }

    @Test
    void aJtiEvictedAtExpIsNotAdmittedAgainWhenThePayerClockStepsBack() throws Exception {
        String token = sign("used-once", ISSUED, EXP);
        assertEquals(ISSUER, admit(token));
        clock.now = EXP;
        validator.sweepExpired();
        assertEquals(0, validator.replayCacheSize());

        clock.now = EXP.minusMillis(1);
        MockPayer.HttpError refused = org.junit.jupiter.api.Assertions.assertThrows(MockPayer.HttpError.class,
                () -> admit(token));
        assertEquals("expired", refused.getMessage(),
                "decisions never use an instant earlier than one that already evicted this jti");
    }

    @Test
    void concurrentFirstUsesOfOneJtiAdmitExactlyOne() throws Exception {
        clock.now = ISSUED.plusSeconds(1);
        String token = sign("fresh", ISSUED, EXP);
        admit(sign("warm-the-jwks-cache", ISSUED, EXP));

        int threads = 8;
        CyclicBarrier start = new CyclicBarrier(threads);
        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            workers.add(guarded(() -> {
                start.await();
                record(token, outcomes);
            }));
        }
        workers.forEach(Thread::start);
        for (Thread worker : workers) {
            worker.join();
        }
        assertNoWorkerFailed();
        assertEquals(threads, outcomes.size(), outcomes::toString);
        assertEquals(1, outcomes.stream().filter(ACCEPTED::equals).count(), outcomes::toString);
        assertEquals(threads - 1, outcomes.stream().filter("replay fresh"::equals).count(), outcomes::toString);
    }

    /** Starts the replay, waits until it holds a clock reading, then lets the rival evict. */
    private static void race(Thread replay, CountDownLatch replayHeld, Thread rival, CountDownLatch rivalStarted)
            throws InterruptedException {
        replay.start();
        replayHeld.await();
        rival.start();
        rivalStarted.countDown();
        rival.join();
        replay.join();
    }

    /** A worker body that may throw anything; whatever it throws is collected, not lost with the thread. */
    @FunctionalInterface
    private interface Work {
        void run() throws Exception;
    }

    private Thread guarded(Work work) {
        return new Thread(() -> {
            try {
                work.run();
            } catch (Throwable e) {
                failures.add(e);
            }
        });
    }

    private void assertNoWorkerFailed() {
        if (!failures.isEmpty()) {
            AssertionError error = new AssertionError(failures.size() + " worker thread(s) failed");
            failures.forEach(error::addSuppressed);
            throw error;
        }
    }

    /** Validates once and records {@link #ACCEPTED} or the refusal's message. Anything else is a worker failure. */
    private void record(String token, Queue<String> outcomes) {
        try {
            validator.validate(token, AUDIENCE, false, false, (iss, claims) -> { });
            outcomes.add(ACCEPTED);
        } catch (MockPayer.HttpError refused) {
            outcomes.add(refused.getMessage());
        }
    }

    private Thread validating(String token, Queue<String> outcomes) {
        return guarded(() -> record(token, outcomes));
    }

    private String admit(String token) {
        return validator.validate(token, AUDIENCE, false, false, (iss, claims) -> { });
    }

    private String sign(String jti, Instant issuedAt, Instant expiry) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).audience(AUDIENCE)
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(expiry)).jwtID(jti).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID("kid").build(), claims);
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }

    /**
     * Answers {@link #now} to every thread except held ones. A held thread gets its own instant and, on its first
     * read, signals {@code held}, waits for the rival to start, and then waits until the rival has finished or is
     * blocked waiting for the validator: so the rival's eviction either completes inside the held thread's window or
     * is shown to be excluded from it.
     */
    private static final class GatedClock extends Clock {
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
}
