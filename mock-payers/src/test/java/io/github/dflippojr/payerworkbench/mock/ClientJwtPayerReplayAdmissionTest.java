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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The replay-admission and eviction scenarios of {@link ClientJwtReplayAdmissionTest}, run through each payer's own
 * integration and policy rather than a stand-in one: Fabrikam's hook authentication (its issued-at rules and its timer
 * sweep) and Tailspin's token endpoint (its exp cap, its sub and client_id check). Races are forced with the same
 * {@link ClientJwtReplayAdmissionTest.GatedClock}: latches and thread states, never sleeps. The payers are not
 * started, so Fabrikam's timer runs only when a test calls {@link FabrikamPayer#sweepExpiredJtis()}.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class ClientJwtPayerReplayAdmissionTest {

    private static final String CLIENT = "client";
    private static final String HOOK_PATH = "/cds-services/order-sign-crd";
    private static final Instant ISSUED = Instant.parse("2026-10-01T12:00:00Z");
    private static final Instant EXP = ISSUED.plusSeconds(300);
    private static final String ACCEPTED = "accepted";

    /** One payer's client-JWT integration, driven the way its HTTP handler drives it. */
    private abstract static class PayerUnderTest {
        abstract String audience();

        /** Presents the assertion; returns normally if the payer accepted it, throws its HttpError if not. */
        abstract void present(String token);

        abstract String replay(String jti);

        abstract String expired(Instant expiry);

        /** Fabrikam's timer sweep; Tailspin has none. */
        void sweep() {
            throw new UnsupportedOperationException("no timer sweep");
        }
    }

    private static final class Fabrikam extends PayerUnderTest {
        private final FabrikamPayer payer;

        Fabrikam(ClientJwtReplayAdmissionTest.GatedClock clock, TestKeys.JwksServer jwks) {
            payer = FabrikamPayer.builder().clock(clock).publicBaseUrl("https://fabrikam.example")
                    .client(CLIENT, jwks.url()).build();
        }

        @Override
        String audience() {
            return "https://fabrikam.example" + HOOK_PATH;
        }

        @Override
        void present(String token) {
            payer.authenticate(new MockPayer.Request("POST", HOOK_PATH, null,
                    Map.of("authorization", "Bearer " + token), ""));
        }

        @Override
        String replay(String jti) {
            return "jti '" + jti + "' was already used (replay)";
        }

        @Override
        String expired(Instant expiry) {
            return "JWT expired at " + expiry;
        }

        @Override
        void sweep() {
            payer.sweepExpiredJtis();
        }

        int cacheSize() {
            return payer.replayCacheSize();
        }
    }

    private static final class Tailspin extends PayerUnderTest {
        private final TailspinPayer payer;

        Tailspin(ClientJwtReplayAdmissionTest.GatedClock clock, TestKeys.JwksServer jwks) {
            payer = TailspinPayer.builder().clock(clock).publicBaseUrl("https://tailspin.example")
                    .client(CLIENT, jwks.url()).build();
        }

        @Override
        String audience() {
            return "https://tailspin.example" + TailspinPayer.TOKEN_PATH;
        }

        @Override
        void present(String token) {
            String form = "grant_type=client_credentials&client_id=" + CLIENT + "&client_assertion_type="
                    + URLEncoder.encode(TailspinPayer.ASSERTION_TYPE, StandardCharsets.UTF_8)
                    + "&client_assertion=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
            MockPayer.Response response = payer.handleOther(new MockPayer.Request("POST", TailspinPayer.TOKEN_PATH,
                    null, Map.of("content-type", "application/x-www-form-urlencoded"), form));
            assertEquals(200, response.status(), response.body());
        }

        @Override
        String replay(String jti) {
            return "jti was already used (replay)";
        }

        @Override
        String expired(Instant expiry) {
            return "exp must be in the future and no more than 5 minutes ahead";
        }
    }

    /** Whatever a worker thread threw; a thread's own exception never reaches JUnit through join(). */
    private final Queue<Throwable> failures = new ConcurrentLinkedQueue<>();
    private KeyPair key;
    private TestKeys.JwksServer jwks;
    private ClientJwtReplayAdmissionTest.GatedClock clock;

    @BeforeEach
    void setUp() throws Exception {
        key = TestKeys.rsa();
        jwks = new TestKeys.JwksServer().publish("kid", key);
        clock = new ClientJwtReplayAdmissionTest.GatedClock(ISSUED);
    }

    @AfterEach
    void tearDown() {
        jwks.close();
    }

    private PayerUnderTest payer(String name) {
        return name.equals("fabrikam") ? new Fabrikam(clock, jwks) : new Tailspin(clock, jwks);
    }

    /** Each payer with each way it evicts expired jtis: Fabrikam's timer and a request, Tailspin's request only. */
    static Stream<Arguments> evictions() {
        return Stream.of(Arguments.of("fabrikam", "timer sweep"), Arguments.of("fabrikam", "another request"),
                Arguments.of("tailspin", "another request"));
    }

    /** The rival that evicts at {@link #EXP}: the payer's timer sweep, or another request with a new valid jti. */
    private Thread evictor(PayerUnderTest payer, String eviction, Queue<String> otherOutcomes) throws Exception {
        if (eviction.equals("timer sweep")) {
            return guarded(payer::sweep);
        }
        String other = sign(payer, "other", EXP.minusSeconds(10), EXP.plusSeconds(60));
        return guarded(() -> record(payer, other, otherOutcomes));
    }

    private static void assertOtherAccepted(String eviction, Queue<String> otherOutcomes) {
        if (eviction.equals("another request")) {
            assertEquals(List.of(ACCEPTED), List.copyOf(otherOutcomes), "the unrelated assertion is new and valid");
        }
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("evictions")
    void aReplayCheckedBeforeExpIsRefusedWhileTheExpiredJtisAreEvictedAtExp(String name, String eviction)
            throws Exception {
        PayerUnderTest payer = payer(name);
        String token = sign(payer, "used-once", ISSUED, EXP);
        payer.present(token);
        clock.now = EXP;

        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        Queue<String> otherOutcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch replayHeld = new CountDownLatch(1);
        CountDownLatch rivalStarted = new CountDownLatch(1);
        Thread[] rival = new Thread[1];
        Thread replay = guarded(() -> record(payer, token, outcomes));
        clock.holdAfterRead(replay, EXP.minusMillis(1), replayHeld, rivalStarted, () -> rival[0]);
        rival[0] = evictor(payer, eviction, otherOutcomes);

        replay.start();
        replayHeld.await();
        rival[0].start();
        rivalStarted.countDown();
        rival[0].join();
        replay.join();
        assertNoWorkerFailed();
        assertEquals(List.of(payer.replay("used-once")), List.copyOf(outcomes),
                "the assertion was already used and was still valid when the replay was checked");
        assertOtherAccepted(eviction, otherOutcomes);
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("evictions")
    void concurrentReplaysOfOneJtiAreAllRefusedWhileTheExpiredJtisAreEvictedAtExp(String name, String eviction)
            throws Exception {
        PayerUnderTest payer = payer(name);
        String token = sign(payer, "used-once", ISSUED, EXP);
        payer.present(token);
        clock.now = EXP;

        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        Queue<String> otherOutcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch anyHeld = new CountDownLatch(1);
        CountDownLatch rivalStarted = new CountDownLatch(1);
        Thread[] rival = new Thread[1];
        List<Thread> replays = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            Thread replay = guarded(() -> record(payer, token, outcomes));
            clock.holdAfterRead(replay, EXP.minusMillis(1), anyHeld, rivalStarted, () -> rival[0]);
            replays.add(replay);
        }
        rival[0] = evictor(payer, eviction, otherOutcomes);

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
        // A replay decided before the eviction is refused as a replay; one decided after it is judged at the
        // eviction's instant, exp, and refused as expired. Neither may be accepted.
        List<String> refusals = List.of(payer.replay("used-once"), payer.expired(EXP));
        assertTrue(outcomes.stream().allMatch(refusals::contains),
                "every replay was checked while the first use was still valid: " + outcomes);
        assertOtherAccepted(eviction, otherOutcomes);
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("evictions")
    void aJtiEvictedAtExpIsNotAdmittedAgainWhenThePayerClockStepsBack(String name, String eviction)
            throws Exception {
        PayerUnderTest payer = payer(name);
        String token = sign(payer, "used-once", ISSUED, EXP);
        payer.present(token);
        clock.now = EXP;
        Queue<String> otherOutcomes = new ConcurrentLinkedQueue<>();
        Thread evict = evictor(payer, eviction, otherOutcomes);
        evict.start();
        evict.join();
        assertNoWorkerFailed();
        assertOtherAccepted(eviction, otherOutcomes);

        clock.now = EXP.minusMillis(1);
        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        record(payer, token, outcomes);
        assertEquals(List.of(payer.expired(EXP)), List.copyOf(outcomes),
                "decisions never use an instant earlier than one that already evicted this jti");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"fabrikam", "tailspin"})
    void concurrentFirstUsesOfOneJtiAdmitExactlyOne(String name) throws Exception {
        PayerUnderTest payer = payer(name);
        clock.now = ISSUED.plusSeconds(1);
        String token = sign(payer, "fresh", ISSUED, EXP);
        payer.present(sign(payer, "warm-the-jwks-cache", ISSUED, EXP));

        int threads = 8;
        CyclicBarrier start = new CyclicBarrier(threads);
        Queue<String> outcomes = new ConcurrentLinkedQueue<>();
        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            workers.add(guarded(() -> {
                start.await();
                record(payer, token, outcomes);
            }));
        }
        workers.forEach(Thread::start);
        for (Thread worker : workers) {
            worker.join();
        }
        assertNoWorkerFailed();
        assertEquals(threads, outcomes.size(), outcomes::toString);
        assertEquals(1, outcomes.stream().filter(ACCEPTED::equals).count(), outcomes::toString);
        assertEquals(threads - 1, outcomes.stream().filter(payer.replay("fresh")::equals).count(),
                outcomes::toString);
    }

    /** A used jti is a replay up to the last instant before exp, and expired from exp on. */
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"fabrikam", "tailspin"})
    void aReplayIsRefusedAsAReplayBeforeExpAndAsExpiredAtExp(String name) throws Exception {
        PayerUnderTest payer = payer(name);
        String token = sign(payer, "used-once", ISSUED, EXP);
        payer.present(token);
        Queue<String> outcomes = new ConcurrentLinkedQueue<>();

        clock.now = EXP.minusMillis(1);
        record(payer, token, outcomes);
        clock.now = EXP;
        record(payer, token, outcomes);
        assertEquals(List.of(payer.replay("used-once"), payer.expired(EXP)), List.copyOf(outcomes));
    }

    /**
     * Fabrikam accepts an iat up to an hour ahead of its clock, so a jti can stay cached for up to 65 minutes. The timer
     * sweep keeps it until its own exp, and a replay is refused as a replay up to then.
     */
    @Test
    void fabrikamHoldsAJtiIssuedAnHourAheadUntilItsExpThroughTimerSweeps() throws Exception {
        Fabrikam payer = new Fabrikam(clock, jwks);
        Instant issued = ISSUED.plus(Duration.ofHours(1));
        Instant expiry = issued.plusSeconds(300);
        String token = sign(payer, "ahead", issued, expiry);
        payer.present(token);
        Queue<String> outcomes = new ConcurrentLinkedQueue<>();

        clock.now = expiry.minusMillis(1);
        payer.sweep();
        assertEquals(1, payer.cacheSize(), "the assertion is still valid for one more millisecond");
        record(payer, token, outcomes);

        clock.now = expiry;
        payer.sweep();
        assertEquals(0, payer.cacheSize());
        record(payer, token, outcomes);
        assertEquals(List.of(payer.replay("ahead"), payer.expired(expiry)), List.copyOf(outcomes));
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

    /** Presents once and records {@link #ACCEPTED} or the refusal's message. Anything else is a worker failure. */
    private static void record(PayerUnderTest payer, String token, Queue<String> outcomes) {
        try {
            payer.present(token);
            outcomes.add(ACCEPTED);
        } catch (MockPayer.HttpError refused) {
            outcomes.add(refused.getMessage());
        }
    }

    private String sign(PayerUnderTest payer, String jti, Instant issuedAt, Instant expiry) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(CLIENT).subject(CLIENT).audience(payer.audience())
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(expiry)).jwtID(jti).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID("kid").build(), claims);
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }
}
