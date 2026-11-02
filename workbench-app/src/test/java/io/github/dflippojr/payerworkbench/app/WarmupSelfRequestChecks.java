package io.github.dflippojr.payerworkbench.app;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The warm-up's self-request reaches the app on this {@code server.address}: the app answers it with its
 * 400 (a 403 from {@link HostCheckFilter} never gets as far as the audit filter) and nothing is warned.
 */
@Import(WarmupSelfRequestChecks.Capture.class)
abstract class WarmupSelfRequestChecks {

    /** One list per application context, so a cached context's events can't satisfy another's wait. */
    static final class Captured {
        final List<AuditEvent> events = new CopyOnWriteArrayList<>();
    }

    @TestConfiguration
    static class Capture {
        @Bean
        Captured captured() {
            return new Captured();
        }

        @Bean
        @Primary
        AuditLog capturingAuditLog(Captured captured, MeterRegistry registry) {
            return new AuditLog(captured.events::add, Clock.systemUTC(), registry);
        }
    }

    @Autowired
    Captured captured;

    @Autowired
    FirstRunWarmup warmup;

    private List<AuditEvent> selfRequests() {
        return captured.events.stream()
                .filter(e -> e.action().equals("run.completed") && e.actorType().equals("system"))
                .toList();
    }

    private void awaitSelfRequests(int count) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (selfRequests().size() < count) {
            if (System.nanoTime() > deadline) {
                fail("The warm-up's self-request never reached the app as the system actor: "
                        + captured.events.stream().map(AuditEvent::action).toList());
            }
            Thread.sleep(25);
        }
    }

    @Test
    void theAppAnswersTheWarmUpWithItsOwn400AndNothingIsWarned() throws Exception {
        // The one at startup first, whose value a second warm-up would otherwise replace.
        awaitSelfRequests(1);
        assertEquals(400, selfRequests().getFirst().metadata().httpStatus());

        Logger logger = (Logger) LoggerFactory.getLogger(FirstRunWarmup.class);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        logged.start();
        logger.addAppender(logged);
        try {
            warmup.warmRequestPath();
        } finally {
            logger.detachAppender(logged);
        }

        awaitSelfRequests(2);
        assertEquals(400, selfRequests().get(1).metadata().httpStatus());
        assertTrue(logged.list.stream().noneMatch(e -> e.getLevel().isGreaterOrEqual(Level.WARN)),
                () -> "unexpected warning: " + logged.list);
    }
}
