package io.github.dflippojr.payerworkbench.app;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    void theAppAnswersTheWarmUpWithItsOwn400AndNothingIsWarned() throws Throwable {
        // The one at startup first, whose value a second warm-up would otherwise replace.
        awaitSelfRequests(1);
        assertEquals(400, selfRequests().getFirst().metadata().httpStatus());

        int before = selfRequests().size();
        List<String> warnings = warningsDuring(warmup::warmRequestPath);

        awaitSelfRequests(before + 1);
        assertEquals(400, selfRequests().get(before).metadata().httpStatus());
        assertEquals(List.of(), warnings);
    }

    /** The value is a live audit identity: with a proxy as the JVM's default, it still goes only to the app. */
    @Test
    void aDefaultProxyNeverSeesTheValueAndTheAppGetsItsOwnRequest() throws Exception {
        awaitSelfRequests(1);
        int before = selfRequests().size();
        ProxySelector original = ProxySelector.getDefault();
        try (DummyProxy proxy = new DummyProxy()) {
            ProxySelector.setDefault(proxy);
            try {
                warmup.warmRequestPath();
            } finally {
                ProxySelector.setDefault(original);
            }
            assertFalse(proxy.sawTheValue.get(), "the internal value reached the proxy");
        }

        awaitSelfRequests(before + 1);
        assertEquals(400, selfRequests().get(before).metadata().httpStatus());
    }

    /** What {@link FirstRunWarmup} logs at WARN or above while {@code action} runs. */
    static List<String> warningsDuring(Executable action) throws Throwable {
        Logger logger = (Logger) LoggerFactory.getLogger(FirstRunWarmup.class);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        logged.start();
        logger.addAppender(logged);
        try {
            action.execute();
        } finally {
            logger.detachAppender(logged);
        }
        return logged.list.stream()
                .filter(e -> e.getLevel().isGreaterOrEqual(Level.WARN))
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    /** Sends every request to a local socket that notes the internal header and answers 502. */
    private static final class DummyProxy extends ProxySelector implements Closeable {
        final AtomicBoolean sawTheValue = new AtomicBoolean();
        private final ServerSocket socket;

        DummyProxy() throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread.ofPlatform().daemon().name("dummy-proxy").start(this::serve);
        }

        @Override
        public List<Proxy> select(URI uri) {
            return List.of(new Proxy(Proxy.Type.HTTP, socket.getLocalSocketAddress()));
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException e) {
            // A refused proxy would show up as the app not getting its request.
        }

        private void serve() {
            String header = InternalRequestToken.HEADER.toLowerCase(Locale.ROOT) + ":";
            while (!socket.isClosed()) {
                try (Socket client = socket.accept();
                     BufferedReader in = new BufferedReader(
                             new InputStreamReader(client.getInputStream(), StandardCharsets.US_ASCII))) {
                    client.setSoTimeout(5_000);
                    String line = in.readLine();
                    while (line != null && !line.isEmpty()) {
                        sawTheValue.compareAndSet(false, line.toLowerCase(Locale.ROOT).startsWith(header));
                        line = in.readLine();
                    }
                    client.getOutputStream().write(("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                            + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                } catch (IOException e) {
                    // closed by the test, or a client that went away; the loop's condition decides
                }
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
