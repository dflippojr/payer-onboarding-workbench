package io.github.dflippojr.payerworkbench.mock;

import com.sun.management.UnixOperatingSystemMXBean;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * When the relay's target refuses the connection, the client it accepted must be closed. Before the fix the
 * accepted socket stayed open and each failed connect leaked one descriptor.
 */
class DateShiftingRelayTest {

    private static final int CONNECTS = 100;
    private static final int READ_TIMEOUT_MS = 5_000;
    /** Slack for descriptors the JVM opens for its own use while the test runs. */
    private static final int FD_SLACK = 10;
    private static final String RESPONSE =
            "HTTP/1.1 200 OK\r\nDate: Sat, 03 Oct 2026 00:00:00 GMT\r\nContent-Length: 2\r\n\r\nok";
    /** The same response with its Date moved by the relay's one-hour offset. */
    private static final String SHIFTED_RESPONSE =
            "HTTP/1.1 200 OK\r\nDate: Sat, 03 Oct 2026 01:00:00 GMT\r\nContent-Length: 2\r\n\r\nok";

    @Test
    void theClientSeesTheConnectionEndWhenTheTargetIsDown() throws Exception {
        int target = closedPort();
        try (DateShiftingRelay relay = new DateShiftingRelay(0, target, Duration.ZERO)) {
            long before = openFileDescriptors();
            for (int connect = 1; connect <= CONNECTS; connect++) {
                expectEndOfStream(relay, connect);
            }
            long after = openFileDescriptors();
            if (before >= 0) {
                assertTrue(after <= before + FD_SLACK,
                        "open file descriptors grew from " + before + " to " + after + " over " + CONNECTS
                                + " connects to a closed target");
            }
        }
    }

    @Test
    void theRelayStillRelaysOnceTheTargetIsBackAfterFailedConnects() throws Exception {
        int target = closedPort();
        try (DateShiftingRelay relay = new DateShiftingRelay(0, target, Duration.ofHours(1))) {
            for (int connect = 1; connect <= CONNECTS; connect++) {
                expectEndOfStream(relay, connect);
            }
            try (ServerSocket backend = new ServerSocket(target, 50, InetAddress.getByName("127.0.0.1"))) {
                backend.setSoTimeout(READ_TIMEOUT_MS);
                try (Socket client = new Socket(InetAddress.getByName("127.0.0.1"), relay.port())) {
                    client.setSoTimeout(READ_TIMEOUT_MS);
                    client.getOutputStream().write('x');
                    client.getOutputStream().flush();
                    try (Socket accepted = backend.accept()) {
                        accepted.setSoTimeout(READ_TIMEOUT_MS);
                        assertEquals('x', accepted.getInputStream().read(), "the request reaches the target");
                        accepted.getOutputStream().write(RESPONSE.getBytes(StandardCharsets.ISO_8859_1));
                        accepted.getOutputStream().flush();
                    }
                    String reply = new String(client.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
                    assertEquals(SHIFTED_RESPONSE, reply, "the response comes back through the relay, Date shifted");
                }
            }
        }
    }

    /** One client connects through the relay and must see the connection end, not wait for an answer. */
    private static void expectEndOfStream(DateShiftingRelay relay, int connect) throws IOException {
        try (Socket client = new Socket(InetAddress.getByName("127.0.0.1"), relay.port())) {
            client.setSoTimeout(READ_TIMEOUT_MS);
            try {
                int read = client.getInputStream().read();
                if (read != -1) {
                    fail("connect #" + connect + ": expected end of stream, read byte " + read);
                }
            } catch (SocketTimeoutException e) {
                fail("connect #" + connect + ": no end of stream within " + READ_TIMEOUT_MS
                        + " ms; the relay kept the accepted socket open", e);
            } catch (SocketException e) {
                // Reset by the relay: the connection ended, which is what the client needed to see.
            }
        }
    }

    /** A loopback port with nothing listening on it: bind an ephemeral port, then release it. */
    private static int closedPort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            return probe.getLocalPort();
        }
    }

    /** Open file descriptors of this JVM, or -1 where the platform does not report them. */
    private static long openFileDescriptors() {
        return ManagementFactory.getOperatingSystemMXBean() instanceof UnixOperatingSystemMXBean unix
                ? unix.getOpenFileDescriptorCount()
                : -1;
    }
}
