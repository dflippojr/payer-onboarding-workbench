package io.github.dflippojr.payerworkbench.mock;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A loopback TCP relay in front of a plain-HTTP payer whose clock is offset. It passes requests through
 * untouched and moves each response's {@code Date} header by the offset. The JDK HTTP server always
 * stamps {@code Date} from the system clock and overwrites any value a handler sets, while a real payer
 * with a skewed clock sends its own time there.
 *
 * <p>Responses are framed by {@code Content-Length}; a response without one is copied through to the end
 * of the connection unchanged.
 */
final class DateShiftingRelay implements AutoCloseable {

    private static final Pattern DATE = Pattern.compile("(?im)^Date:[ \\t]*+([^\\r\\n]*+)");
    private static final Pattern CONTENT_LENGTH = Pattern.compile("(?im)^Content-Length:[ \\t]*(\\d+)[ \\t]*\\r?$");
    /** IMF-fixdate (RFC 9110 §5.6.7), which always has a two-digit day. */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ROOT);

    private final ServerSocket listener;
    private final int target;
    private final Duration offset;
    /** Platform threads: the relay's stream copies hold monitors, which would pin virtual threads. */
    private final ExecutorService executor = Executors.newCachedThreadPool(task -> {
        Thread thread = new Thread(task, "date-shifting-relay");
        thread.setDaemon(true);
        return thread;
    });
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();

    /** Listens on {@code port} (0 for ephemeral) on loopback and relays to {@code target} on loopback. */
    DateShiftingRelay(int port, int target, Duration offset) throws IOException {
        this.listener = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
        this.target = target;
        this.offset = offset;
        executor.submit(this::accept);
    }

    int port() {
        return listener.getLocalPort();
    }

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket client = listener.accept();
                Socket server = new Socket(InetAddress.getByName("127.0.0.1"), target);
                sockets.add(client);
                sockets.add(server);
                executor.submit(() -> requests(client, server));
                executor.submit(() -> responses(server, client));
            } catch (IOException e) {
                // Closed while waiting, or the payer went away; either way there is nothing to relay.
            }
        }
    }

    private void requests(Socket client, Socket server) {
        try {
            client.getInputStream().transferTo(server.getOutputStream());
            server.shutdownOutput();
        } catch (IOException e) {
            close(client, server);
        }
    }

    private void responses(Socket server, Socket client) {
        try (server; client) {
            InputStream in = new BufferedInputStream(server.getInputStream());
            OutputStream out = client.getOutputStream();
            String head;
            while ((head = readHead(in)) != null) {
                out.write(shift(head).getBytes(StandardCharsets.ISO_8859_1));
                Matcher length = CONTENT_LENGTH.matcher(head);
                if (!length.find()) {
                    in.transferTo(out);
                    break;
                }
                out.write(in.readNBytes(Integer.parseInt(length.group(1))));
                out.flush();
            }
        } catch (IOException e) {
            // The client or the payer closed the connection.
        } finally {
            sockets.remove(server);
            sockets.remove(client);
        }
    }

    /** The response head up to and including the blank line, or {@code null} at the end of the stream. */
    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        int b;
        while ((b = in.read()) != -1) {
            head.write(b);
            if (b == '\r') {
                matched = matched == 2 ? 3 : 1;
            } else {
                matched = b == '\n' && (matched == 1 || matched == 3) ? matched + 1 : 0;
            }
            if (matched == 4) {
                return head.toString(StandardCharsets.ISO_8859_1);
            }
        }
        if (head.size() > 0) {
            throw new IOException("Response head ended early");
        }
        return null;
    }

    /** {@code head} with its {@code Date} header moved by the offset; unparseable dates are left alone. */
    String shift(String head) {
        Matcher date = DATE.matcher(head);
        if (!date.find()) {
            return head;
        }
        try {
            String value = date.group(1).stripTrailing();
            ZonedDateTime moved = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                    .plus(offset).withZoneSameInstant(ZoneOffset.UTC);
            return head.substring(0, date.start(1)) + HTTP_DATE.format(moved)
                    + head.substring(date.start(1) + value.length());
        } catch (DateTimeParseException e) {
            return head;
        }
    }

    private void close(Socket... pair) {
        for (Socket socket : pair) {
            try {
                socket.close();
            } catch (IOException e) {
                // Already closed.
            }
            sockets.remove(socket);
        }
    }

    @Override
    public void close() {
        try {
            listener.close();
        } catch (IOException e) {
            // Already closed.
        }
        close(sockets.toArray(Socket[]::new));
        executor.shutdownNow();
    }
}
