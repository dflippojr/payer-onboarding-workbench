package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import tools.jackson.databind.json.JsonMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Where the warm-up's self-request goes, and that its single-use value does not outlive the send (#272). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WarmupRequestPathTest {

    @Autowired
    OnboardingRunner runner;

    @Autowired
    JsonMapper json;

    @Autowired
    ApplicationContext context;

    @ParameterizedTest
    @CsvSource(nullValues = "unset", value = {
        "192.0.2.10, http://192.0.2.10:8080/api/runs",
        "127.0.0.2, http://127.0.0.2:8080/api/runs",
        "::1, http://[::1]:8080/api/runs",
        "[::1], http://[::1]:8080/api/runs",
        "2001:db8::10, http://[2001:db8::10]:8080/api/runs",
        "0:0:0:0:0:0:0:1, http://[0:0:0:0:0:0:0:1]:8080/api/runs",
        "2001:DB8::10, http://[2001:DB8::10]:8080/api/runs",
        "fe80::1%1, http://[fe80::1%1]:8080/api/runs",
        "workbench.example, http://workbench.example:8080/api/runs",
        "Workbench.Example, http://Workbench.Example:8080/api/runs",
        "0.0.0.0, http://127.0.0.1:8080/api/runs",
        "::, http://127.0.0.1:8080/api/runs",
        "[::], http://127.0.0.1:8080/api/runs",
        "0:0:0:0:0:0:0:0, http://127.0.0.1:8080/api/runs",
        "unset, http://127.0.0.1:8080/api/runs",
        "'', http://127.0.0.1:8080/api/runs",
    })
    void theAddressMapsToTheUri(String serverAddress, String expected) {
        assertEquals(expected, FirstRunWarmup.requestPathUri(serverAddress, 8080).toString());
    }

    /** An address written the way a browser writes it gets past {@link HostCheckFilter} rather than a 403. */
    @ParameterizedTest
    @CsvSource({"192.0.2.10", "::1", "2001:db8::10", "workbench.example"})
    void aCanonicalAddressIsOneTheHostCheckAllows(String serverAddress) {
        String host = FirstRunWarmup.requestPathUri(serverAddress, 8080).getHost();
        assertTrue(HostCheckFilter.allowedHosts(serverAddress, "").contains(host), host);
    }

    @Test
    void withdrawClearsOnlyTheValueItIsGiven() {
        InternalRequestToken token = new InternalRequestToken();
        token.withdraw("nothing pending"); // no value pending: nothing to do

        String old = token.issue();
        String newer = token.issue();
        token.withdraw(old);
        token.withdraw(null);
        token.withdraw(newer + "x");
        assertTrue(token.consume(newer), "withdrawing anything else must not clear the newer value");

        String withdrawn = token.issue();
        token.withdraw(withdrawn);
        assertFalse(token.consume(withdrawn));
    }

    @Test
    void aRefusedConnectionWithdrawsTheValue() throws Exception {
        AtomicReference<String> issued = new AtomicReference<>();
        InternalRequestToken token = Mockito.spy(new InternalRequestToken());
        Mockito.doAnswer(call -> {
            issued.set((String) call.callRealMethod());
            return issued.get();
        }).when(token).issue();
        FirstRunWarmup warmup = new FirstRunWarmup(runner, json, context, token);
        try (ServerSocket closed = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            warmup.webServerPort(closed.getLocalPort());
        }

        warmup.warmRequestPath();

        assertNotNull(issued.get(), "the warm-up must have got as far as issuing a value");
        assertFalse(token.consume(issued.get()));
    }

    @Test
    void aConnectionDroppedAfterTheRequestWithdrawsTheValue() throws Exception {
        assertFalse(valueAfterAPeerThatAnswers(null));
    }

    @Test
    void aResponseFromBeforeTheAuditFilterWithdrawsTheValue() throws Exception {
        assertFalse(valueAfterAPeerThatAnswers("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"));
    }

    /** A refusal is an ordinary response, so nothing else would say that the request path was not warmed. */
    @Test
    void aStatusOtherThanTheApps400IsWarned() throws Throwable {
        List<String> warnings = WarmupSelfRequestChecks.warningsDuring(
                () -> valueAfterAPeerThatAnswers("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"));

        assertEquals(1, warnings.size(), warnings::toString);
        assertTrue(warnings.getFirst().contains("403"), warnings::toString);
    }

    /** Whether the value the warm-up really sent to a peer that never consumes it is still usable. */
    private boolean valueAfterAPeerThatAnswers(String response) throws Exception {
        InternalRequestToken token = new InternalRequestToken();
        FirstRunWarmup warmup = new FirstRunWarmup(runner, json, context, token);
        AtomicReference<String> sent = new AtomicReference<>();
        try (ServerSocket peer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread server = Thread.ofPlatform().daemon().start(() -> answerOnce(peer, response, sent));
            warmup.webServerPort(peer.getLocalPort());

            warmup.warmRequestPath();
            server.join(10_000);
        }
        assertNotNull(sent.get(), "the peer must have seen the value");
        return token.consume(sent.get());
    }

    private static void answerOnce(ServerSocket peer, String response, AtomicReference<String> sent) {
        String header = InternalRequestToken.HEADER.toLowerCase(Locale.ROOT) + ":";
        try (Socket socket = peer.accept();
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))) {
            String line = in.readLine();
            while (line != null && !line.isEmpty()) {
                if (line.toLowerCase(Locale.ROOT).startsWith(header)) {
                    sent.set(line.substring(header.length()).strip());
                }
                line = in.readLine();
            }
            if (response != null) {
                socket.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
            }
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
