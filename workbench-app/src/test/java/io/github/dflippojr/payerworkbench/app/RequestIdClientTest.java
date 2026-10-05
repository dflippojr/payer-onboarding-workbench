package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RequestIdClientTest {

    @Test
    void setsTheRequestIdOnceAndKeepsTheRestOfTheRequest() throws Exception {
        HttpClient delegate = mock(HttpClient.class);
        HttpRequest original = HttpRequest.newBuilder(URI.create("https://example.test/cds-services/order-sign"))
                .timeout(Duration.ofSeconds(7))
                .header("Content-Type", "application/json")
                .header("x-request-id", "stale")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();

        new RequestIdClient(delegate, "run-42").send(original, HttpResponse.BodyHandlers.ofString());

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).send(sent.capture(), any());
        HttpRequest request = sent.getValue();
        assertEquals(List.of("run-42"), request.headers().allValues("X-Request-Id"));
        assertEquals(List.of("application/json"), request.headers().allValues("Content-Type"));
        assertEquals("POST", request.method());
        assertEquals(original.uri(), request.uri());
        assertEquals(Optional.of(Duration.ofSeconds(7)), request.timeout());
        assertEquals(original.bodyPublisher().orElseThrow().contentLength(),
                request.bodyPublisher().orElseThrow().contentLength());
    }
}
