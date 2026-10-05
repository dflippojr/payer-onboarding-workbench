package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtObservingClientTest {
    @Test
    void observesOnlyBearerRequestsAndDelegatesSyncAndAsyncWithoutChangingRequests() throws Exception {
        HttpClient delegate = mock(HttpClient.class);
        List<String> observed = new ArrayList<>();
        JwtObservingClient client = new JwtObservingClient(delegate, observed::add);
        HttpRequest bearer = request("Bearer header.payload.signature");
        HttpRequest basic = request("Basic synthetic");
        HttpRequest publicRequest = HttpRequest.newBuilder(URI.create("https://example.test")).build();
        HttpResponse.BodyHandler<String> handler = HttpResponse.BodyHandlers.ofString();
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        var future = CompletableFuture.completedFuture(response);
        HttpResponse.PushPromiseHandler<String> push = (r, p, a) -> { };
        when(delegate.send(bearer, handler)).thenReturn(response);
        when(delegate.sendAsync(bearer, handler)).thenReturn(future);
        when(delegate.sendAsync(bearer, handler, push)).thenReturn(future);
        assertSame(response, client.send(bearer, handler));
        assertSame(future, client.sendAsync(bearer, handler));
        assertSame(future, client.sendAsync(bearer, handler, push));
        client.send(basic, handler);
        client.send(publicRequest, handler);
        assertEquals(List.of("header.payload.signature", "header.payload.signature", "header.payload.signature"), observed);
        verify(delegate).send(basic, handler);
        verify(delegate).send(publicRequest, handler);
    }

    @Test
    void preservesTransportConfiguration() {
        HttpClient delegate = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
        try (delegate) {
            JwtObservingClient client = new JwtObservingClient(delegate, ignored -> { });
            assertEquals(Optional.of(Duration.ofSeconds(3)), client.connectTimeout());
            assertEquals(delegate.cookieHandler(), client.cookieHandler());
            assertEquals(delegate.followRedirects(), client.followRedirects());
            assertEquals(delegate.proxy(), client.proxy());
            assertSame(delegate.sslContext(), client.sslContext());
            assertArrayEquals(delegate.sslParameters().getProtocols(), client.sslParameters().getProtocols());
            assertEquals(delegate.authenticator(), client.authenticator());
            assertEquals(delegate.version(), client.version());
            assertEquals(delegate.executor(), client.executor());
        }
    }

    private static HttpRequest request(String authorization) {
        return HttpRequest.newBuilder(URI.create("https://example.test"))
                .header("Authorization", authorization).build();
    }
}
