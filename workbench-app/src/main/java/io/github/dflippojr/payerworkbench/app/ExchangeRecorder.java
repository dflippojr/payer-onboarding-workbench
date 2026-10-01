package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.HttpExchange;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sends the workbench's HTTP requests and keeps a redacted {@link HttpExchange} of
 * each. The raw response is handed back to the caller only (it may hold an access
 * token); what is recorded has been through {@code Redactor}.
 */
final class ExchangeRecorder {

    /** A recorded exchange plus, when the server answered, the unredacted response for the caller. */
    record Sent(HttpExchange exchange, HttpResponse<String> response) {
        boolean ok() {
            return response != null && response.statusCode() / 100 == 2;
        }
    }

    private final HttpClient http;
    private final Duration timeout;
    private final List<HttpExchange> exchanges = new ArrayList<>();

    ExchangeRecorder(HttpClient http, Duration timeout) {
        this.http = http;
        this.timeout = timeout;
    }

    List<HttpExchange> exchanges() {
        return List.copyOf(exchanges);
    }

    Sent get(URI url, Map<String, String> headers) {
        return send("GET", url, headers, null);
    }

    Sent post(URI url, Map<String, String> headers, String body) {
        return send("POST", url, headers, body);
    }

    private Sent send(String method, URI url, Map<String, String> headers, String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(url)
                .timeout(timeout)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        Map<String, List<String>> requestHeaders = new LinkedHashMap<>();
        headers.forEach((name, value) -> {
            builder.header(name, value);
            requestHeaders.put(name, List.of(value));
        });
        long start = System.nanoTime();
        HttpResponse<String> response = null;
        String transportError = null;
        try {
            response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            transportError = "Request timed out after " + timeout.toMillis() + " ms";
        } catch (ConnectException e) {
            transportError = "Connection refused: " + url.getHost() + ":" + url.getPort();
        } catch (IOException e) {
            transportError = e.getClass().getSimpleName() + ": " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            transportError = "Interrupted";
        } catch (IllegalArgumentException e) {
            transportError = "Invalid request: " + e.getMessage();
        }
        Duration latency = Duration.ofNanos(System.nanoTime() - start);
        HttpExchange exchange = new HttpExchange(method, url.toString(),
                response == null ? HttpExchange.NO_RESPONSE : response.statusCode(), latency,
                requestHeaders, body,
                response == null ? Map.of() : response.headers().map(),
                response == null ? null : response.body(),
                transportError);
        exchanges.add(exchange);
        return new Sent(exchange, response);
    }
}
