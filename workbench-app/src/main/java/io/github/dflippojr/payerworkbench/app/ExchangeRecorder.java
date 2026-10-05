package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.payerworkbench.core.HttpExchange;

import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Adapts the SDK's redacted HTTP attempt events to workbench observations.
 *
 * <p>The SDK reports the request it built, before {@link RequestIdClient} added the
 * correlation header on the way out; the recorder adds that header back so each
 * recorded request shows what the payer received.
 */
final class ExchangeRecorder implements PayerExchangeListener {
    private final List<PayerExchange> events = new ArrayList<>();
    private final String requestId;

    /** @param requestId the {@link RequestIdClient#HEADER} value every request carries */
    ExchangeRecorder(String requestId) {
        this.requestId = requestId;
    }

    @Override
    public void onExchange(PayerExchange e) {
        Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(e.requestHeaders().map());
        headers.put(RequestIdClient.HEADER, List.of(requestId));
        events.add(new PayerExchange(e.phase(), e.payerId(), e.environment(), e.method(), e.uri(), e.attempt(),
                e.startedAt(), e.elapsed(), e.statusCode(), HttpHeaders.of(headers, (k, v) -> true),
                e.responseHeaders(), e.requestBody(), e.responseBody(), e.error()));
    }

    /** Every attempt, in the order they were made. */
    List<PayerExchange> events() {
        return List.copyOf(events);
    }

    List<PayerExchange> events(PayerCallPhase phase) {
        return events.stream().filter(e -> e.phase() == phase).toList();
    }

    static HttpExchange adapt(PayerExchange event) {
        return new HttpExchange(event.method(), event.uri().toString(),
                event.statusCode().orElse(HttpExchange.NO_RESPONSE), event.elapsed(),
                event.requestHeaders().map(), event.requestBody(), event.responseHeaders().map(),
                event.responseBody(), transportFailure(event.error()));
    }

    private static String transportFailure(Exception error) {
        if (error == null) {
            return null;
        }
        List<String> causes = new ArrayList<>();
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            causes.add(cause.getClass().getSimpleName() + ": " + cause.getMessage());
        }
        return String.join("; caused by: ", causes);
    }
}
