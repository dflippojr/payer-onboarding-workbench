package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.payerworkbench.core.HttpExchange;

import java.util.ArrayList;
import java.util.List;

/** Adapts the SDK's redacted HTTP attempt events to workbench observations. */
final class ExchangeRecorder implements PayerExchangeListener {
    private final List<PayerExchange> events = new ArrayList<>();

    @Override
    public void onExchange(PayerExchange exchange) {
        events.add(exchange);
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
