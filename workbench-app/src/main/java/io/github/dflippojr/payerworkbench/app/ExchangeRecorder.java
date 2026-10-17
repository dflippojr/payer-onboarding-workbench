package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.Redactor;

import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
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
        ResponseTooLargeException tooLarge = ResponseTooLargeException.in(e.error());
        events.add(new PayerExchange(e.phase(), e.payerId(), e.environment(), e.method(), e.uri(), e.attempt(),
                e.startedAt(), e.elapsed(),
                tooLarge == null ? e.statusCode() : OptionalInt.of(tooLarge.statusCode()),
                HttpHeaders.of(headers, (k, v) -> true),
                tooLarge == null ? e.responseHeaders() : tooLarge.headers(),
                e.requestBody(),
                tooLarge == null ? e.responseBody() : truncatedBody(e.phase(), tooLarge),
                e.error()));
    }

    /**
     * The SDK saw no response for a body cut at the limit, so it recorded none: keep what arrived,
     * with a note. A token body is never kept, as the SDK keeps none, since a cut access token
     * could slip past the redactor. The kept prefix is redacted before the note is added, so a cut
     * that ends inside a secret's value is masked as the end of the text, not as text the note follows.
     */
    private static String truncatedBody(PayerCallPhase phase, ResponseTooLargeException tooLarge) {
        String body = tooLarge.truncatedBody();
        return phase == PayerCallPhase.TOKEN || body == null ? tooLarge.note()
                : Redactor.redact(body) + "\n" + tooLarge.note();
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
