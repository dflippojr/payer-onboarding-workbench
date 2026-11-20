package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.StepResult;
import java.util.List;
import java.util.Map;

/**
 * The {@link ExchangeView}s a step recorded. A step's details are plain data since #377 ({@link StepResult}), so each
 * exchange is the map of an ExchangeView's components; this reads it back as the view for the tests that check one.
 */
final class StepExchanges {

    private StepExchanges() {
    }

    /** The exchanges in {@code step}'s details, none if it has none. */
    static List<ExchangeView> of(StepResult step) {
        return step.details().get("exchanges") instanceof List<?> list
                ? list.stream().map(e -> view((Map<?, ?>) e)).toList()
                : List.of();
    }

    @SuppressWarnings("unchecked")
    private static ExchangeView view(Map<?, ?> e) {
        return new ExchangeView((String) e.get("method"), (String) e.get("url"), ((Number) e.get("status")).intValue(),
                ((Number) e.get("latencyMs")).longValue(), (Map<String, List<String>>) e.get("requestHeaders"),
                (String) e.get("requestBody"), (Map<String, List<String>>) e.get("responseHeaders"),
                (String) e.get("responseBody"), (String) e.get("transportError"));
    }
}
