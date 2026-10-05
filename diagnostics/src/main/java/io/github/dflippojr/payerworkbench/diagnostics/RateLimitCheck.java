package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/** Explains throttled hook calls without retrying them. */
public final class RateLimitCheck implements DiagnosticCheck {
    public static final String CHECK_ID = "perf.rate-limit";

    @Override
    public String id() {
        return CHECK_ID;
    }

    static boolean explains(HookResponse hook) {
        return hook.exchange().status() == 429;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        for (HookResponse hook : obs.hookResponses()) {
            if (!explains(hook)) {
                continue;
            }
            HttpExchange exchange = hook.exchange();
            String retry = Support.header(exchange.responseHeaders(), "Retry-After").orElse("");
            String delay = delay(retry, exchange);
            findings.add(new Finding(CHECK_ID, Severity.FAIL, "Payer rate-limited hook " + hook.serviceId(),
                    "The payer throttled this hook call with HTTP 429. Retry-After: "
                            + (retry.isBlank() ? "(missing)" : retry) + ". " + delay,
                    Support.describe(exchange) + "\nRetry-After: " + (retry.isBlank() ? "(missing)" : retry),
                    "Back off before sending another hook call. " + delay
                            + " Reduce request concurrency and use exponential backoff with jitter; the workbench does not retry."));
        }
        return findings;
    }

    private static String delay(String value, HttpExchange exchange) {
        String retry = value.strip();
        if (retry.matches("[0-9]+")) {
            try {
                return "Wait at least " + Long.parseLong(retry) + " seconds.";
            } catch (NumberFormatException ignored) {
                return "Retry-After exceeds the supported seconds range; confirm the delay with the payer.";
            }
        }
        try {
            var until = ZonedDateTime.parse(retry, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return Support.serverDate(exchange)
                    .map(now -> "Wait at least " + Math.max(0, Duration.between(now, until).getSeconds())
                            + " seconds (until " + until + ", relative to the payer's Date header).")
                    .orElse("Wait until " + until + "; no valid payer Date header was supplied.");
        } catch (DateTimeParseException ignored) {
            return "No usable Retry-After delay was supplied; confirm the retry window with the payer.";
        }
    }
}
