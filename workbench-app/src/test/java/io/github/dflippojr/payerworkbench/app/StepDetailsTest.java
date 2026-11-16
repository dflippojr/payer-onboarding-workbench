package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * The runner's own records in a step's details are built field by field (#360, snapshot first); each map must give the
 * same JSON as the record did, so a run is served, stored and reported as before.
 */
class StepDetailsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void buildsTheSameJsonAsEachRecord() {
        ExchangeView exchange = new ExchangeView("POST", "https://payer.example/hook", 200, 12L,
                Map.of("Content-Type", List.of("application/json")), "{}", Map.of(), null, null);
        assertEquals(JSON.writeValueAsString(exchange), JSON.writeValueAsString(StepDetails.of(exchange)));
        assertEquals(JSON.writeValueAsString(List.of(exchange)), JSON.writeValueAsString(StepDetails.exchanges(List.of(exchange))));
        JwtClaims claims = new JwtClaims("client", List.of("https://payer.example/token"), Instant.parse("2026-11-16T10:00:00Z"),
                Instant.parse("2026-11-16T09:55:00.123Z"), "jti-1", "kid-1", "client");
        assertEquals(JSON.writeValueAsString(claims), JSON.writeValueAsString(StepDetails.of(claims)));
        JwtClaims empty = new JwtClaims(null, List.of(), null, null, null, null, null);
        assertEquals(JSON.writeValueAsString(empty), JSON.writeValueAsString(StepDetails.of(empty)));
        for (ConnectionStatus status : ConnectionStatus.values()) {
            RedactedConnection connection = new RedactedConnection("northwind-synthetic", "Northwind", Environment.SANDBOX,
                    "https://payer.example", AuthType.values()[0], "https://payer.example/token", "client", "kid-1",
                    "https://payer.example/jwks", null, List.of("system/*.read"), true, false, "2.1.0", status);
            assertEquals(JSON.writeValueAsString(connection), JSON.writeValueAsString(StepDetails.of(connection)));
        }
    }
}
