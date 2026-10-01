package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ContractsTest {

    private static final String SYNTHETIC_SECRET = "synthetic-secret-value-0123456789";

    private static ConnectionRecord record() {
        return ConnectionRecord.builder()
                .payerId("acme-synthetic")
                .displayName("Acme (synthetic)")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:0/cds-services")
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("http://localhost:0/token")
                .clientId("synthetic-client")
                .credentialRef("acme-client-secret")
                .build();
    }

    @Test
    void redactedConnectionDropsCredentialReferences() {
        RedactedConnection view = RedactedConnection.of(record());

        assertTrue(view.credentialConfigured());
        assertFalse(view.mtlsConfigured());
        assertEquals("synthetic-client", view.clientId());
        assertFalse(view.toString().contains("acme-client-secret"));
    }

    @Test
    void httpExchangeRedactsHeadersAndBodies() {
        HttpExchange exchange = new HttpExchange("POST", "http://localhost:0/token", 200, Duration.ofMillis(12),
                Map.of("Authorization", List.of("Basic " + SYNTHETIC_SECRET)),
                "grant_type=client_credentials&client_secret=" + SYNTHETIC_SECRET,
                Map.of("Content-Type", List.of("application/json")),
                "{\"access_token\":\"" + SYNTHETIC_SECRET + "\",\"token_type\":\"Bearer\"}",
                null);

        assertFalse(exchange.toString().contains(SYNTHETIC_SECRET));
        assertTrue(exchange.responded());
    }

    @Test
    void findingRedactsEvidence() {
        Finding finding = new Finding("token.obtained", Severity.FAIL, "Token request rejected",
                "The token endpoint returned 401.", "client_secret=" + SYNTHETIC_SECRET, "Check the client secret.");

        assertEquals("client_secret=" + Redactor.MASK, finding.evidence());
    }

    @Test
    void runObservationsBuilderSnapshotsCollections() {
        HttpExchange discovery = new HttpExchange("GET", "http://localhost:0/cds-services", HttpExchange.NO_RESPONSE,
                Duration.ofMillis(3), null, null, null, null, "Connection refused");
        RunObservations.Builder builder = RunObservations.builder(RedactedConnection.of(record()))
                .exchange(discovery)
                .discovery(discovery);

        RunObservations first = builder.build();
        builder.exchange(discovery);

        assertEquals(1, first.exchanges().size());
        assertFalse(first.discovery().responded());
        assertEquals(List.of(), first.hookResponses());
        assertThrows(UnsupportedOperationException.class, () -> first.exchanges().add(discovery));
    }

    @Test
    void onboardingRunAndStepResultAreImmutable() {
        List<StepResult> steps = new ArrayList<>();
        steps.add(new StepResult("discovery", Instant.EPOCH, Duration.ZERO, true, "ok", Map.of("services", 2)));
        OnboardingRun run = new OnboardingRun("run-1", "acme-synthetic", Environment.SANDBOX, steps, null);
        steps.clear();

        assertEquals(1, run.steps().size());
        assertEquals(List.of(), run.findings());
        assertThrows(UnsupportedOperationException.class, () -> run.steps().get(0).details().put("x", 1));
    }
}
