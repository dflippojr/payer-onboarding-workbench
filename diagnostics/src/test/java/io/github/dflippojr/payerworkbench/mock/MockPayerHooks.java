package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import java.util.List;

/**
 * Calls a mock payer's hook handler directly, with no HTTP server and no authentication,
 * so the diagnostics conformance corpus holds exactly what each mock payer answers.
 * It lives in the mock package because {@link MockPayer#handleHook} is protected.
 */
public final class MockPayerHooks {

    private MockPayerHooks() {
    }

    /** Northwind, Fabrikam and Tailspin with every fault off, reading {@code clock}. Never started. */
    public static List<MockPayer> payers(Clock clock) {
        return List.of(
                NorthwindPayer.builder().clock(clock).build(),
                FabrikamPayer.builder().clock(clock).build(),
                TailspinPayer.builder().clock(clock).build());
    }

    /** The response body {@code payer} sends for {@code request} on {@code service}. */
    public static ObjectNode answer(MockPayer payer, MockPayer.ServiceDefinition service, ObjectNode request) {
        return payer.handleHook(service, request);
    }
}
