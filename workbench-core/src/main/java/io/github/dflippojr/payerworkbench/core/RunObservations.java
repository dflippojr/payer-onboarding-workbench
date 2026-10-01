package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Everything an onboarding run observed, as input to {@link DiagnosticCheck}s.
 * Immutable, and free of secret material: the connection is a
 * {@link RedactedConnection}, every {@link HttpExchange} is redacted on
 * construction, and the token response carries metadata only.
 *
 * <p>{@code exchanges} is the full ordered log of HTTP traffic. {@code discovery},
 * {@code tokenResponse} and {@code hookResponses} are typed views of the parts
 * checks most often need; callers record those exchanges in {@code exchanges} too.
 *
 * @param connection the connection the run targeted
 * @param exchanges every HTTP exchange, in the order it happened
 * @param discovery the discovery ({@code GET {baseUrl}/cds-services}) exchange;
 *     {@code null} if discovery was not attempted
 * @param tokenResponse token endpoint result; {@code null} if no token was requested
 * @param hookResponses hook calls, in the order they happened
 */
public record RunObservations(
        RedactedConnection connection,
        List<HttpExchange> exchanges,
        HttpExchange discovery,
        TokenResponseMetadata tokenResponse,
        List<HookResponse> hookResponses
) {
    public RunObservations {
        Objects.requireNonNull(connection, "connection");
        exchanges = exchanges == null ? List.of() : List.copyOf(exchanges);
        hookResponses = hookResponses == null ? List.of() : List.copyOf(hookResponses);
    }

    public static Builder builder(RedactedConnection connection) {
        return new Builder(connection);
    }

    /** Collects observations as a run progresses; {@link #build()} snapshots them. */
    public static final class Builder {
        private final RedactedConnection connection;
        private final List<HttpExchange> exchanges = new ArrayList<>();
        private HttpExchange discovery;
        private TokenResponseMetadata tokenResponse;
        private final List<HookResponse> hookResponses = new ArrayList<>();

        private Builder(RedactedConnection connection) {
            this.connection = Objects.requireNonNull(connection, "connection");
        }

        public Builder exchange(HttpExchange exchange) {
            exchanges.add(Objects.requireNonNull(exchange, "exchange"));
            return this;
        }

        public Builder discovery(HttpExchange discovery) {
            this.discovery = discovery;
            return this;
        }

        public Builder tokenResponse(TokenResponseMetadata tokenResponse) {
            this.tokenResponse = tokenResponse;
            return this;
        }

        public Builder hookResponse(HookResponse hookResponse) {
            hookResponses.add(Objects.requireNonNull(hookResponse, "hookResponse"));
            return this;
        }

        public RunObservations build() {
            return new RunObservations(connection, exchanges, discovery, tokenResponse, hookResponses);
        }
    }
}
