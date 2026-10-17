package io.github.dflippojr.payerworkbench.app;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import io.github.dflippojr.payerworkbench.mock.PayerBehaviour;
import io.github.dflippojr.payerworkbench.mock.TailspinPayer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The payer-behaviour matrix (#169): every row of {@code payer-matrix.json} runs end to end through
 * {@link OnboardingRunner}, against one of the named mock payers configured with that row's
 * {@link PayerBehaviour} and registered as a loopback custom endpoint. The run's verdict, first broken
 * step and findings must be what the row's cited spec clause says.
 *
 * <p>A row with a {@code knownDefect} is one the workbench gets wrong today. It must still disagree
 * with the spec, so a fix makes the row fail until its marker is removed and it becomes an ordinary
 * passing row.
 *
 * <p>Keys and secrets are generated per row; nothing leaves loopback.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.custom-endpoints.enabled=true")
class PayerMatrixTest {

    private static final String SAMPLE = "order-sign-hospital-bed";
    private static final String CLIENT_ID = "matrix-client";
    private static final String KEY_ID = "matrix-key-1";
    private static final String ABSENT = "ABSENT";

    @Autowired
    OnboardingRunner runner;

    static Stream<PayerMatrix.Row> rows() {
        return PayerMatrix.load().rows().stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rows")
    void eachPayerBehaviourGetsTheVerdictItsSpecRequires(PayerMatrix.Row row) throws Exception {
        try (Scenario scenario = new Scenario(row)) {
            OnboardingRun run = runner.run(scenario.request());
            Outcome expected = Outcome.expected(row.expect());
            Outcome actual = Outcome.of(run, row.expect(), scenario.otherHostRequests());
            if (row.knownDefect() == null) {
                assertEquals(expected, actual, () -> explain(row, run));
            } else {
                assertNotEquals(expected, actual, () -> row.id() + " now gets its spec verdict, so "
                        + row.knownDefect() + " looks fixed: remove knownDefect from the row.\n" + explain(row, run));
            }
        }
    }

    /** What the matrix compares: the verdict, the first broken step, the named checks and the other host. */
    record Outcome(String verdict, String brokeAt, Map<String, String> findings, boolean otherHostUntouched) {

        static Outcome expected(PayerMatrix.Expect expect) {
            return new Outcome(expect.verdict(), expect.brokeAt(), new TreeMap<>(expect.findings()),
                    expect.otherHostUntouched());
        }

        /** Only the checks the row names are compared, so unrelated findings never decide a row. */
        static Outcome of(OnboardingRun run, PayerMatrix.Expect expect, int otherHostRequests) {
            RunVerdict verdict = RunVerdict.of(run);
            Map<String, String> findings = new TreeMap<>();
            for (String checkId : expect.findings().keySet()) {
                findings.put(checkId, run.findings().stream()
                        .filter(f -> f.checkId().equals(checkId))
                        .map(Finding::severity)
                        .max(Comparator.naturalOrder())
                        .map(Enum::name)
                        .orElse(ABSENT));
            }
            return new Outcome(verdict.status(), verdict.brokeAt(), findings,
                    expect.otherHostUntouched() && otherHostRequests == 0);
        }
    }

    private static String explain(PayerMatrix.Row row, OnboardingRun run) {
        StringBuilder out = new StringBuilder(row.id()).append(" (").append(row.spec()).append(")\n");
        for (StepResult step : run.steps()) {
            out.append("  step ").append(step.stepId()).append(": ").append(RunVerdict.stepStatus(step))
                    .append(" - ").append(step.summary()).append('\n');
        }
        for (Finding finding : run.findings()) {
            out.append("  ").append(finding.severity()).append(' ').append(finding.checkId()).append(": ")
                    .append(finding.title()).append('\n');
        }
        return out.toString();
    }

    /** One row's payer, its keys and, for an other-host redirect, the second server that must stay untouched. */
    private static final class Scenario implements AutoCloseable {

        private static final SecureRandom RANDOM = new SecureRandom();

        private final PayerMatrix.Row row;
        private final List<AutoCloseable> open = new ArrayList<>();
        private final AtomicInteger otherHostRequests = new AtomicInteger();
        private final MockPayer payer;
        private String tokenEndpoint;
        private String credential;

        Scenario(PayerMatrix.Row row) throws Exception {
            this.row = row;
            String otherHost = startOtherHost();
            PayerMatrix.Behaviour behaviour = row.behaviour() == null
                    ? new PayerMatrix.Behaviour(null, null, null, null, null, null, null, null, null, null)
                    : row.behaviour();
            this.payer = switch (row.auth()) {
                case NONE, OAUTH2_CLIENT_CREDENTIALS -> northwind(behaviour.toPayerBehaviour(otherHost, NorthwindPayer.TOKEN_PATH));
                case CDS_HOOKS_JWT -> fabrikam(behaviour.toPayerBehaviour(otherHost, null));
                case OAUTH2_PRIVATE_KEY_JWT -> tailspin(behaviour.toPayerBehaviour(otherHost, TailspinPayer.TOKEN_PATH));
                default -> throw new IllegalArgumentException("The matrix has no payer for " + row.auth());
            };
        }

        /** A loopback server under another host name (127.0.0.1, where the payer is localhost) that counts requests. */
        private String startOtherHost() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                otherHostRequests.incrementAndGet();
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
            });
            server.start();
            open.add(() -> server.stop(0));
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        private MockPayer northwind(PayerBehaviour behaviour) throws IOException {
            String secret = secret();
            NorthwindPayer northwind = NorthwindPayer.builder().client(CLIENT_ID, secret).behaviour(behaviour).build();
            started(northwind);
            if (row.auth() == AuthType.OAUTH2_CLIENT_CREDENTIALS) {
                tokenEndpoint = northwind.tokenEndpoint();
                credential = secret;
            }
            return northwind;
        }

        private MockPayer fabrikam(PayerBehaviour behaviour) throws Exception {
            FabrikamPayer fabrikam = FabrikamPayer.builder().client(CLIENT_ID, signingKey()).behaviour(behaviour).build();
            started(fabrikam);
            return fabrikam;
        }

        private MockPayer tailspin(PayerBehaviour behaviour) throws Exception {
            TailspinPayer tailspin = TailspinPayer.builder().client(CLIENT_ID, signingKey()).behaviour(behaviour).build();
            started(tailspin);
            tokenEndpoint = tailspin.tokenEndpoint();
            return tailspin;
        }

        /** Generates this row's RSA key, publishes its public half and keeps the PEM as the credential. */
        private java.net.URI signingKey() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair key = generator.generateKeyPair();
            JwksServer jwks = new JwksServer(KEY_ID, key.getPublic());
            open.add(jwks);
            credential = PemKeys.toPem("PRIVATE KEY", key.getPrivate().getEncoded());
            return jwks.url();
        }

        private void started(MockPayer payer) throws IOException {
            payer.start(0);
            open.add(payer);
        }

        RunRequest request() {
            boolean signs = row.auth() == AuthType.CDS_HOOKS_JWT || row.auth() == AuthType.OAUTH2_PRIVATE_KEY_JWT;
            return new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                    new RunRequest.CustomEndpoint(payer.baseUrl(), row.auth(),
                            row.auth() == AuthType.NONE ? null : CLIENT_ID, tokenEndpoint, signs ? KEY_ID : null,
                            payer.igVersion(), credential));
        }

        int otherHostRequests() {
            return otherHostRequests.get();
        }

        private static String secret() {
            byte[] bytes = new byte[32];
            RANDOM.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }

        @Override
        public void close() throws Exception {
            for (AutoCloseable c : open.reversed()) {
                c.close();
            }
        }
    }
}
