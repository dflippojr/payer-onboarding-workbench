package io.github.dflippojr.payerworkbench.mock;

import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The {@code main} entry points, minus the shutdown hook. */
class StandaloneLaunchTest {

    @Test
    void northwindPrintsAGeneratedSecretThatWorks() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (NorthwindPayer payer = NorthwindPayer.launch(new String[] {"--port", "0", "--client-id", "demo-client"},
                new PrintStream(output, true, StandardCharsets.UTF_8))) {
            String printed = output.toString(StandardCharsets.UTF_8);
            assertTrue(printed.contains("listening at " + payer.baseUrl()), printed);
            Matcher secret = Pattern.compile("client secret:\\s+(\\S+)").matcher(printed);
            assertTrue(secret.find(), printed);

            TestKeys.InMemoryCredentials credentials = new TestKeys.InMemoryCredentials();
            credentials.put("secret", secret.group(1));
            ConnectionRecord record = ConnectionRecord.builder()
                    .payerId("northwind-synthetic").environment(Environment.SANDBOX).baseUrl(payer.baseUrl())
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint(payer.tokenEndpoint())
                    .clientId("demo-client").credentialRef("secret").build();
            CdsHookRequest request = CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()),
                    PayerFixture.northwindPrefetch());
            assertEquals(3, new CdsHooksClient(credentials).callHook(record, "order-sign", request).systemActions().size());
        }
    }

    @Test
    void fabrikamRegistersClientsFromTheCommandLine() throws Exception {
        KeyPair key = TestKeys.rsa();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish("demo-key", key);
             FabrikamPayer payer = FabrikamPayer.launch(new String[] {"--port=0", "--client", "demo-client=" + jwks.url()},
                     new PrintStream(output, true, StandardCharsets.UTF_8))) {
            String printed = output.toString(StandardCharsets.UTF_8);
            assertTrue(printed.contains("client iss=demo-client"), printed);

            TestKeys.InMemoryCredentials credentials = new TestKeys.InMemoryCredentials();
            credentials.put("key", TestKeys.privatePem(key));
            ConnectionRecord record = ConnectionRecord.builder()
                    .payerId("fabrikam-synthetic").environment(Environment.SANDBOX).baseUrl(payer.baseUrl())
                    .authType(AuthType.CDS_HOOKS_JWT).clientId("demo-client").keyId("demo-key")
                    .credentialRef("key").build();
            CdsHookRequest request = CdsHookRequest.of(SyntheticData.orderSign(SyntheticData.standardOrders()), null);
            assertEquals(3, new CdsHooksClient(credentials).callHook(record, "order-sign-crd", request)
                    .coverageInformation().size());
        }
    }

    @Test
    void bothLaunchersAcceptTlsFlagBeforeOtherOptions() throws Exception {
        PrintStream sink = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        try (NorthwindPayer northwind = NorthwindPayer.launch(new String[]{"--tls", "--port", "0"}, sink);
             FabrikamPayer fabrikam = FabrikamPayer.launch(new String[]{"--tls", "--port", "0"}, sink)) {
            assertTrue(northwind.baseUrl().startsWith("https://127.0.0.1:"));
            assertTrue(fabrikam.baseUrl().startsWith("https://127.0.0.1:"));
        }
    }

    @Test
    void rejectsMalformedArguments() {
        PrintStream sink = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> NorthwindPayer.launch(new String[] {"port", "0"}, sink));
        assertThrows(IllegalArgumentException.class, () -> NorthwindPayer.launch(new String[] {"--port"}, sink));
        assertThrows(IllegalArgumentException.class, () -> FabrikamPayer.launch(new String[] {"--client", "no-equals"}, sink));
    }
}
