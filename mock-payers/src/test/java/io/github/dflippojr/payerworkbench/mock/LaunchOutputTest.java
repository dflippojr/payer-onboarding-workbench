package io.github.dflippojr.payerworkbench.mock;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Characterizes what each payer's {@code launch} prints, so the shared launch steps cannot change it. */
class LaunchOutputTest {

    @FunctionalInterface
    private interface Launcher {
        MockPayer launch(String[] args, PrintStream out) throws IOException;
    }

    @Test
    void northwindWithAFixedSecret() throws IOException {
        assertEquals(List.of(
                        "Northwind Health (synthetic) listening at http://localhost:PORT (CRD 2.2.1)",
                        "  token endpoint: http://localhost:PORT/oauth/token  (client_secret_basic)",
                        "  client id:      demo-client",
                        "  faults:         http://localhost:PORT/admin/faults"),
                printed(NorthwindPayer::launch, "--port", "0", "--client-id", "demo-client", "--client-secret", "s3cret"));
    }

    @Test
    void northwindWithAGeneratedSecretOverTls() throws IOException {
        List<String> lines = printed(NorthwindPayer::launch, "--tls", "--port", "0");
        assertEquals(List.of(
                        "Northwind Health (synthetic) listening at https://127.0.0.1:PORT (CRD 2.2.1)",
                        "  token endpoint: https://127.0.0.1:PORT/oauth/token  (client_secret_basic)",
                        "  client id:      workbench-demo",
                        "  client secret:  SECRET  (generated for this run; pass --client-secret to fix it)",
                        "  faults:         https://127.0.0.1:PORT/admin/faults"),
                lines.stream().map(line -> line.replaceFirst("(client secret: {2})[A-Za-z0-9_-]{32}", "$1SECRET")).toList());
    }

    @Test
    void fabrikamWithAClient() throws IOException {
        assertEquals(List.of(
                        "Fabrikam Benefits (synthetic) listening at http://localhost:PORT (CRD 2.0.1)",
                        "  client iss=demo-client  jwks=http://localhost:1/jwks",
                        "  faults: http://localhost:PORT/admin/faults"),
                printed(FabrikamPayer::launch, "--port=0", "--client", "demo-client=http://localhost:1/jwks",
                        "--public-base-url", "https://crd.fabrikam.example"));
    }

    @Test
    void fabrikamWithNoClients() throws IOException {
        assertEquals(List.of(
                        "Fabrikam Benefits (synthetic) listening at http://localhost:PORT (CRD 2.0.1)",
                        "  no clients registered: every hook call will get 401 (add --client ISS=JWKS_URL)",
                        "  faults: http://localhost:PORT/admin/faults"),
                printed(FabrikamPayer::launch, "--port", "0"));
    }

    @Test
    void tailspinWithAClient() throws IOException {
        assertEquals(List.of(
                        "Tailspin Health Plan (synthetic) listening at http://localhost:PORT (CRD 2.2.1)",
                        "  token endpoint: http://localhost:PORT/oauth/token (private_key_jwt)",
                        "  client id=demo-client jwks=http://localhost:1/jwks",
                        "  faults: http://localhost:PORT/admin/faults"),
                printed(TailspinPayer::launch, "--port", "0", "--client", "demo-client=http://localhost:1/jwks"));
    }

    @Test
    void tailspinWithNoClients() throws IOException {
        assertEquals(List.of(
                        "Tailspin Health Plan (synthetic) listening at http://localhost:PORT (CRD 2.2.1)",
                        "  token endpoint: http://localhost:PORT/oauth/token (private_key_jwt)",
                        "  faults: http://localhost:PORT/admin/faults"),
                printed(TailspinPayer::launch, "--port", "0"));
    }

    @Test
    void clientErrorMessages() {
        assertEquals("--client expects ISS=JWKS_URL, got 'no-equals'",
                clientError(FabrikamPayer::launch, "no-equals"));
        assertEquals("--client expects ISS=JWKS_URL, got '=http://localhost:1/jwks'",
                clientError(FabrikamPayer::launch, "=http://localhost:1/jwks"));
        assertEquals("--client expects ID=JWKS_URL", clientError(TailspinPayer::launch, "no-equals"));
        assertEquals("--client expects ID=JWKS_URL", clientError(TailspinPayer::launch, "=http://localhost:1/jwks"));
    }

    private static List<String> printed(Launcher launcher, String... args) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (MockPayer payer = launcher.launch(args, new PrintStream(output, true, StandardCharsets.UTF_8))) {
            String normalized = payer.baseUrl().replaceFirst(":\\d+$", ":PORT");
            return output.toString(StandardCharsets.UTF_8).lines()
                    .map(line -> line.replace(payer.baseUrl(), normalized))
                    .toList();
        }
    }

    private static String clientError(Launcher launcher, String client) {
        PrintStream sink = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        return assertThrows(IllegalArgumentException.class,
                () -> launcher.launch(new String[] {"--port", "0", "--client", client}, sink)).getMessage();
    }
}
