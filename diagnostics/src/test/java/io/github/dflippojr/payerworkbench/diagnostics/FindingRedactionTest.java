package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.ACCESS_TOKEN;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.NOW;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.ORDER_SIGN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.TOKEN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.discovery;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.jwt;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.signatureOf;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.token;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.Redactor;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Proves that secrets the run handled (access token, client secret, private key,
 * JWT signature) never reach a finding, even when the payer echoes them back in
 * the bodies and errors that checks quote as evidence.
 */
class FindingRedactionTest {

    @Test
    void secretsNeverAppearInAnyFinding() throws Exception {
        String clientSecret = "cs" + UUID.randomUUID().toString().replace("-", "");
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String keyBase64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + keyBase64 + "\n-----END PRIVATE KEY-----";
        String assertion = jwt(TOKEN_URL + "/", NOW.plusSeconds(400), NOW.plusSeconds(700));
        // The CDS Hooks client JWT for the hook call, whose claims the run records apart from the token.
        String hookJwt = jwt(ORDER_SIGN_URL + "/", NOW, NOW.plusSeconds(300));

        var run = healthy();
        // Discovery fails and the payer's error page dumps a key.
        run.discovery = discovery(500, "server error; loaded key:\n" + pem);
        // Token request uses client_secret_post and a client_assertion; the payer echoes the secret.
        run.token = token(401,
                "grant_type=client_credentials&client_id=synthetic-client&client_secret=" + clientSecret
                        + "&client_assertion=" + assertion,
                "{\"error\":\"invalid_client\",\"error_description\":\"iat in the future\",\"client_secret\":\""
                        + clientSecret + "\"}",
                NOW);
        run.tokenResponse = new TokenResponseMetadata(false, null, null, List.of(), "invalid_client",
                "rejected client_secret=" + clientSecret);
        // A hook call is rejected and echoes the bearer token; another fails mid-TLS quoting a truncated key.
        run.hooks = new ArrayList<>(List.of(
                orderSign(hook(401, "{\"error\":\"invalid_token\",\"access_token\":\"" + ACCESS_TOKEN
                        + "\",\"detail\":\"Bearer " + ACCESS_TOKEN + " expired\"}", 12_000)),
                // A hook call whose client JWT audience is rejected; the payer echoes the whole JWT.
                orderSign(hook(401, "{\"error\":\"unauthorized\",\"error_description\":\"bad aud in "
                        + hookJwt + "\"}", 300), ORDER_SIGN_URL + "/"),
                new HookResponse("crd-appointment-book", "appointment-book", null,
                        Fixtures.unreachable("POST", Fixtures.DISCOVERY_URL + "/crd-appointment-book",
                                "javax.net.ssl.SSLHandshakeException: bad_certificate; client key "
                                        + pem.substring(0, pem.length() / 2)))));

        List<Finding> findings = new DiagnosticEngine().run(run.build());

        assertTrue(findings.stream().filter(f -> f.severity() == Severity.FAIL).count() >= 4, findings::toString);
        assertTrue(findings.stream().anyMatch(f -> f.checkId().equals(JwtAudienceCheck.CHECK_ID)
                && f.severity() == Severity.FAIL && f.evidence().contains("JWT aud: " + ORDER_SIGN_URL + "/")),
                findings::toString);
        assertTrue(findings.stream().anyMatch(f -> f.evidence() != null && f.evidence().contains(Redactor.MASK)),
                "expected some evidence to show masked material");
        List<String> forbidden = new ArrayList<>(List.of(clientSecret, ACCESS_TOKEN, signatureOf(assertion),
                hookJwt, signatureOf(hookJwt)));
        // Every full line of the key body; the last line may be short, so require 16+ characters.
        for (String line : keyBase64.split("\n")) {
            if (line.length() >= 16) {
                forbidden.add(line);
            }
        }
        for (Finding f : findings) {
            String all = String.join("\n", f.checkId(), f.title(), String.valueOf(f.explanation()),
                    String.valueOf(f.evidence()), String.valueOf(f.suggestedFix()));
            for (String secret : forbidden) {
                assertFalse(all.contains(secret), () -> "secret leaked into finding " + f.checkId() + ": " + f.title());
            }
        }
    }

    /**
     * A payer whose serializer escapes token characters (.NET's System.Text.Json writes {@code +} as
     * {@code +}) echoes the bearer token into a 401 body. The rejection finding quotes that body
     * as evidence and the decoded {@code error_description} in its explanation; neither may keep any
     * part of the token. The first part is all letters, which alone would pass as a prose word.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "<1>\\u002B<2>\\u002B<3>==",
            "<1>\\u002F<2>\\u002F<3>",
            "<1>/<2>\\u002B<3>\\/<4>+<5>\\u002f",
            "<1>\\/<2>+<3>\\/<4>=="})
    void escapedTokenEchoesNeverAppearInTheRejectionFinding(String shape) {
        List<String> parts = new ArrayList<>(List.of("SynthTok"));
        for (int i = 0; i < 4; i++) {
            parts.add(UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        }
        String token = shape;
        for (int i = 0; i < parts.size(); i++) {
            token = token.replace("<" + (i + 1) + ">", parts.get(i));
        }
        var run = healthy();
        run.hooks = new ArrayList<>(List.of(orderSign(hook(401,
                "{\"error\":\"invalid_token\",\"error_description\":\"rejected Bearer " + token + "\"}", 300))));

        Finding rejected = new DiagnosticEngine().run(run.build()).stream()
                .filter(f -> f.checkId().equals(HookRejectedCheck.CHECK_ID)).findFirst().orElseThrow();

        assertTrue(rejected.evidence().contains("rejected Bearer " + Redactor.MASK + "\""), rejected::evidence);
        assertTrue(rejected.explanation().contains("rejected Bearer " + Redactor.MASK), rejected::explanation);
        for (String part : parts) {
            assertFalse(rejected.evidence().contains(part), () -> "'" + part + "' survived in: " + rejected.evidence());
            assertFalse(rejected.explanation().contains(part), () -> "'" + part + "' survived in: " + rejected.explanation());
        }
    }
}
