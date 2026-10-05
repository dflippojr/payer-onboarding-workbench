package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.NOW;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.ORDER_SIGN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.TOKEN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertionBody;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.jwt;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertOnly;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.token;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.tokenError;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class AuthChecksTest {

    private static final String INVALID_CLIENT = "{\"error\":\"invalid_client\",\"error_description\":\"client authentication failed\"}";

    @Nested
    class Token {
        private final AuthTokenCheck check = new AuthTokenCheck();

        @Test
        void issuedTokenPasses() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void unauthorizedClientFails() {
            var run = healthy();
            run.token = token(401, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            run.tokenResponse = tokenError("invalid_client", "client authentication failed");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.title().contains("client not authenticated"));
            assertTrue(f.suggestedFix().contains(Fixtures.CLIENT_ID));
        }

        @Test
        void invalidScopeFails() {
            var run = healthy();
            run.token = token(400, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))),
                    "{\"error\":\"invalid_scope\"}", NOW);
            run.tokenResponse = tokenError("invalid_scope", null);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Token request rejected: invalid_scope", f.title());
            assertTrue(f.evidence().contains("requested scopes: system/*.read"));
        }

        @Test
        void missingExpiresInWarns() {
            var run = healthy();
            run.tokenResponse = new TokenResponseMetadata(true, "Bearer", null, List.of("system/*.read"), null, null);
            assertEquals("Token response lacks expires_in", assertOnly(check.evaluate(run.build()), Severity.WARN).title());
        }

        @Test
        void doesNotApplyWithoutTokenRequest() {
            var run = healthy();
            run.token = null;
            run.tokenResponse = null;
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }

    @Nested
    class JwtAudience {
        private final JwtAudienceCheck check = new JwtAudienceCheck();

        @Test
        void exactAudiencePasses() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void trailingSlashAudienceFailsOn401() {
            var run = healthy();
            run.token = token(401, assertionBody(jwt(TOKEN_URL + "/", NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            run.tokenResponse = tokenError("invalid_client", null);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("aud has a trailing slash"), f::explanation);
            assertTrue(f.suggestedFix().contains("exactly " + TOKEN_URL));
        }

        @Test
        void r4PrefixAudienceFailsOn401() {
            var run = healthy();
            String aud = "https://auth.synthetic-payer.test/r4/oauth2/token";
            run.token = token(401, assertionBody(jwt(aud, NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("aud has the extra path segment /r4"), f::explanation);
        }

        @Test
        void describesMissingSegmentAndHost() {
            assertEquals("aud lacks the path segment /r4 that the URL has",
                    JwtAudienceCheck.difference("https://p.test/cds-services/x", "https://p.test/r4/cds-services/x"));
            assertEquals("aud names host other.test but the request went to p.test",
                    JwtAudienceCheck.difference("https://other.test/token", "https://p.test/token"));
        }

        @Test
        void mismatchAcceptedByPayerIsInfo() {
            var run = healthy();
            run.token = token(200, assertionBody(jwt(TOKEN_URL + "/", NOW, NOW.plusSeconds(300))),
                    Fixtures.TOKEN_OK_BODY, NOW);
            assertOnly(check.evaluate(run.build()), Severity.INFO);
        }

        @Test
        void hookJwtWithTrailingSlashFailsOn401() {
            var run = healthy();
            HookResponse call = orderSign(hook(401, "{\"error\":\"unauthorized\"}", 300), ORDER_SIGN_URL + "/");
            run.hooks = new ArrayList<>(List.of(call));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("CDS Hooks client JWT"), f::explanation);
            assertTrue(f.explanation().contains("aud has a trailing slash"), f::explanation);
            assertTrue(f.evidence().contains("JWT aud: " + ORDER_SIGN_URL + "/"), f::evidence);
            assertTrue(f.suggestedFix().contains("exactly " + ORDER_SIGN_URL));
            assertTrue(JwtAudienceCheck.explains(call));
        }

        @Test
        void hookJwtWithR4PrefixAcceptedIsInfo() {
            var run = healthy();
            String aud = Fixtures.BASE_URL + "/r4/cds-services/crd-order-sign";
            run.hooks = new ArrayList<>(List.of(orderSign(hook(200, Fixtures.resource("order-sign-healthy.json"), 300),
                    aud)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.INFO);
            assertTrue(f.explanation().contains("aud has the extra path segment /r4"), f::explanation);
        }

        @Test
        void exactHookJwtRejectedForAudienceFails() {
            var run = healthy();
            String expected = "https://crd.elsewhere.test/cds-services/crd-order-sign";
            HookResponse call = orderSign(hook(401, "{\"error\":\"unauthorized\",\"error_description\":"
                    + "\"aud must be exactly '" + expected + "', got [" + ORDER_SIGN_URL + "]\"}", 300), ORDER_SIGN_URL);
            run.hooks = new ArrayList<>(List.of(call));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Payer expects a different JWT audience", f.title());
            assertTrue(f.explanation().contains("apparently " + expected), f::explanation);
            assertTrue(f.evidence().contains("URL named in the payer's error: " + expected), f::evidence);
            assertTrue(JwtAudienceCheck.explains(call));
        }

        @Test
        void exactHookJwtRejectedForAnotherReasonIsNotThisCheck() {
            var run = healthy();
            HookResponse call = orderSign(hook(401, "{\"error\":\"unauthorized\",\"error_description\":"
                    + "\"JWT expired\"}", 300), ORDER_SIGN_URL);
            run.hooks = new ArrayList<>(List.of(call));
            // Only the token request's client assertion is verified; the hook call is someone else's finding.
            Finding f = assertOnly(check.evaluate(run.build()), Severity.PASS);
            assertFalse(f.evidence().contains(ORDER_SIGN_URL), f::evidence);
            assertFalse(JwtAudienceCheck.explains(call));
        }

        @Test
        void exactHookJwtAcceptedPasses() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(200, Fixtures.resource("order-sign-healthy.json"), 300),
                    ORDER_SIGN_URL)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.PASS);
            assertTrue(f.evidence().contains(ORDER_SIGN_URL), f::evidence);
        }

        @Test
        void noVisibleJwtDoesNotApply() {
            var run = healthy();
            run.token = token(200, "grant_type=client_credentials", Fixtures.TOKEN_OK_BODY, NOW);
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }

    @Nested
    class ClockSkew {
        private final ClockSkewCheck check = new ClockSkewCheck(Duration.ofSeconds(60));

        @Test
        void agreeingClocksPass() {
            assertOnly(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void futureIatRejectedFails() {
            var run = healthy();
            var iat = NOW.plusSeconds(300);
            run.token = token(400, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))),
                    "{\"error\":\"invalid_client\",\"error_description\":\"iat is in the future\"}", NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("300 seconds after"), f::explanation);
            assertTrue(f.suggestedFix().contains("NTP"));
        }

        @Test
        void expiredJwtRejectedFailsEvenWithoutTimingMessage() {
            var run = healthy();
            var iat = NOW.minusSeconds(900);
            run.token = token(401, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))), INVALID_CLIENT, NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("already expired"), f::explanation);
        }

        @Test
        void expiryWithoutMeasurementIsNotClockSkew() {
            var run = healthy();
            run.token = token(401, "grant_type=client_credentials",
                    "{\"error\":\"invalid_client\",\"error_description\":\"assertion expired\"}", NOW);
            assertTrue(check.evaluate(run.build()).isEmpty());
        }

        @Test
        void skewedButAcceptedWarns() {
            var run = healthy();
            var iat = NOW.plusSeconds(120);
            run.token = token(200, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))), Fixtures.TOKEN_OK_BODY, NOW);
            assertOnly(check.evaluate(run.build()), Severity.WARN);
        }

        @Test
        void unrelatedRejectionIsNotClockSkew() {
            var run = healthy();
            run.token = token(400, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))),
                    "{\"error\":\"invalid_scope\"}", NOW);
            assertTrue(check.evaluate(run.build()).isEmpty());
        }
    }
}
