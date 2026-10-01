package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.NOW;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.TOKEN_URL;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.assertionBody;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.jwt;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.only;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.token;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.tokenError;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
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
            only(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void unauthorizedClientFails() {
            var run = healthy();
            run.token = token(401, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            run.tokenResponse = tokenError("invalid_client", "client authentication failed");
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.title().contains("client not authenticated"));
            assertTrue(f.suggestedFix().contains(Fixtures.CLIENT_ID));
        }

        @Test
        void invalidScopeFails() {
            var run = healthy();
            run.token = token(400, assertionBody(jwt(TOKEN_URL, NOW, NOW.plusSeconds(300))),
                    "{\"error\":\"invalid_scope\"}", NOW);
            run.tokenResponse = tokenError("invalid_scope", null);
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Token request rejected: invalid_scope", f.title());
            assertTrue(f.evidence().contains("requested scopes: system/*.read"));
        }

        @Test
        void missingExpiresInWarns() {
            var run = healthy();
            run.tokenResponse = new TokenResponseMetadata(true, "Bearer", null, List.of("system/*.read"), null, null);
            assertEquals("Token response lacks expires_in", only(check.evaluate(run.build()), Severity.WARN).title());
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
            only(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void trailingSlashAudienceFailsOn401() {
            var run = healthy();
            run.token = token(401, assertionBody(jwt(TOKEN_URL + "/", NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            run.tokenResponse = tokenError("invalid_client", null);
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("aud has a trailing slash"), f::explanation);
            assertTrue(f.suggestedFix().contains("exactly " + TOKEN_URL));
        }

        @Test
        void r4PrefixAudienceFailsOn401() {
            var run = healthy();
            String aud = "https://auth.synthetic-payer.test/r4/oauth2/token";
            run.token = token(401, assertionBody(jwt(aud, NOW, NOW.plusSeconds(300))), INVALID_CLIENT, NOW);
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
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
            only(check.evaluate(run.build()), Severity.INFO);
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
            only(check.evaluate(healthy().build()), Severity.PASS);
        }

        @Test
        void futureIatRejectedFails() {
            var run = healthy();
            var iat = NOW.plusSeconds(300);
            run.token = token(400, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))),
                    "{\"error\":\"invalid_client\",\"error_description\":\"iat is in the future\"}", NOW);
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("300 seconds after"), f::explanation);
            assertTrue(f.suggestedFix().contains("NTP"));
        }

        @Test
        void expiredJwtRejectedFailsEvenWithoutTimingMessage() {
            var run = healthy();
            var iat = NOW.minusSeconds(900);
            run.token = token(401, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))), INVALID_CLIENT, NOW);
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("already expired"), f::explanation);
        }

        @Test
        void timingErrorWithoutMeasurementFails() {
            var run = healthy();
            run.token = token(401, "grant_type=client_credentials",
                    "{\"error\":\"invalid_client\",\"error_description\":\"assertion expired\"}", NOW);
            only(check.evaluate(run.build()), Severity.FAIL);
        }

        @Test
        void skewedButAcceptedWarns() {
            var run = healthy();
            var iat = NOW.plusSeconds(120);
            run.token = token(200, assertionBody(jwt(TOKEN_URL, iat, iat.plusSeconds(300))), Fixtures.TOKEN_OK_BODY, NOW);
            only(check.evaluate(run.build()), Severity.WARN);
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
