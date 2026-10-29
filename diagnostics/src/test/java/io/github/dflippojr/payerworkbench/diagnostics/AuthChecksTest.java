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
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.rawJwt;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.token;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.tokenError;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.UUID;
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

        /** RFC 6749 §5.1 makes token_type REQUIRED; a blank one says nothing either (#218). */
        @Test
        void missingTokenTypeWarns() {
            for (String type : Arrays.asList(null, "", "  ")) {
                var run = healthy();
                run.tokenResponse = new TokenResponseMetadata(true, type, 300L, List.of("system/*.read"), null, null);
                Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
                assertEquals("Token response lacks token_type", f.title(), String.valueOf(type));
                assertEquals("An access token was issued, but the response does not say its token_type. RFC 6749 §5.1 "
                        + "makes token_type REQUIRED, and §7.1 says a client must not use an access token whose type it "
                        + "does not understand. The router SDK sends every token as Bearer whatever the response says, "
                        + "so the client cannot tell whether the payer accepts it that way.", f.explanation(),
                        String.valueOf(type));
                assertTrue(f.suggestedFix().startsWith("Ask the payer to return token_type"), f::suggestedFix);
            }
            var run = healthy();
            run.tokenResponse = new TokenResponseMetadata(true, null, 300L, List.of("system/*.read"), null, null);
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.WARN).evidence().contains(", token_type=null, "));
        }

        /** The router SDK implements only Bearer, so a DPoP or mac token it would send as Bearer is not one it can use (#218). */
        @Test
        void tokenTypeOtherThanBearerWarns() {
            for (String type : List.of("DPoP", "mac", "Basic", "Bearer2", "Bearer x")) {
                var run = healthy();
                run.tokenResponse = new TokenResponseMetadata(true, type, 300L, List.of("system/*.read"), null, null);
                Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
                assertEquals("Token response's token_type is not Bearer", f.title(), type);
                assertEquals("An access token was issued with token_type \"" + type + "\". The router SDK implements "
                        + "only Bearer: it sends every token as Authorization: Bearer, so a token bound to another type, "
                        + "such as DPoP or mac, is likely to be refused at the hook call.", f.explanation(), type);
                assertTrue(f.suggestedFix().contains("Bearer"), f::suggestedFix);
            }
        }

        /** The type is case insensitive (RFC 6749 §5.1), and surrounding spaces do not change what the SDK sends. */
        @Test
        void bearerInAnyCaseWithSpacesPasses() {
            for (String type : List.of("Bearer", "bearer", "BEARER", " Bearer ")) {
                var run = healthy();
                run.tokenResponse = new TokenResponseMetadata(true, type, 300L, List.of("system/*.read"), null, null);
                assertOnly(check.evaluate(run.build()), Severity.PASS);
            }
        }

        /**
         * The class-level check for #218: auth.token never PASSes a token_type it cannot vouch for, whatever the
         * payer sends. A value no branch names must not pass by default, so this sweeps seeded random strings over
         * Bearer's letters and separators, plus the awkward ones (blanks, tabs, non-ASCII), and checks every one.
         */
        @Test
        void onlyBearerInAnySpellingPasses() {
            Random random = new Random(218L);
            String alphabet = "BEARbear DPoMAC\t-_é ";
            for (int i = 0; i < 2_000; i++) {
                StringBuilder type = new StringBuilder();
                for (int length = random.nextInt(9); length > 0; length--) {
                    type.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
                String value = type.toString();
                var run = healthy();
                run.tokenResponse = new TokenResponseMetadata(true, value, 300L, List.of("system/*.read"), null, null);
                Finding f = assertOnly(check.evaluate(run.build()));
                boolean bearer = value.strip().equalsIgnoreCase("bearer");
                assertEquals(bearer ? Severity.PASS : Severity.WARN, f.severity(), () -> "token_type \"" + value + "\"");
            }
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
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertEquals("Token response lacks expires_in", f.title());
            assertEquals("An access token was issued, but the response does not say how long it lasts (expires_in, "
                    + "in seconds). Without it a client cannot tell when to fetch a new token, and may keep using "
                    + "an expired one and get 401s mid-session.", f.explanation());
            assertTrue(f.evidence().contains(", expires_in=null, "), f::evidence);
        }

        @Test
        void unusableExpiresInWarnsThatItWasPresent() {
            // A fraction the SDK truncates to 0 or less, or that is beyond a long, is not cached either.
            for (String sent : List.of("\"5 minutes\"", "\"1.5\"", "0", "-300", "true", "{}", "[300]", "[1.5]",
                    "0.5", "0.9E-3", "-1.5", "1.0E19", "1.0E300", "9223372036854775808")) {
                var run = healthy();
                run.tokenResponse = expiresIn(null, sent);
                Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
                assertEquals("Token response lacks expires_in", f.title(), sent);
                assertEquals("An access token was issued, but its expires_in (" + sent + ") was present but not "
                        + "usable: it is not a positive whole number of seconds, and RFC 6749 §5.1 requires a JSON "
                        + "number. The router SDK accepts a numeric-string expires_in, keeps the 24 h cap, and "
                        + "caches nothing else, so it treats this response as having no expires_in and does not "
                        + "cache the token. Without it a client cannot tell when to fetch a new token, and may keep "
                        + "using an expired one and get 401s mid-session.", f.explanation(), sent);
                assertTrue(f.evidence().contains(", expires_in=" + sent + ", "), f::evidence);
                assertTrue(f.suggestedFix().startsWith("Ask the payer to return expires_in as a whole JSON number"));
            }
        }

        /** The router SDK reads a JSON number with Jackson's {@code asLong()}, which truncates a fraction and caches it. */
        @Test
        void fractionalExpiresInWarnsThatTheSdkTruncatesIt() {
            var run = healthy();
            run.tokenResponse = expiresIn(null, "3599.9");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertEquals("Token response lacks expires_in", f.title());
            assertEquals("An access token was issued, but its expires_in (3599.9) was present but not usable: it is "
                    + "not a positive whole number of seconds. The router SDK reads a JSON number with Jackson's "
                    + "asLong(), which truncates it to 3599, so it caches this token for 3599 seconds. A "
                    + "client that rejects a fraction cannot tell when to fetch a new token, and may keep using an "
                    + "expired one and get 401s mid-session.", f.explanation());
            assertTrue(f.evidence().contains(", expires_in=3599.9, "), f::evidence);
            assertTrue(f.suggestedFix().startsWith("Ask the payer to return expires_in as a whole JSON number"));

            run.tokenResponse = expiresIn(null, "1.5E0");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.WARN).explanation()
                    .contains("which truncates it to 1, so it caches this token for 1 seconds."));
        }

        /**
         * Oracle for the WARN's claim about the SDK: {@code expiresInSeconds} from fhir-crd-router#151, copied
         * as it is there, run on the same Jackson and the default {@code ObjectMapper} its token client uses.
         */
        @Test
        void theWarnSaysWhatTheSdkCaches() throws Exception {
            ObjectMapper mapper = new ObjectMapper();
            var run = healthy();
            for (String json : List.of("3599.9", "1.5", "0.5", "0.9e-3", "-1.5", "1e19", "1e300", "86400.5", "86401.5",
                    "9.223372036854775807E18", "9223372036854775808", "0", "-300", "true", "\"1.5\"", "\"abc\"",
                    "[1.5]", "{}")) {
                JsonNode node = mapper.readTree(json);
                long sdk = sdkExpiresInSeconds(node);
                run.tokenResponse = expiresIn(null, node.toString());
                String explanation = assertOnly(check.evaluate(run.build()), Severity.WARN).explanation();
                if (sdk > 0) {
                    assertTrue(explanation.contains("so it caches this token for " + (sdk > AuthTokenCheck.SDK_MAX_CACHE_SECONDS
                            ? "at most 24 h (86400 seconds)." : sdk + " seconds.")), json + ": " + explanation);
                } else {
                    assertTrue(explanation.contains("does not cache the token"), json + ": " + explanation);
                }
            }
        }

        private static long sdkExpiresInSeconds(JsonNode expiresIn) {
            if (expiresIn == null) {
                return 0;
            }
            if (expiresIn.canConvertToLong()) {
                return expiresIn.asLong();
            }
            if (expiresIn.isTextual()) {
                try {
                    return Long.parseLong(expiresIn.textValue().trim());
                } catch (NumberFormatException e) {
                    // "abc", "", "1.5", "1e3" or out of range: not cached, as for any other unusable value.
                }
            }
            return 0;
        }

        @Test
        void fractionalExpiresInAbove24HoursWarnsWithTheCap() {
            var run = healthy();
            run.tokenResponse = expiresIn(null, "86400.5");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.WARN).explanation()
                    .contains("which truncates it to 86400, so it caches this token for 86400 seconds."));

            run.tokenResponse = expiresIn(null, "86401.5");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.WARN).explanation()
                    .contains("which truncates it to 86401, so it caches this token for at most 24 h (86400 "
                            + "seconds)."));

            // Jackson's canConvertToLong() admits a double up to (double) Long.MAX_VALUE, and asLong() saturates.
            run.tokenResponse = expiresIn(null, "9.223372036854776E18");
            assertTrue(assertOnly(check.evaluate(run.build()), Severity.WARN).explanation()
                    .contains("which truncates it to 9223372036854775807, so it caches this token for at "
                            + "most 24 h (86400 seconds)."));
        }

        @Test
        void numberExpiresInPassesWithoutANote() {
            Finding f = assertOnly(check.evaluate(healthy().build()), Severity.PASS);
            assertEquals("Access token obtained", f.title());
            assertEquals("The token endpoint issued an access token with an expiry of 300 seconds.", f.explanation());
            assertTrue(f.evidence().contains(", expires_in=300, "), f::evidence);
        }

        @Test
        void numericStringExpiresInPassesWithTheSdkRule() {
            var run = healthy();
            run.tokenResponse = expiresIn(300L, "\"300\"");
            Finding f = assertOnly(check.evaluate(run.build()), Severity.PASS);
            assertEquals("The token endpoint issued an access token with an expiry of 300 seconds. Its expires_in "
                    + "was sent as a JSON string (\"300\"), where RFC 6749 §5.1 requires a JSON number. The router "
                    + "SDK accepts a numeric-string expires_in, keeps the 24 h cap, and caches nothing else, so it "
                    + "caches this token for at most 24 h.", f.explanation());
            assertEquals(null, f.suggestedFix());
        }

        @Test
        void expiresInAbove24HoursIsReportedWithTheCap() {
            var run = healthy();
            run.tokenResponse = expiresIn(86_400L, "86400");
            assertEquals("The token endpoint issued an access token with an expiry of 86400 seconds.",
                    assertOnly(check.evaluate(run.build()), Severity.PASS).explanation(), "exactly 24 h is not capped");

            run.tokenResponse = expiresIn(86_401L, "86401");
            assertEquals("The token endpoint issued an access token with an expiry of 86401 seconds. That is more "
                    + "than 24 h: the router SDK caches a token for at most 24 h (86400 seconds), not the 86401 sent.",
                    assertOnly(check.evaluate(run.build()), Severity.PASS).explanation());

            run.tokenResponse = expiresIn(172_800L, "\" 172800\"");
            assertEquals("The token endpoint issued an access token with an expiry of 172800 seconds. Its expires_in "
                    + "was sent as a JSON string (\" 172800\"), where RFC 6749 §5.1 requires a JSON number. The "
                    + "router SDK accepts a numeric-string expires_in, keeps the 24 h cap, and caches nothing else, "
                    + "so it caches this token for at most 24 h. That is more than 24 h: the router SDK caches a "
                    + "token for at most 24 h (86400 seconds), not the 172800 sent.",
                    assertOnly(check.evaluate(run.build()), Severity.PASS).explanation());
        }

        private static TokenResponseMetadata expiresIn(Long seconds, String sent) {
            return new TokenResponseMetadata(true, "Bearer", seconds, sent, List.of("system/*.read"), 0, null, null);
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
        void skewedHookClientJwtAcceptedWarns() {
            var run = withoutRequestJwts();
            run.hooks = List.of(clientJwtHook(200, Fixtures.resource("order-sign-healthy.json"), NOW.plusSeconds(300)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
            assertTrue(f.explanation().contains("300 seconds after"), f::explanation);
        }

        @Test
        void skewedHookClientJwtRejectedFails() {
            var run = withoutRequestJwts();
            run.hooks = List.of(clientJwtHook(401, "{\"error\":\"invalid_token\"}", NOW.plusSeconds(300)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("iat offset=300 s"), f::evidence);
        }

        @Test
        void skewedClientAssertionRejectedFails() {
            var run = withoutRequestJwts();
            run.token = token(401, "grant_type=client_credentials", INVALID_CLIENT, NOW);
            run.clientAssertion = claims(TOKEN_URL, NOW.plusSeconds(300));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().startsWith("POST " + TOKEN_URL), f::evidence);
        }

        @Test
        void recordedClaimsWithinTolerancePass() {
            var run = withoutRequestJwts();
            run.clientAssertion = claims(TOKEN_URL, NOW.minusSeconds(20));
            run.hooks = List.of(clientJwtHook(200, Fixtures.resource("order-sign-healthy.json"), NOW.plusSeconds(30)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.PASS);
            assertTrue(f.evidence().contains(TOKEN_URL + " (iat offset -20 s)"), f::evidence);
            assertTrue(f.evidence().contains(ORDER_SIGN_URL + " (iat offset 30 s)"), f::evidence);
        }

        /** An exp with no iat measures nothing, so it must not earn "iat offset 0 s" and a PASS (#266). */
        @Test
        void expOnlyAssertionIsNotAMeasurement() {
            var run = healthy();
            run.token = token(200, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"exp\":"
                    + NOW.plusSeconds(300).getEpochSecond() + "}")), Fixtures.TOKEN_OK_BODY, NOW);
            assertEquals(List.of(), check.evaluate(run.build()));
        }

        @Test
        void expOnlyHookClientJwtIsNotAMeasurement() {
            var run = withoutRequestJwts();
            run.hooks = List.of(new HookResponse("crd-order-sign", "order-sign", "sample-order-sign-1",
                    hook(200, Fixtures.resource("order-sign-healthy.json"), 800),
                    new JwtClaims(Fixtures.CLIENT_ID, List.of(ORDER_SIGN_URL), NOW.plusSeconds(300), null,
                            UUID.randomUUID().toString(), "synthetic-kid", Fixtures.CLIENT_ID)));
            assertEquals(List.of(), check.evaluate(run.build()));
        }

        /** The PASS lists only the exchanges whose iat was compared, not an exp-only one beside them. */
        @Test
        void passListsOnlyMeasuredExchanges() {
            var run = withoutRequestJwts();
            run.clientAssertion = new JwtClaims(Fixtures.CLIENT_ID, List.of(TOKEN_URL), NOW.plusSeconds(300), null,
                    UUID.randomUUID().toString(), "synthetic-kid", Fixtures.CLIENT_ID);
            run.hooks = List.of(clientJwtHook(200, Fixtures.resource("order-sign-healthy.json"), NOW.plusSeconds(30)));
            Finding f = assertOnly(check.evaluate(run.build()), Severity.PASS);
            assertEquals(ORDER_SIGN_URL + " (iat offset 30 s)", f.evidence());
        }

        /** expired() needs no iat, so an expired exp-only JWT rejected for timing keeps its FAIL (#266). */
        @Test
        void expiredExpOnlyAssertionRejectedForTimingFails() {
            var run = healthy();
            run.token = token(401, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"exp\":"
                    + NOW.minusSeconds(600).getEpochSecond() + "}")),
                    "{\"error\":\"invalid_client\",\"error_description\":\"clock skew too large\"}", NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains("already expired by the payer's clock (600 seconds ago"),
                    f::explanation);
            assertTrue(f.evidence().endsWith("\nJWT iat=(none), exp=" + NOW.minusSeconds(600) + "; payer Date header="
                    + NOW), f::evidence);
            assertFalse(f.evidence().contains("iat offset"), f::evidence);
        }

        /** With no iat, the FAIL must not claim the JWT times were within tolerance. */
        @Test
        void unexpiredExpOnlyAssertionRejectedForTimingSaysNoIat() {
            var run = healthy();
            run.token = token(401, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"exp\":"
                    + NOW.plusSeconds(300).getEpochSecond() + "}")),
                    "{\"error\":\"invalid_client\",\"error_description\":\"iat is in the future\"}", NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.explanation().contains(", and the JWT has no iat (issued-at), so its issue time could not "
                    + "be compared with the payer's clock."), f::explanation);
            assertFalse(f.explanation().contains("within 60 seconds"), f::explanation);
            assertFalse(f.evidence().contains("iat offset"), f::evidence);
        }

        /** Beyond Instant's range (about ±3.2e16 s) a claim is absent, not a DateTimeException (#266). */
        @Test
        void outOfRangeIatOrExpIsUnmeasuredNotACrash() {
            for (String claims : List.of("\"iat\":1000000000000000000", "\"exp\":1000000000000000000",
                    "\"iat\":-1000000000000000000", "\"iat\":1e18", "\"iat\":1000000000000000000,\"exp\":"
                            + Long.MAX_VALUE, "\"iat\":123456789012345678901234567890")) {
                for (int status : List.of(200, 401)) {
                    var run = healthy();
                    run.token = token(status, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\"," + claims + "}")),
                            status == 200 ? Fixtures.TOKEN_OK_BODY : INVALID_CLIENT, NOW);
                    List<Finding> findings = assertDoesNotThrow(() -> check.evaluate(run.build()), claims);
                    assertEquals(List.of(), findings, claims + " " + status);
                }
            }
        }

        /** An out-of-range iat beside a usable exp leaves the exp measured. */
        @Test
        void outOfRangeIatKeepsAUsableExp() {
            var run = healthy();
            run.token = token(401, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"iat\":1000000000000000000,"
                    + "\"exp\":" + NOW.minusSeconds(600).getEpochSecond() + "}")),
                    "{\"error\":\"invalid_client\",\"error_description\":\"clock skew too large\"}", NOW);
            Finding f = assertOnly(check.evaluate(run.build()), Severity.FAIL);
            assertTrue(f.evidence().contains("JWT iat=(none), exp=" + NOW.minusSeconds(600)), f::evidence);
        }

        /** The first and last second an Instant holds are still measured; one past either is not. */
        @Test
        void instantRangeEdgesAreMeasured() {
            for (long edge : List.of(Instant.MAX.getEpochSecond(), Instant.MIN.getEpochSecond())) {
                var run = healthy();
                run.token = token(200, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"iat\":" + edge + "}")),
                        Fixtures.TOKEN_OK_BODY, NOW);
                Finding f = assertOnly(check.evaluate(run.build()), Severity.WARN);
                assertTrue(f.evidence().contains("iat=" + Instant.ofEpochSecond(edge)), f::evidence);
                long past = edge > 0 ? edge + 1 : edge - 1;
                run.token = token(200, assertionBody(rawJwt("{\"aud\":\"" + TOKEN_URL + "\",\"iat\":" + past + "}")),
                        Fixtures.TOKEN_OK_BODY, NOW);
                assertEquals(List.of(), check.evaluate(run.build()), String.valueOf(past));
            }
        }

        /** A healthy run whose recorded requests carry no readable JWT, as in the app. */
        private Fixtures.Run withoutRequestJwts() {
            var run = healthy();
            run.token = token(200, "grant_type=client_credentials", Fixtures.TOKEN_OK_BODY, NOW);
            return run;
        }

        private HookResponse clientJwtHook(int status, String body, Instant iat) {
            var exchange = hook(status, body, 800);
            assertTrue(Support.requestJwtClaims(exchange).isEmpty());
            return new HookResponse("crd-order-sign", "order-sign", "sample-order-sign-1", exchange,
                    claims(ORDER_SIGN_URL, iat));
        }

        private JwtClaims claims(String aud, Instant iat) {
            return new JwtClaims(Fixtures.CLIENT_ID, List.of(aud), iat.plusSeconds(300), iat,
                    UUID.randomUUID().toString(), "synthetic-kid", Fixtures.CLIENT_ID);
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
