package io.github.dflippojr.payerworkbench.mock;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The replay cache the shared validator keeps: keyed by issuer and jti, held until exp, then dropped. */
class ClientJwtValidatorTest {

    private static final String AUDIENCE = "https://payer.example/token";

    private static final ClientJwtValidator.Policy POLICY = new ClientJwtValidator.Policy(
            Set.of(JWSAlgorithm.RS384), true,
            new ClientJwtValidator.Messages("missing", "not signed", alg -> "alg", iss -> "iss", "kid", "exp",
                    null, exp -> "expired", "jti", jti -> "replay " + jti),
            new ClientJwtValidator.ExpiryCap(Duration.ofMinutes(5), "too far"), null);

    @Test
    void replayCacheIsPerIssuerAndForgetsAJtiOnceItsAssertionExpires() throws Exception {
        KeyPair key = TestKeys.rsa();
        TestKeys.MutableClock clock = new TestKeys.MutableClock();
        try (TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish("kid", key)) {
            ClientJwtValidator validator = new ClientJwtValidator(Map.of("a", jwks.url(), "b", jwks.url()),
                    message -> new MockPayer.HttpError(401, "rejected", message), clock, POLICY);

            assertEquals("a", validate(validator, key, "a", "same", clock.instant()));
            assertEquals("b", validate(validator, key, "b", "same", clock.instant()),
                    "the same jti from another issuer is not a replay");
            MockPayer.HttpError replay = assertThrows(MockPayer.HttpError.class,
                    () -> validate(validator, key, "a", "same", clock.instant()));
            assertEquals("replay same", replay.getMessage());
            assertEquals(2, validator.replayCacheSize());

            clock.advance(Duration.ofSeconds(299));
            validator.sweepExpired();
            assertEquals(2, validator.replayCacheSize(), "both assertions are still valid for one more second");

            clock.advance(Duration.ofSeconds(1));
            validator.sweepExpired();
            assertEquals(0, validator.replayCacheSize());
            assertEquals("a", validate(validator, key, "a", "same", clock.instant()),
                    "once the first assertion expired its jti may be used again");
        }
    }

    private static String validate(ClientJwtValidator validator, KeyPair key, String issuer, String jti,
                                   Instant issuedAt) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer).audience(AUDIENCE)
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(issuedAt.plusSeconds(300))).jwtID(jti).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID("kid").build(), claims);
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return validator.validate(jwt.serialize(), AUDIENCE, false, false, (iss, set) -> { });
    }
}
