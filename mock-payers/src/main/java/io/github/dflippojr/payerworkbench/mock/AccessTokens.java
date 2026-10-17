package io.github.dflippojr.payerworkbench.mock;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Mints the access tokens a payer's token endpoint issues, in its {@link PayerBehaviour.AccessToken} format.
 * JWT access tokens follow RFC 9068 ({@code typ at+jwt}) and are signed with a key generated for this
 * payer instance; no key is ever written down. The payer keeps its own record of what it issued, so
 * the format never changes how hook calls are authenticated.
 */
final class AccessTokens {

    /** The audience of a {@link PayerBehaviour.AccessToken#JWT_OTHER_AUDIENCE} token. */
    static final String OTHER_AUDIENCE = "https://fhir.other-resource.example";

    private final SecureRandom random = new SecureRandom();
    private final PayerBehaviour.AccessToken format;
    private JWSSigner signer;
    private JWSAlgorithm algorithm;

    AccessTokens(PayerBehaviour.AccessToken format) {
        this.format = format;
    }

    String issue(String issuer, String clientId, Instant issuedAt, Instant expiresAt) {
        return switch (format) {
            case OPAQUE -> randomText(32);
            case VERY_LONG -> randomText(PayerBehaviour.VERY_LONG_TOKEN_LENGTH * 3 / 4);
            case JWT_RS256, JWT_ES256 -> jwt(issuer, issuer, clientId, issuedAt, expiresAt);
            case JWT_OTHER_AUDIENCE -> jwt(issuer, OTHER_AUDIENCE, clientId, issuedAt, expiresAt);
        };
    }

    private String randomText(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private synchronized String jwt(String issuer, String audience, String clientId, Instant issuedAt,
                                    Instant expiresAt) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer).audience(audience).subject(clientId).claim("client_id", clientId)
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .build();
        try {
            JWSSigner jws = signer();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm)
                    .type(new JOSEObjectType("at+jwt")).keyID("access-token-key").build(), claims);
            jwt.sign(jws);
            return jwt.serialize();
        } catch (JOSEException | GeneralSecurityException e) {
            throw new IllegalStateException("Could not sign a synthetic access token", e);
        }
    }

    private JWSSigner signer() throws GeneralSecurityException, JOSEException {
        if (signer == null) {
            if (format == PayerBehaviour.AccessToken.JWT_ES256) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                signer = new ECDSASigner((ECPrivateKey) generator.generateKeyPair().getPrivate());
                algorithm = JWSAlgorithm.ES256;
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair pair = generator.generateKeyPair();
                signer = new RSASSASigner(pair.getPrivate());
                algorithm = JWSAlgorithm.RS256;
            }
        }
        return signer;
    }
}
