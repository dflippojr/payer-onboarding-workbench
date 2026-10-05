package io.github.dflippojr.payerworkbench.mock;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/** Verifies against registered URLs only; untrusted JWT jku headers are never followed. */
final class RegisteredJwks {
    private final Map<String, URI> jwksUrls;
    private final Map<String, JWKSet> jwksCache = new ConcurrentHashMap<>();
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Function<String, MockPayer.HttpError> rejected;

    RegisteredJwks(Map<String, URI> urls, Function<String, MockPayer.HttpError> rejected) {
        this.jwksUrls = Map.copyOf(urls);
        this.rejected = rejected;
    }
    private MockPayer.HttpError rejected(String message) { return rejected.apply(message); }
    void verify(SignedJWT jwt, String issuer, String keyId) {
        JWK key = jwksCache.computeIfAbsent(issuer, this::fetchJwks).getKeyByKeyId(keyId);
        if (key == null) {
            // The client may have rotated keys since we cached its JWKS.
            JWKSet refreshed = fetchJwks(issuer);
            jwksCache.put(issuer, refreshed);
            key = refreshed.getKeyByKeyId(keyId);
        }
        if (!(key instanceof AsymmetricJWK asymmetric)) {
            throw rejected("No public key with kid '" + keyId + "' in the JWKS for iss '" + issuer + "'");
        }
        try {
            if (!jwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), asymmetric.toPublicKey()))) {
                throw rejected("JWT signature does not verify against kid '" + keyId + "'");
            }
        } catch (JOSEException e) {
            throw rejected("JWT signature could not be checked with kid '" + keyId + "': " + e.getMessage());
        }
    }

    private JWKSet fetchJwks(String issuer) {
        URI url = jwksUrls.get(issuer);
        try {
            HttpResponse<String> response = httpClient.send(
                    HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw rejected("Could not fetch JWKS for iss '" + issuer + "' from " + url
                        + ": HTTP " + response.statusCode());
            }
            return JWKSet.parse(response.body());
        } catch (IOException | ParseException e) {
            throw rejected("Could not fetch JWKS for iss '" + issuer + "' from " + url + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw rejected("Interrupted fetching JWKS for iss '" + issuer + "'");
        }
    }

}
