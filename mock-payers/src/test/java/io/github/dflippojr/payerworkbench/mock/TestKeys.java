package io.github.dflippojr.payerworkbench.mock;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.auth.Jwks;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Runtime-generated keys, a JWKS endpoint and other test plumbing. Nothing here is written to disk. */
final class TestKeys {

    private TestKeys() { }

    static KeyPair rsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair ecP384() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp384r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String privatePem(KeyPair keyPair) {
        return PemKeys.toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    }

    /** Serves a client's public JWK Set at {@link #url()}; the published keys can be replaced (rotation). */
    static final class JwksServer implements AutoCloseable {

        private final HttpServer server;
        private final Map<String, KeyPair> keys = new LinkedHashMap<>();
        private final AtomicInteger fetches = new AtomicInteger();

        JwksServer() throws IOException {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.createContext("/jwks.json", exchange -> {
                fetches.incrementAndGet();
                byte[] body = json().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
        }

        synchronized JwksServer publish(String keyId, KeyPair keyPair) {
            keys.put(keyId, keyPair);
            return this;
        }

        private synchronized String json() {
            Jwks jwks = Jwks.builder();
            keys.forEach((kid, pair) -> jwks.add(kid, pair.getPublic()));
            return jwks.toJson();
        }

        URI url() {
            return URI.create("http://localhost:" + server.getAddress().getPort() + "/jwks.json");
        }

        int fetchCount() {
            return fetches.get();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** A clock tests can move forward. */
    static final class MutableClock extends Clock {

        private volatile Instant now = Instant.now();

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** Secrets held in memory for one test. */
    static final class InMemoryCredentials implements CredentialProvider {

        private final Map<String, String> secrets = new ConcurrentHashMap<>();

        @Override
        public Optional<String> resolve(String credentialRef) {
            return Optional.ofNullable(secrets.get(credentialRef));
        }

        @Override
        public void put(String credentialRef, String secretValue) {
            secrets.put(credentialRef, secretValue);
        }

        @Override
        public void remove(String credentialRef) {
            secrets.remove(credentialRef);
        }
    }
}
