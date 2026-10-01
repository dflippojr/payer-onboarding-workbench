package io.github.dflippojr.payerworkbench.app;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.auth.Jwks;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

/**
 * Publishes the workbench client's public signing key as a JWK Set on a loopback
 * ephemeral port, where the JWT-authenticating mock payer fetches it.
 */
final class JwksServer implements AutoCloseable {

    private final HttpServer server;

    JwksServer(String keyId, PublicKey publicKey) throws IOException {
        byte[] body = Jwks.builder().add(keyId, publicKey).toJson().getBytes(StandardCharsets.UTF_8);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/jwks.json", exchange -> {
            try (exchange) {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
        });
        server.start();
    }

    URI url() {
        return URI.create("http://localhost:" + server.getAddress().getPort() + "/jwks.json");
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
