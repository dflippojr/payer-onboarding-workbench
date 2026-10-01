package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdPrefetch;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * One running mock payer plus a fhir-crd-router {@link CdsHooksClient} and a
 * {@link ConnectionRecord} configured for it, as an onboarding engineer would set them up.
 */
final class PayerFixture implements AutoCloseable {

    static final String CLIENT_ID = "workbench-test-client";
    static final String KEY_ID = "workbench-test-key-1";

    final String name;
    final MockPayer payer;
    final ConnectionRecord record;
    final CdsHooksClient client;
    final String orderSignId;
    final String orderSelectId;
    /** The prefetch key carrying the Coverage search Bundle. */
    final String coveragePrefetchKey;
    final TestKeys.InMemoryCredentials credentials;
    final TestKeys.JwksServer jwks;
    private final Function<List<ObjectNode>, Map<String, Object>> fullPrefetch;
    private final HttpClient http = HttpClient.newHttpClient();

    private PayerFixture(String name, MockPayer payer, ConnectionRecord record, TestKeys.InMemoryCredentials credentials,
                         String orderSignId, String orderSelectId, String coveragePrefetchKey,
                         Function<List<ObjectNode>, Map<String, Object>> fullPrefetch, TestKeys.JwksServer jwks) {
        this.name = name;
        this.payer = payer;
        this.record = record;
        this.credentials = credentials;
        this.client = new CdsHooksClient(credentials);
        this.orderSignId = orderSignId;
        this.orderSelectId = orderSelectId;
        this.coveragePrefetchKey = coveragePrefetchKey;
        this.fullPrefetch = fullPrefetch;
        this.jwks = jwks;
    }

    static PayerFixture create(String name) throws IOException {
        return switch (name) {
            case "northwind" -> northwind();
            case "fabrikam" -> fabrikam();
            default -> throw new IllegalArgumentException(name);
        };
    }

    static PayerFixture northwind() throws IOException {
        return northwind(NorthwindPayer.builder());
    }

    static PayerFixture northwind(NorthwindPayer.Builder builder) throws IOException {
        String secret = UUID.randomUUID().toString();
        TestKeys.InMemoryCredentials credentials = new TestKeys.InMemoryCredentials();
        credentials.put("northwind-client-secret", secret);
        NorthwindPayer payer = builder.client(CLIENT_ID, secret).build().start(0);
        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("northwind-synthetic")
                .displayName(NorthwindPayer.DISPLAY_NAME)
                .environment(Environment.SANDBOX)
                .baseUrl(payer.baseUrl())
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(payer.tokenEndpoint())
                .clientId(CLIENT_ID)
                .credentialRef("northwind-client-secret")
                .igVersion(NorthwindPayer.IG_VERSION)
                .build();
        return new PayerFixture("northwind", payer, record, credentials, "order-sign", "order-select", "coverage",
                orders -> CrdPrefetch.builder()
                        .patient(SyntheticData.patient())
                        .coverage(SyntheticData.coverageBundle())
                        .build(),
                null);
    }

    static PayerFixture fabrikam() throws IOException {
        return fabrikam(FabrikamPayer.builder());
    }

    static PayerFixture fabrikam(FabrikamPayer.Builder builder) throws IOException {
        KeyPair key = TestKeys.rsa();
        TestKeys.JwksServer jwks = new TestKeys.JwksServer().publish(KEY_ID, key);
        TestKeys.InMemoryCredentials credentials = new TestKeys.InMemoryCredentials();
        credentials.put("fabrikam-signing-key", TestKeys.privatePem(key));
        FabrikamPayer payer = builder.client(CLIENT_ID, jwks.url()).build().start(0);
        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("fabrikam-synthetic")
                .displayName(FabrikamPayer.DISPLAY_NAME)
                .environment(Environment.SANDBOX)
                .baseUrl(payer.baseUrl())
                .authType(AuthType.CDS_HOOKS_JWT)
                .clientId(CLIENT_ID)
                .keyId(KEY_ID)
                .jwksUrl(jwks.url().toString())
                .credentialRef("fabrikam-signing-key")
                .igVersion(FabrikamPayer.IG_VERSION)
                .build();
        return new PayerFixture("fabrikam", payer, record, credentials, "order-sign-crd", "order-select-crd",
                "coverageBundle",
                orders -> {
                    List<ObjectNode> included = new ArrayList<>(orders);
                    included.add(SyntheticData.patient());
                    included.add(SyntheticData.coverage());
                    return CrdPrefetch.builder()
                            .put("coverageBundle", SyntheticData.coverageBundle())
                            .put("deviceRequestBundle", SyntheticData.bundle("searchset", included))
                            .build();
                },
                jwks);
    }

    Map<String, Object> fullPrefetch(List<ObjectNode> orders) {
        return fullPrefetch.apply(orders);
    }

    CdsHookResponse orderSign(List<ObjectNode> orders) {
        return orderSign(orders, fullPrefetch(orders));
    }

    CdsHookResponse orderSign(List<ObjectNode> orders, Map<String, Object> prefetch) {
        return client.callHook(record, orderSignId, CdsHookRequest.of(SyntheticData.orderSign(orders), prefetch));
    }

    CdsHookResponse orderSelect(List<ObjectNode> orders) {
        return client.callHook(record, orderSelectId,
                CdsHookRequest.of(SyntheticData.orderSelect(orders), fullPrefetch(orders)));
    }

    /** A raw request straight to the payer, without the SDK's auth handling. */
    HttpResponse<String> raw(String method, String path, String body, String... headers) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(payer.baseUrl() + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (headers.length > 0) {
            request.headers(headers);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Override
    public void close() {
        payer.close();
        if (jwks != null) {
            jwks.close();
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
