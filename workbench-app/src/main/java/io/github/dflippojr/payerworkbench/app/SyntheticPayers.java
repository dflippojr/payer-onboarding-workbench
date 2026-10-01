package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The two mock payers, started in-process on loopback ephemeral ports, plus what an
 * onboarding engineer would have set up for them: a {@link ConnectionRecord} each in a
 * directory-core file store under a temp directory, and credentials generated at startup
 * and held only in memory ({@link InMemoryCredentials}).
 *
 * <p>Only {@link Environment#SANDBOX} records are seeded, so a run against another
 * environment shows what happens when the directory has no record.
 */
@Component
public class SyntheticPayers implements DisposableBean {

    public static final String NORTHWIND_ID = "northwind-synthetic";
    public static final String FABRIKAM_ID = "fabrikam-synthetic";
    static final String CLIENT_ID = "payer-workbench";
    static final String KEY_ID = "payer-workbench-key-1";

    private static final Logger log = LoggerFactory.getLogger(SyntheticPayers.class);

    private final Path workDir;
    private final FileBasedConnectionStore store;
    private final InMemoryCredentials credentials = new InMemoryCredentials();
    private final JwksServer jwks;
    private final Map<String, MockPayer> payers = new LinkedHashMap<>();

    public SyntheticPayers() throws IOException {
        workDir = Files.createTempDirectory("payer-workbench-");
        store = new FileBasedConnectionStore(workDir.resolve("connections.yaml"));
        try {
            String secret = randomSecret();
            credentials.put("northwind-client-secret", secret);
            NorthwindPayer northwind = NorthwindPayer.builder().client(CLIENT_ID, secret).build().start(0);
            payers.put(NORTHWIND_ID, northwind);
            store.save(ConnectionRecord.builder()
                    .payerId(NORTHWIND_ID)
                    .displayName(northwind.displayName())
                    .environment(Environment.SANDBOX)
                    .baseUrl(northwind.baseUrl())
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                    .tokenEndpoint(northwind.tokenEndpoint())
                    .clientId(CLIENT_ID)
                    .credentialRef("northwind-client-secret")
                    .igVersion(northwind.igVersion())
                    .contactInfo("synthetic; no real payer")
                    .build());

            KeyPair key = rsaKey();
            credentials.put("fabrikam-signing-key", PemKeys.toPem("PRIVATE KEY", key.getPrivate().getEncoded()));
            jwks = new JwksServer(KEY_ID, key.getPublic());
            FabrikamPayer fabrikam = FabrikamPayer.builder().client(CLIENT_ID, jwks.url()).build().start(0);
            payers.put(FABRIKAM_ID, fabrikam);
            store.save(ConnectionRecord.builder()
                    .payerId(FABRIKAM_ID)
                    .displayName(fabrikam.displayName())
                    .environment(Environment.SANDBOX)
                    .baseUrl(fabrikam.baseUrl())
                    .authType(AuthType.CDS_HOOKS_JWT)
                    .clientId(CLIENT_ID)
                    .keyId(KEY_ID)
                    .jwksUrl(jwks.url().toString())
                    .credentialRef("fabrikam-signing-key")
                    .igVersion(fabrikam.igVersion())
                    .contactInfo("synthetic; no real payer")
                    .build());
        } catch (IOException | RuntimeException e) {
            destroy();
            throw e;
        }
        payers.forEach((id, payer) -> log.info("Started synthetic payer {} at {}", id, payer.baseUrl()));
    }

    public ConnectionStore store() {
        return store;
    }

    InMemoryCredentials credentials() {
        return credentials;
    }

    public List<String> payerIds() {
        return List.copyOf(payers.keySet());
    }

    public Optional<MockPayer> payer(String payerId) {
        return Optional.ofNullable(payers.get(payerId));
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static KeyPair rsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void destroy() {
        payers.values().forEach(MockPayer::close);
        if (jwks != null) {
            jwks.close();
        }
        try (Stream<Path> paths = Files.walk(workDir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
