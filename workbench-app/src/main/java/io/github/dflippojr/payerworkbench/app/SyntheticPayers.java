package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.mock.TestTls;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import io.github.dflippojr.payerworkbench.mock.TailspinPayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
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
 * The three mock payers, started in-process on loopback ephemeral ports, plus what an
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
    public static final String TAILSPIN_ID = "tailspin-synthetic";
    static final String CLIENT_ID = "payer-workbench";
    static final String KEY_ID = "payer-workbench-key-1";

    private static final Logger log = LoggerFactory.getLogger(SyntheticPayers.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final TestTls tls = new TestTls();

    TestTls tls() {
        return tls;
    }

    private final Path workDir;
    private final FileBasedConnectionStore store;
    private final AuditLog audit;
    private final PathDeleter deleter;
    private final InMemoryCredentials credentials;
    private final JwksServer jwks;
    private final Map<String, MockPayer> payers = new LinkedHashMap<>();

    /** Deletes one path during cleanup; replaceable so a test can make a delete fail. */
    @FunctionalInterface
    interface PathDeleter {
        void delete(Path path) throws IOException;
    }

    /** Standalone use (no Spring): lifecycle events go to the log with a throwaway failure counter. */
    public SyntheticPayers() throws IOException {
        this(new AuditLog(new io.micrometer.core.instrument.simple.SimpleMeterRegistry()));
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SyntheticPayers(AuditLog audit) throws IOException {
        this(audit, Files::delete);
    }

    SyntheticPayers(AuditLog audit, PathDeleter deleter) throws IOException {
        this.audit = audit;
        this.deleter = deleter;
        this.credentials = new InMemoryCredentials(audit);
        workDir = createPrivateTempDir();
        store = new FileBasedConnectionStore(workDir.resolve("connections.yaml"));
        try {
            String secret = randomSecret();
            credentials.put("northwind-client-secret", secret);
            NorthwindPayer northwind = NorthwindPayer.builder().client(CLIENT_ID, secret).build();
            northwind.tls(tls).start(0);
            started(NORTHWIND_ID, northwind);
            seed(ConnectionRecord.builder()
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
            KeyPair tailspinKey = rsaKey();
            credentials.put("tailspin-signing-key", PemKeys.toPem("PRIVATE KEY", tailspinKey.getPrivate().getEncoded()));
            jwks = new JwksServer(Map.of(KEY_ID, key.getPublic(), "tailspin-key-1", tailspinKey.getPublic()));
            FabrikamPayer fabrikam = FabrikamPayer.builder().client(CLIENT_ID, jwks.url()).build();
            fabrikam.tls(tls).start(0);
            started(FABRIKAM_ID, fabrikam);
            seed(ConnectionRecord.builder()
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
            TailspinPayer tailspin = TailspinPayer.builder().client(CLIENT_ID, jwks.url()).build();
            tailspin.tls(tls).start(0);
            started(TAILSPIN_ID, tailspin);
            seed(ConnectionRecord.builder()
                    .payerId(TAILSPIN_ID).displayName(tailspin.displayName()).environment(Environment.SANDBOX)
                    .baseUrl(tailspin.baseUrl()).authType(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                    .tokenEndpoint(tailspin.tokenEndpoint()).clientId(CLIENT_ID).keyId("tailspin-key-1")
                    .jwksUrl(jwks.url().toString()).credentialRef("tailspin-signing-key")
                    .igVersion(tailspin.igVersion()).contactInfo("synthetic; no real payer").build());
        } catch (IOException | RuntimeException e) {
            audit.lifecycle("startup.failed", "failed", "application", null,
                    AuditEvent.Metadata.ofLifecycle("seed_failed", null, null, null));
            destroy();
            throw e;
        }
        payers.forEach((id, payer) -> log.info("Started synthetic payer {} at {}", id, payer.baseUrl()));
    }

    private void started(String payerId, MockPayer payer) {
        payers.put(payerId, payer);
        payer.auditSink(audit::append).auditPayerId(payerId);
        audit.lifecycle("payer.started", "success", "payer", payerId,
                AuditEvent.Metadata.ofLifecycle(null, payerId, null, null));
    }

    private void seed(ConnectionRecord record) {
        store.save(record);
        audit.lifecycle("connection.seeded", "success", "connection", record.payerId(),
                AuditEvent.Metadata.ofLifecycle(null, record.payerId(), null, null));
    }

    public ConnectionStore store() {
        return store;
    }

    AuditLog audit() {
        return audit;
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

    /**
     * connections.yaml lives here, so the directory is owner-only ({@code rwx------}) where the file
     * system supports POSIX permissions. Elsewhere (Windows) the default temp directory is already
     * per-user, so no attribute is passed.
     */
    private static Path createPrivateTempDir() throws IOException {
        FileAttribute<?>[] ownerOnly = FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))}
                : new FileAttribute<?>[0];
        return Files.createTempDirectory("payer-workbench-", ownerOnly);
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
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

    /**
     * Stops the payers and deletes the temp directory, recording what was observed. A delete that fails
     * is counted, never reported as done. A crash or SIGKILL skips this method, so no shutdown event
     * is written in that case.
     */
    @Override
    public void destroy() {
        audit.lifecycle("cleanup.attempted", "started", "application", null,
                AuditEvent.Metadata.ofLifecycle(null, null, null, null));
        payers.forEach((id, payer) -> {
            payer.close();
            audit.lifecycle("payer.stopped", "success", "payer", id,
                    AuditEvent.Metadata.ofLifecycle(null, id, null, null));
        });
        if (jwks != null) {
            jwks.close();
        }
        credentials.removeAll();
        List<Path> paths;
        try (Stream<Path> walk = Files.walk(workDir)) {
            paths = walk.sorted(Comparator.reverseOrder()).toList();
        } catch (IOException e) {
            audit.lifecycle("cleanup.finished", "failed", "application", null,
                    AuditEvent.Metadata.ofLifecycle("walk_failed", null, null, AuditEvent.Lifecycle.cleanup(0, 0, 0)));
            throw new UncheckedIOException(e);
        }
        int deleted = 0;
        int failed = 0;
        for (Path path : paths) {
            try {
                deleter.delete(path);
                deleted++;
            } catch (IOException | RuntimeException e) {
                failed++;
            }
        }
        boolean gone = !Files.exists(workDir);
        boolean complete = failed == 0 && gone;
        if (!complete) {
            log.warn("Cleanup left synthetic temp files behind");
        }
        audit.lifecycle("cleanup.finished", complete ? "success" : "partial", "application", null,
                AuditEvent.Metadata.ofLifecycle(complete ? null : "delete_failed", null, null,
                        AuditEvent.Lifecycle.cleanup(paths.size(), deleted, failed)));
    }
}
