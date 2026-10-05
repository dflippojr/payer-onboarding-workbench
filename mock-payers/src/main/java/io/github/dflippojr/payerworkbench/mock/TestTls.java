package io.github.dflippojr.payerworkbench.mock;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import org.bouncycastle.operator.OperatorCreationException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

/** Synthetic certificate authorities and server identities, held exclusively in memory. */
public final class TestTls {
    private final KeyPair serverKey;
    private final X509Certificate ca;
    private final Map<String, X509Certificate[]> chains;

    public TestTls() {
        try {
            KeyPair trustedKey = key();
            KeyPair otherKey = key();
            serverKey = key();
            Instant now = Instant.now();
            Instant before = now.minus(30, ChronoUnit.DAYS);
            Instant after = now.plus(30, ChronoUnit.DAYS);
            ca = certificate("Workbench test CA", trustedKey, "Workbench test CA", trustedKey, before, after, true, false);
            X509Certificate other = certificate("Other test CA", otherKey, "Other test CA", otherKey, before, after, true, false);
            chains = Map.of(
                    "healthy", new X509Certificate[]{certificate("localhost", serverKey, "Workbench test CA", trustedKey, before, after, false, false), ca},
                    "untrusted", new X509Certificate[]{certificate("localhost", serverKey, "Other test CA", otherKey, before, after, false, false), other},
                    "expired", new X509Certificate[]{certificate("localhost", serverKey, "Workbench test CA", trustedKey, before, now.minus(1, ChronoUnit.DAYS), false, false), ca},
                    "wrong-host", new X509Certificate[]{certificate("crd.other-payer.example", serverKey, "Workbench test CA", trustedKey, before, after, false, true), ca});
        } catch (GeneralSecurityException | IOException | OperatorCreationException e) {
            throw new IllegalStateException("Cannot generate synthetic TLS identities", e);
        }
    }

    /** A fresh context trusts only this instance's CA; no JVM trust-store changes. */
    public SSLContext clientContext() {
        try {
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            trust.setCertificateEntry("test-ca", ca);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot initialize test CA trust", e);
        }
    }

    SSLContext serverContext(FaultSettings faults) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{new Certificates(faults)}, null, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot initialize mock payer TLS", e);
        }
    }

    private static KeyPair key() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String subject, KeyPair key, String issuer, KeyPair signer,
                                               Instant before, Instant after, boolean authority, boolean wrongHost) throws GeneralSecurityException, IOException, OperatorCreationException {
        var builder = new JcaX509v3CertificateBuilder(new X500Name("CN=" + issuer),
                new BigInteger(160, new SecureRandom()), Date.from(before), Date.from(after),
                new X500Name("CN=" + subject), key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(authority));
        if (!authority) {
            GeneralName[] names = wrongHost
                    ? new GeneralName[]{new GeneralName(GeneralName.dNSName, "crd.other-payer.example")}
                    : new GeneralName[]{new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")};
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
    }

    private final class Certificates extends X509ExtendedKeyManager {
        private final FaultSettings faults;

        private Certificates(FaultSettings faults) {
            this.faults = faults;
        }

        private String alias(String keyType) {
            if (!"RSA".equals(keyType)) {
                return null;
            }
            if (faults.isEnabled(Fault.UNTRUSTED_CERTIFICATE)) {
                return "untrusted";
            }
            if (faults.isEnabled(Fault.EXPIRED_CERTIFICATE)) {
                return "expired";
            }
            return faults.isEnabled(Fault.HOSTNAME_MISMATCH) ? "wrong-host" : "healthy";
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return alias(keyType);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return alias(keyType);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            String selected = alias(keyType);
            return selected == null ? null : new String[]{selected};
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            X509Certificate[] chain = chains.get(alias);
            return chain == null ? null : chain.clone();
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return chains.containsKey(alias) ? serverKey.getPrivate() : null;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            return null;
        }
    }
}
