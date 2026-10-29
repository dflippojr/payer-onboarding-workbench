package io.github.dflippojr.payerworkbench.mock;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.UnaryOperator;

/** Minimal {@code --name value} parsing for the payers' {@code main} methods. */
final class StandaloneArgs {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, List<String>> values;

    private StandaloneArgs(Map<String, List<String>> values) {
        this.values = values;
    }

    static StandaloneArgs parse(String[] args) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new IllegalArgumentException("Unexpected argument '" + arg + "'; options look like --name value");
            }
            String name = arg.substring(2);
            String value;
            int eq = name.indexOf('=');
            if (eq >= 0) {
                value = name.substring(eq + 1);
                name = name.substring(0, eq);
            } else if (name.equals("tls")) {
                value = "true";
            } else if (i + 1 < args.length) {
                value = args[++i];
            } else {
                throw new IllegalArgumentException("Option --" + name + " needs a value");
            }
            values.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
        return new StandaloneArgs(values);
    }

    String single(String name, String defaultValue) {
        List<String> list = values.get(name);
        return list == null ? defaultValue : list.get(list.size() - 1);
    }

    void configureTls(MockPayer payer) {
        if (Boolean.parseBoolean(single("tls", "false"))) {
            payer.tls(new TestTls());
        }
    }

    List<String> all(String name) {
        return values.getOrDefault(name, List.of());
    }

    /**
     * Registers each {@code --client ID=JWKS_URL}.
     *
     * @param usage the error text for a value with no ID before an {@code =}
     */
    void clients(UnaryOperator<String> usage, BiConsumer<String, URI> register) {
        for (String client : all("client")) {
            int eq = client.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException(usage.apply(client));
            }
            register.accept(client.substring(0, eq), URI.create(client.substring(eq + 1)));
        }
    }

    /** Applies {@code --tls}, then starts {@code payer} on {@code --port} ({@code defaultPort} if absent). */
    <P extends MockPayer> P startFrom(P payer, int defaultPort) throws IOException {
        configureTls(payer);
        payer.start(Integer.parseInt(single("port", String.valueOf(defaultPort))));
        return payer;
    }

    /** The first line a standalone payer prints: its name, where it listens and its CRD version. */
    static void printHeader(PrintStream out, MockPayer payer) {
        out.println(payer.displayName() + " listening at " + payer.baseUrl() + " (CRD " + payer.igVersion() + ")");
    }

    /** Stops {@code payer} when the JVM shuts down, for a {@code main} that runs until the process is stopped. */
    static void stopOnShutdown(MockPayer payer) {
        Runtime.getRuntime().addShutdownHook(new Thread(payer::stop));
    }

    /** A random URL-safe secret for a standalone run, so no secret is ever committed. */
    static String randomSecret() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
