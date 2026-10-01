package io.github.dflippojr.payerworkbench.mock;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal {@code --name value} parsing for the payers' {@code main} methods. */
final class StandaloneArgs {

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

    List<String> all(String name) {
        return values.getOrDefault(name, List.of());
    }

    /** A random URL-safe secret for a standalone run, so no secret is ever committed. */
    static String randomSecret() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
