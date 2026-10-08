package io.github.dflippojr.payerworkbench.app;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A random, in-memory, single-use value that lets the app's own warm-up request be audited as the
 * system actor. It is never configured, logged or returned; a caller that does not hold the current
 * value stays anonymous, and a value that has been used no longer matches.
 */
@Component
final class InternalRequestToken {

    static final String HEADER = "X-Workbench-Internal";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AtomicReference<byte[]> pending = new AtomicReference<>();

    /** Issues the value for exactly one self-request, replacing any unused earlier one. */
    String issue() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        pending.set(value.getBytes(StandardCharsets.US_ASCII));
        return value;
    }

    /** True once, for the value most recently issued. */
    boolean consume(String presented) {
        byte[] expected = pending.get();
        if (expected == null || presented == null) {
            return false;
        }
        return MessageDigest.isEqual(expected, presented.getBytes(StandardCharsets.US_ASCII))
                && pending.compareAndSet(expected, null);
    }
}
