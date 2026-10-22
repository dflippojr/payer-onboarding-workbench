package io.github.dflippojr.payerworkbench.mock;

import java.time.Duration;
import java.util.Objects;

/**
 * How one mock payer differs from its standard behaviour: the legitimate (and some illegitimate)
 * variation real payers show in token format, token responses, authentication, clock and discovery.
 * Passed at construction through each payer's builder; {@link #STANDARD} is what the named payers do
 * by default. Unlike a {@link Fault}, a behaviour is fixed for the payer's lifetime.
 *
 * @param accessToken       what the token endpoint issues as {@code access_token}
 * @param tokenType         the {@code token_type} value, case kept as given
 * @param expiresIn         the JSON type and form of {@code expires_in}
 * @param extraTokenFields  add response fields the client does not know
 * @param tokenContentType  the token response's {@code Content-Type}
 * @param tokenErrorWith200 answer a valid token request with HTTP 200 and an OAuth {@code error} body
 * @param hookAuthentication whether hook calls are authenticated at all
 * @param clockOffset       how far the payer's clock (and its {@code Date} header) is from the real time
 * @param redirect          a redirect the payer answers one endpoint with, or {@code null}
 * @param discovery         the shape of the discovery document
 */
public record PayerBehaviour(AccessToken accessToken, String tokenType, ExpiresIn expiresIn,
                             boolean extraTokenFields, String tokenContentType, boolean tokenErrorWith200,
                             HookAuthentication hookAuthentication, Duration clockOffset, Redirect redirect,
                             Discovery discovery) {

    public static final PayerBehaviour STANDARD = new PayerBehaviour(AccessToken.OPAQUE, "Bearer", ExpiresIn.NUMBER, false,
            "application/json", false, HookAuthentication.ENFORCED, Duration.ZERO, null, Discovery.STANDARD);

    public PayerBehaviour {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(tokenType, "tokenType");
        Objects.requireNonNull(expiresIn, "expiresIn");
        Objects.requireNonNull(tokenContentType, "tokenContentType");
        Objects.requireNonNull(hookAuthentication, "hookAuthentication");
        Objects.requireNonNull(clockOffset, "clockOffset");
        Objects.requireNonNull(discovery, "discovery");
    }

    /** What the token endpoint issues. */
    public enum AccessToken {
        /** 32 random bytes, base64url: the named payers' default. */
        OPAQUE,
        /** A JWT access token (RFC 9068) signed RS256, audience this payer. */
        JWT_RS256,
        /** A JWT access token signed ES256 (P-256), audience this payer. */
        JWT_ES256,
        /** An RS256 JWT access token whose {@code aud} names another resource server; this payer still accepts it. */
        JWT_OTHER_AUDIENCE,
        /** An opaque token of {@value PayerBehaviour#VERY_LONG_TOKEN_LENGTH} characters. */
        VERY_LONG
    }

    /** How the token response sends {@code expires_in}. */
    public enum ExpiresIn {
        /** A JSON number of seconds, as RFC 6749 section 5.1 requires. */
        NUMBER,
        /** The same seconds as a JSON string, such as {@code "300"}; some identity providers do this. */
        NUMERIC_STRING,
        /** A JSON string that is not a number of seconds: {@value PayerBehaviour#NON_NUMERIC_EXPIRES_IN}. */
        NON_NUMERIC_STRING
    }

    /** The {@code expires_in} a {@link ExpiresIn#NON_NUMERIC_STRING} payer sends. */
    public static final String NON_NUMERIC_EXPIRES_IN = "5 minutes";

    /** Length of a {@link AccessToken#VERY_LONG} token; large identity-provider tokens reach this size. */
    public static final int VERY_LONG_TOKEN_LENGTH = 8192;

    /** Whether hook calls are authenticated. */
    public enum HookAuthentication {
        /** Hook calls must carry the payer's credential. */
        ENFORCED,
        /** Any hook call is accepted, with or without a credential. */
        IGNORED
    }

    /** The shape of {@code GET /cds-services}. */
    public enum Discovery {
        STANDARD,
        /** Adds services for hooks the client does not use, with fields and extensions it does not know. */
        EXTRA_UNKNOWN_SERVICES,
        /** Leaves out every service's {@code prefetch} (it is OPTIONAL in CDS Hooks 2.0). */
        NO_PREFETCH,
        /** An empty {@code services} array, which CDS Hooks prescribes for a server with no services. */
        EMPTY
    }

    /**
     * Requests for {@code path} are answered with {@code status} and {@code Location: location}. A
     * location under {@value #MOVED_PREFIX} on the same payer serves the real endpoint, so a client that
     * follows a same-host redirect gets an answer.
     */
    public record Redirect(String path, int status, String location) {

        /** Every endpoint is also served under this path prefix, where redirects never apply. */
        public static final String MOVED_PREFIX = "/moved";

        public Redirect {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(location, "location");
            if (status < 300 || status > 399) {
                throw new IllegalArgumentException("A redirect needs a 3xx status, got " + status);
            }
        }

        /** A redirect to the same endpoint under {@value #MOVED_PREFIX} on this payer. */
        public static Redirect sameHost(String path, int status) {
            return new Redirect(path, status, MOVED_PREFIX + path);
        }
    }

    public PayerBehaviour withAccessToken(AccessToken value) {
        return new PayerBehaviour(value, tokenType, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withTokenType(String value) {
        return new PayerBehaviour(accessToken, value, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withExpiresIn(ExpiresIn value) {
        return new PayerBehaviour(accessToken, tokenType, value, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withExtraTokenFields(boolean value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, value, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withTokenContentType(String value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, value,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withTokenErrorWith200(boolean value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, tokenContentType,
                value, hookAuthentication, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withHookAuthentication(HookAuthentication value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, value, clockOffset, redirect, discovery);
    }

    public PayerBehaviour withClockOffset(Duration value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, value, redirect, discovery);
    }

    public PayerBehaviour withRedirect(Redirect value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, value, discovery);
    }

    public PayerBehaviour withDiscovery(Discovery value) {
        return new PayerBehaviour(accessToken, tokenType, expiresIn, extraTokenFields, tokenContentType,
                tokenErrorWith200, hookAuthentication, clockOffset, redirect, value);
    }
}
