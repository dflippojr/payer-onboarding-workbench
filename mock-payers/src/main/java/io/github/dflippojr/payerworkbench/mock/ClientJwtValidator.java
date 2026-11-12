package io.github.dflippojr.payerworkbench.mock;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * The client-JWT checks Fabrikam (CDS Hooks client JWT) and Tailspin (SMART private_key_jwt) share, and the jti
 * replay cache they keep. In order: the token is present and parses as a signed JWT, its alg is allowed, its
 * {@code iss} is registered, the payer's own issuer check passes, {@code kid} is present, the signature verifies
 * against the issuer's registered JWKS, {@code aud} is exactly the expected audience, {@code exp} is present and not
 * past (plus the payer's optional caps on exp and iat), {@code jti} is present, and the {@code iss|jti} pair has not
 * been seen while its assertion is still valid. Each payer supplies its error factory, its messages and its
 * {@link Policy}; the order and the replay cache are the same for both.
 */
final class ClientJwtValidator {

    /** The wording a payer uses for each rejection the shared checks raise. */
    record Messages(
            String missingToken,
            String notSigned,
            Function<JWSAlgorithm, String> algorithm,
            Function<String, String> unknownIssuer,
            String missingKid,
            String missingExp,
            /* Used only when the caller forces expiry with Fault.EXPIRED_TOKEN_401; null if it never does. */
            String forcedExpired,
            Function<Instant, String> expired,
            String missingJti,
            Function<String, String> replay) {
        Messages {
            Objects.requireNonNull(missingToken, "missingToken");
            Objects.requireNonNull(notSigned, "notSigned");
            Objects.requireNonNull(algorithm, "algorithm");
            Objects.requireNonNull(unknownIssuer, "unknownIssuer");
            Objects.requireNonNull(missingKid, "missingKid");
            Objects.requireNonNull(missingExp, "missingExp");
            Objects.requireNonNull(expired, "expired");
            Objects.requireNonNull(missingJti, "missingJti");
            Objects.requireNonNull(replay, "replay");
        }
    }

    /** Refuses an {@code exp} more than {@code max} ahead of the payer's clock. */
    record ExpiryCap(Duration max, String message) {
        ExpiryCap {
            Objects.requireNonNull(max, "max");
            Objects.requireNonNull(message, "message");
        }
    }

    /**
     * Requires an {@code iat}, caps {@code exp - iat} at {@code maxLifetime} (and requires it positive), and caps how
     * far {@code iat} may be ahead of the payer's clock at {@code maxAhead}. Together they bound how long a jti stays
     * in the replay cache: at most {@code maxAhead + maxLifetime} past the current time.
     */
    record IssuedAtRule(Duration maxLifetime, Duration maxAhead, String missing,
                        Function<Duration, String> lifetime, Function<Duration, String> ahead) {
        IssuedAtRule {
            Objects.requireNonNull(maxLifetime, "maxLifetime");
            Objects.requireNonNull(maxAhead, "maxAhead");
            Objects.requireNonNull(missing, "missing");
            Objects.requireNonNull(lifetime, "lifetime");
            Objects.requireNonNull(ahead, "ahead");
        }
    }

    /**
     * What one payer accepts. {@code rejectBlankKid} refuses a blank {@code kid} as missing (otherwise it reaches the
     * JWKS lookup and fails there). {@code expiryCap} and {@code issuedAt} are null when the payer has no such rule.
     */
    record Policy(Set<JWSAlgorithm> algorithms, boolean rejectBlankKid, Messages messages,
                  ExpiryCap expiryCap, IssuedAtRule issuedAt) {
        Policy {
            algorithms = Set.copyOf(algorithms);
            Objects.requireNonNull(messages, "messages");
        }
    }

    private final Map<String, URI> issuers;
    private final RegisteredJwks verifier;
    private final Function<String, MockPayer.HttpError> rejected;
    private final Clock clock;
    private final Policy policy;
    private final Messages messages;
    private final Map<String, Instant> usedJtis = new ConcurrentHashMap<>();

    /**
     * @param issuers  each registered {@code iss} and the URL its public JWK Set is served from
     * @param rejected the payer's error factory, for every rejection including the JWKS ones
     * @param clock    the payer's clock
     */
    ClientJwtValidator(Map<String, URI> issuers, Function<String, MockPayer.HttpError> rejected, Clock clock,
                       Policy policy) {
        this.issuers = Map.copyOf(issuers);
        this.rejected = Objects.requireNonNull(rejected, "rejected");
        this.verifier = new RegisteredJwks(this.issuers, rejected);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.messages = policy.messages();
    }

    /**
     * Runs every check and records the jti.
     *
     * @param token         the compact JWT, or null if the request carried none
     * @param audience      the one {@code aud} value this call must carry
     * @param audienceFault whether {@link Fault#WRONG_AUDIENCE_REJECT} is on, so an aud mismatch is tagged with it
     * @param expiredFault  whether {@link Fault#EXPIRED_TOKEN_401} is on, so a JWT that got as far as its times is
     *                      refused as expired and tagged with it
     * @param issuerCheck   the payer's own check of the registered issuer against the claims, run before the kid
     *                      check; it throws to refuse
     * @return the verified issuer
     */
    String validate(String token, String audience, boolean audienceFault, boolean expiredFault,
                    BiConsumer<String, JWTClaimsSet> issuerCheck) {
        if (token == null) {
            throw rejected.apply(messages.missingToken());
        }
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw rejected.apply(messages.notSigned());
        }
        JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        if (!policy.algorithms().contains(algorithm)) {
            throw rejected.apply(messages.algorithm().apply(algorithm));
        }
        String issuer = claims.getIssuer();
        if (issuer == null || !issuers.containsKey(issuer)) {
            throw rejected.apply(messages.unknownIssuer().apply(issuer));
        }
        issuerCheck.accept(issuer, claims);
        String keyId = jwt.getHeader().getKeyID();
        if (keyId == null || (policy.rejectBlankKid() && keyId.isBlank())) {
            throw rejected.apply(messages.missingKid());
        }
        verifier.verify(jwt, issuer, keyId);

        if (!List.of(audience).equals(claims.getAudience())) {
            MockPayer.HttpError error = rejected.apply(
                    "aud must be exactly '" + audience + "', got " + claims.getAudience());
            throw audienceFault ? error.fault(Fault.WRONG_AUDIENCE_REJECT) : error;
        }

        Instant expiry = checkTimes(claims, expiredFault);

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw rejected.apply(messages.missingJti());
        }
        // Times are checked before the jti is recorded, so a refused assertion never occupies the cache. This sweep
        // keeps the map tidy on every accepted assertion; a payer may also call sweepExpired on a timer.
        sweepExpired();
        if (usedJtis.putIfAbsent(issuer + "|" + jti, expiry) != null) {
            throw rejected.apply(messages.replay().apply(jti));
        }
        return issuer;
    }

    /** @return the assertion's exp, once every time rule passed */
    private Instant checkTimes(JWTClaimsSet claims, boolean expiredFault) {
        Instant now = clock.instant();
        if (claims.getExpirationTime() == null) {
            throw rejected.apply(messages.missingExp());
        }
        IssuedAtRule issuedAt = policy.issuedAt();
        if (issuedAt != null && claims.getIssueTime() == null) {
            throw rejected.apply(issuedAt.missing());
        }
        Instant expiry = claims.getExpirationTime().toInstant();
        if (expiredFault) {
            throw rejected.apply(messages.forcedExpired()).fault(Fault.EXPIRED_TOKEN_401);
        }
        if (!now.isBefore(expiry)) {
            throw rejected.apply(messages.expired().apply(expiry));
        }
        ExpiryCap cap = policy.expiryCap();
        if (cap != null && expiry.isAfter(now.plus(cap.max()))) {
            throw rejected.apply(cap.message());
        }
        if (issuedAt != null) {
            Instant issued = claims.getIssueTime().toInstant();
            Duration lifetime = Duration.between(issued, expiry);
            if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(issuedAt.maxLifetime()) > 0) {
                throw rejected.apply(issuedAt.lifetime().apply(lifetime));
            }
            // Without this bound a future iat keeps the lifetime short but moves the whole window far ahead of the
            // payer's clock, and its jti would stay cached for as long as that.
            Duration ahead = Duration.between(now, issued);
            if (ahead.compareTo(issuedAt.maxAhead()) > 0) {
                throw rejected.apply(issuedAt.ahead().apply(ahead));
            }
        }
        return expiry;
    }

    /** Drops every jti whose exp has passed on the payer's clock. */
    void sweepExpired() {
        Instant now = clock.instant();
        usedJtis.values().removeIf(seenExpiry -> !now.isBefore(seenExpiry));
    }

    /** The jtis held against replay, for tests. */
    int replayCacheSize() {
        return usedJtis.size();
    }
}
