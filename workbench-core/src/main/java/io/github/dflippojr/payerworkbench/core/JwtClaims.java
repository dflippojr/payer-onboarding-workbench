package io.github.dflippojr.payerworkbench.core;

import java.time.Instant;
import java.util.List;

/**
 * The non-secret claims of a JWT the workbench sent, for checks that cannot read
 * them from the recorded request (a bearer JWT in an {@code Authorization} header
 * is masked whole by {@link Redactor}). Never holds the token, its encoded parts
 * or its signature.
 *
 * @param iss the {@code iss} claim; may be {@code null}
 * @param aud the {@code aud} claim, as a list even when the JWT has a single string
 * @param exp the {@code exp} claim; may be {@code null}
 * @param iat the {@code iat} claim; may be {@code null}
 * @param jti the {@code jti} claim; may be {@code null}
 * @param kid the {@code kid} header parameter; may be {@code null}
 */
public record JwtClaims(
        String iss,
        List<String> aud,
        Instant exp,
        Instant iat,
        String jti,
        String kid
) {
    public JwtClaims {
        aud = aud == null ? List.of() : List.copyOf(aud);
    }
}
