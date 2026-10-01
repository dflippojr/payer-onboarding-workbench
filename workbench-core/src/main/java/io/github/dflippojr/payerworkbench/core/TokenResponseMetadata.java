package io.github.dflippojr.payerworkbench.core;

import java.util.List;

/**
 * What a token endpoint returned, minus the token itself. The access token
 * value is never stored; only whether one was present.
 *
 * @param accessTokenPresent whether the response contained a non-empty {@code access_token}
 * @param tokenType the {@code token_type}, e.g. {@code Bearer}; may be {@code null}
 * @param expiresInSeconds the {@code expires_in}; {@code null} if absent
 * @param scopes the granted {@code scope}, split on spaces; empty if absent
 * @param error the OAuth2 {@code error} code on failure; {@code null} on success
 * @param errorDescription the OAuth2 {@code error_description}, redacted; may be {@code null}
 */
public record TokenResponseMetadata(
        boolean accessTokenPresent,
        String tokenType,
        Long expiresInSeconds,
        List<String> scopes,
        String error,
        String errorDescription
) {
    public TokenResponseMetadata {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
        errorDescription = Redactor.redact(errorDescription);
    }
}
