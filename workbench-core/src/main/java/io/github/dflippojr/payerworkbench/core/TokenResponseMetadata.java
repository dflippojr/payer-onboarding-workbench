package io.github.dflippojr.payerworkbench.core;

import java.util.List;

/**
 * What a token endpoint returned, minus the token itself. The access token
 * value is never stored; only whether one was present. Every string comes from
 * the payer, so each is cut with {@link TextLimit#cut(String)}, all but the scopes
 * redacted first, and at most {@link #MAX_SCOPES} scopes are kept.
 *
 * @param accessTokenPresent whether the response contained a non-empty {@code access_token}
 * @param tokenType the {@code token_type}, e.g. {@code Bearer}, redacted; may be {@code null}
 * @param expiresInSeconds the {@code expires_in} in seconds; {@code null} if absent or not usable (a
 *                         JSON number or numeric string that is not a positive whole number)
 * @param expiresInSent the {@code expires_in} as the payer sent it, as JSON text (a string keeps its
 *                      quotes, so {@code "300"} tells a string from the number {@code 300}), redacted;
 *                      {@code null} if absent
 * @param scopes the first {@link #MAX_SCOPES} of the granted {@code scope}, split on spaces; empty if absent
 * @param scopesNotShown how many more granted scopes there were
 * @param error the OAuth2 {@code error} code on failure, redacted; {@code null} on success
 * @param errorDescription the OAuth2 {@code error_description}, redacted; may be {@code null}
 */
public record TokenResponseMetadata(
        boolean accessTokenPresent,
        String tokenType,
        Long expiresInSeconds,
        String expiresInSent,
        List<String> scopes,
        int scopesNotShown,
        String error,
        String errorDescription
) {
    /** The most granted scopes kept; a payer may send millions in one 4 MiB {@code scope}. */
    public static final int MAX_SCOPES = 20;

    public TokenResponseMetadata {
        scopes = scopes == null ? List.of() : scopes;
        if (scopes.size() > MAX_SCOPES) {
            scopesNotShown += scopes.size() - MAX_SCOPES;
            scopes = scopes.subList(0, MAX_SCOPES);
        }
        scopes = List.copyOf(scopes.stream().map(TextLimit::cut).toList());
        tokenType = redactedAndCut(tokenType);
        error = redactedAndCut(error);
        errorDescription = redactedAndCut(errorDescription);
        expiresInSent = redactedAndCut(expiresInSent);
    }

    /** Redacts before the final cut; the first cut only bounds the redactor's work. */
    private static String redactedAndCut(String text) {
        return TextLimit.cut(Redactor.redact(TextLimit.cut(text, TextLimit.MAX_FINDING_CHARS)));
    }

    /** Metadata whose {@code scopes} are all the granted scopes and whose {@code expires_in}, if any, was a JSON number. */
    public TokenResponseMetadata(boolean accessTokenPresent, String tokenType, Long expiresInSeconds,
                                 List<String> scopes, String error, String errorDescription) {
        this(accessTokenPresent, tokenType, expiresInSeconds,
                expiresInSeconds == null ? null : expiresInSeconds.toString(), scopes, 0, error, errorDescription);
    }
}
