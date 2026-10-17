package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class TokenResponseMetadataTest {

    @Test
    void cutsEveryPayerStringAndKeepsTheFirstScopes() {
        String huge = "x".repeat(1_000_000);
        TokenResponseMetadata token = new TokenResponseMetadata(true, "Bearer" + huge, 300L,
                Collections.nCopies(25, huge), 7, huge, "client_secret=" + huge);

        String cut = "x".repeat(TextLimit.MAX_CHARS) + TextLimit.ELLIPSIS;
        assertEquals(("Bearer" + huge).substring(0, TextLimit.MAX_CHARS) + TextLimit.ELLIPSIS, token.tokenType());
        assertEquals(cut, token.error());
        assertEquals(TokenResponseMetadata.MAX_SCOPES, token.scopes().size());
        assertEquals(cut, token.scopes().getFirst());
        assertEquals(7 + 25 - TokenResponseMetadata.MAX_SCOPES, token.scopesNotShown());
        assertFalse(token.errorDescription().contains("xxxx"), token.errorDescription());
    }

    @Test
    void shortValuesStayWhole() {
        TokenResponseMetadata token = new TokenResponseMetadata(true, "Bearer", 300L, List.of("system/*.read"),
                null, "try again");
        assertEquals("Bearer", token.tokenType());
        assertEquals(List.of("system/*.read"), token.scopes());
        assertEquals(0, token.scopesNotShown());
        assertEquals("try again", token.errorDescription());
    }
}
