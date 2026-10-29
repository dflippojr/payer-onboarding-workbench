package io.github.dflippojr.payerworkbench.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** {@link AuthChallenge}: the RFC 9110 §11.2 challenge grammar, and which challenge's parameters win. */
class AuthChallengeTest {

    private static AuthChallenge challenge(String scheme, String... nameValues) {
        Map<String, String> params = new LinkedHashMap<>();
        for (int i = 0; i < nameValues.length; i += 2) {
            params.put(nameValues[i], nameValues[i + 1]);
        }
        return new AuthChallenge(scheme, params);
    }

    @Test
    void quotedValuesAreSkippedWhole() {
        assertEquals(List.of(challenge("Bearer", "error_uri", "https://p.test/help?error=see_docs, scope=x",
                        "error", "invalid_token")),
                AuthChallenge.parse("Bearer error_uri=\"https://p.test/help?error=see_docs, scope=x\", "
                        + "error=\"invalid_token\""));
    }

    @Test
    void escapedQuotesAndBackslashesAreUnescaped() {
        assertEquals(List.of(challenge("Bearer", "error_description", "Rejected \"a, b\" \\ c", "error", "x")),
                AuthChallenge.parse("Bearer error_description=\"Rejected \\\"a, b\\\" \\\\ c\", error=x"));
    }

    @Test
    void namesAreCaseInsensitiveAndTheFirstRepeatWins() {
        assertEquals(List.of(challenge("BEARER", "error", "first", "scope", "s")),
                AuthChallenge.parse("BEARER Error=first,error=second , SCOPE = \"s\""));
    }

    @Test
    void severalChallengesKeepTheirOwnParameters() {
        assertEquals(List.of(challenge("Basic", "realm", "a"), challenge("Bearer", "error", "invalid_token"),
                        challenge("Negotiate"), challenge("Digest", "realm", "d", "qop", "auth,auth-int")),
                AuthChallenge.parse("Basic realm=\"a\", Bearer\terror=\"invalid_token\", Negotiate YII+/a.b-c~d_==, "
                        + "Digest realm=d, qop=\"auth,auth-int\""));
    }

    @Test
    void schemesWithoutParametersAndToken68AreChallenges() {
        assertEquals(List.of(challenge("Negotiate"), challenge("Basic"), challenge("Bearer", "error", "e")),
                AuthChallenge.parse("Negotiate abc=, Basic,Bearer error=e"));
        assertEquals(List.of(challenge("Negotiate")), AuthChallenge.parse("Negotiate abc== "));
        assertEquals(List.of(challenge("Negotiate")), AuthChallenge.parse("Negotiate abc"));
        assertEquals(List.of(challenge("Bearer", "realm", "")), AuthChallenge.parse("Bearer realm=\"\""));
        assertEquals(List.of(challenge("Bearer", "realm", "a", "error", "")),
                AuthChallenge.parse("Bearer realm=a, error="));
        assertEquals(List.of(challenge("Bearer", "error", "e"), challenge("Basic")),
                AuthChallenge.parse("Bearer error=e, Basic"));
    }

    @Test
    void parametersBeforeAnySchemeBelongToAnUnnamedChallenge() {
        assertEquals(List.of(challenge("", "error", "invalid_token")), AuthChallenge.parse("error=invalid_token"));
    }

    @Test
    void malformedElementsAreSkippedToTheNextComma() {
        assertEquals(List.of(challenge("Bearer", "error", "x", "scope", "s")),
                AuthChallenge.parse("Bearer error=x junk \"a, b\" more, @@ \"c, d\", scope=s, ="));
        assertEquals(List.of(challenge("Bearer", "error", "unterminated, scope=s")),
                AuthChallenge.parse("Bearer error=\"unterminated, scope=s"));
        assertEquals(List.of(challenge("Bearer", "error", "\\")), AuthChallenge.parse("Bearer error=\"\\"));
        assertEquals(List.of(), AuthChallenge.parse(""));
        assertEquals(List.of(), AuthChallenge.parse(" , \t"));
    }

    @Test
    void nonAsciiLettersAreNotTokenCharacters() {
        assertEquals(List.of(challenge("Bearer", "error", "x")), AuthChallenge.parse("Bearer é=1, error=x"));
        assertEquals(List.of(challenge("Bearer", "x~", "1", "!a", "2", "error", "x")),
                AuthChallenge.parse("Bearer x~=1, !a=2, \u007f=3, error=x"));
        assertEquals(List.of(challenge("Negotiate", "error", "x")), AuthChallenge.parse("Negotiate é, error=x"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "Basic realm=\"a\", scope=b, Bearer error=\"invalid_token\", scope=c|error|invalid_token",
        "Basic realm=\"a\", scope=b, Bearer error=\"invalid_token\", scope=c|scope|c",
        "Basic realm=\"a\", scope=b, Bearer error=\"invalid_token\"|scope|",
        "Basic realm=\"a\", Bearer scope=b, Digest scope=c|scope|b",
        "Basic realm=\"a\", Bearer scope=b|error|",
        "Bearer myscope=\"x\", suberror=y, scope=\"system/*.read\"|SCOPE|system/*.read"})
    void parametersComeFromTheFirstChallengeCarryingAnError(String header, String name, String expected) {
        assertEquals(Optional.ofNullable(expected), AuthChallenge.param(AuthChallenge.parse(header), name));
    }
}
