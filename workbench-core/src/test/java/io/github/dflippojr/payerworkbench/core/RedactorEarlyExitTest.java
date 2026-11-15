package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * The classes the security rounds 3 to 6 on #356 found (#360): each left a JWK private member's value unmasked where the
 * reading of a text stopped before it was complete. The rule they share: whenever reading a text stops early (an exit, a
 * skip, a cut-off, a budget, an exception or an ambiguous reading), the whole text is masked. Each grid crosses all eight
 * private members, both boundaries (a private member's name, or its value, right where the stop happens), every
 * separator or delimiter spelling, and the text bare and stringified one to three levels, plus in turn one level below,
 * at and one past {@link Redactor#NESTED_LEVELS}. Each case checks that no character of the secret is left in the output,
 * not only that a mask is there. replay/test/leaks.test.mjs builds the same grids and checks the leak scanner flags every
 * input and accepts every output.
 */
class RedactorEarlyExitTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A dummy secret whose letters appear nowhere else in the texts below, nor in the mask. */
    private static final String SECRET = "JGVWXZJGVWXZ";

    private static final List<String> MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "k", "oth");

    private static final String B = String.valueOf((char) 92);

    /** A quote spelled as a unicode escape. */
    private static final String U = B + "u0022";

    /** A quote spelled as a unicode escape whose backslash is itself a unicode escape. */
    private static final String CHAIN = B + "u005cu0022";

    /** Every line separator spelling: raw, escaped once, and as unicode escapes. */
    static List<String> separators() {
        return List.of("\n", "\r", "\r\n", " ", " ", "\u0085", B + "n", B + "r", B + "r" + B + "n",
                B + "u000a", B + "u000d", B + "u2028", B + "u2029", B + "u0085");
    }

    /** Every JSON delimiter spelled as a unicode escape, in both hex cases, through an escaped backslash, and doubled. */
    static List<String> delimiters() {
        List<String> out = new ArrayList<>();
        for (char c : new char[] {',', ':', '{', '}', '[', ']', '"'}) {
            String hex = String.format("%04x", (int) c);
            out.add(B + "u" + hex);
            out.add(B + "u" + hex.toUpperCase(java.util.Locale.ROOT));
            out.add(B + "u005cu" + hex);
            out.add(B + B + "u" + hex);
        }
        return out;
    }

    /** Round 3: a quote reading that is ambiguous, so which object owns a private member is not decided. */
    static List<String> round3() {
        return round3(notes(), MEMBERS);
    }

    /** The earlier ordinary strings round 3 puts before the private member, each holding an escaped quote and delimiters. */
    static List<String> notes() {
        return List.of("{\"note\":\"x" + B + "\":}\",", "{\"note\":\"" + B + "\"}\",", "{\"note\":\"x" + B + "\",{\",",
                "{\"note\":\"x" + B + "\":[\",");
    }

    static List<String> round3(List<String> notes, List<String> members) {
        List<String> texts = new ArrayList<>();
        for (String note : notes) {
            for (String m : members) {
                texts.add(note + "\"" + m + U + ":" + U + SECRET + B + "\"," + B + "\"kty\":\"oct\"}");
                texts.add(note + B + "\"" + m + U + ":\"" + SECRET + U + ",\"kty\":\"oct\"}");
                texts.add(note + "\"" + m + B + "\":" + U + SECRET + B + "\"," + B + "\"kty\":\"oct\"}");
                texts.add(note + CHAIN + m + U + ":\"" + SECRET + "\",\"kty\":\"oct\"}");
            }
        }
        for (String m : members) {
            // Escaped quotes in an ordinary string that, read as quotes, close its object before the member.
            texts.add("{\"kty\":\"oct\",\"a\":{\"note\":\"x" + B + "\"}," + B + "\"y" + B + "\":" + B + "\"z\",\"" + m
                    + "\":\"" + SECRET + "\"}}");
        }
        return texts;
    }

    /** Round 4: a prose skip that starts at a line separator in an earlier string, with the private member after it. */
    static List<String> round4() {
        return round4(separators(), spaces(), MEMBERS);
    }

    /** Whitespace before a name spelled as an escape, also with its backslash spelled as one. */
    static List<String> spaces() {
        return List.of(B + "u0020", B + "u0009", B + B + "u0020", B + "u005c" + B + "u2003", B + "u005cn",
                B + "u005c" + B + "u005ct", B + "u005cu0020", B + B + "u005cr");
    }

    static List<String> round4(List<String> separators, List<String> spaces, List<String> members) {
        List<String> texts = new ArrayList<>();
        for (String sep : separators) {
            String note = "{\"note\":\"a" + sep + "b\",";
            for (String m : members) {
                texts.add(note + "\"" + m + U + ":" + U + SECRET + B + "\"," + B + "\"kty\":\"oct\"}");
                texts.add(note + B + "\"" + m + U + ":\"" + SECRET + U + ",\"kty\":\"oct\"}");
                // The private member opening right after the separator, behind a comma or a brace.
                String name = sep + U + m + U + ":\"" + SECRET + "\"";
                texts.add("{\"kty\":\"oct\",\"note\":\"x" + U + "," + name + "}");
                texts.add("{\"kty\":\"oct\",\"note\":\"x" + U + "{" + name + "}");
                texts.add("{\"note\":\"x" + U + "," + name + "," + U + "kty" + U + ":\"oct\"}");
            }
        }
        for (String space : spaces) {
            for (String m : members) {
                texts.add("{\"note\":\"a\nb\"," + space + "\"" + m + U + ":" + U + SECRET + B + "\"," + B
                        + "\"kty\":\"oct\"}");
            }
        }
        return texts;
    }

    /**
     * Round 5: the same boundary at a stop inside stringified text: the comma before a private member's name lost with
     * the skipped stretch, or the name inside the stretch and the value outside it; the kty before or after.
     */
    static List<String> round5() {
        return round5(separators(), MEMBERS);
    }

    static List<String> round5(List<String> separators, List<String> members) {
        List<String> texts = new ArrayList<>();
        String e = B + "\"";
        for (String sep : separators) {
            String note = "\"note\":" + e + "a" + sep + "b, ";
            for (String m : members) {
                String atName = "\"" + m + "\": \"" + SECRET + "\"";
                String atValue = e + m + e + ": \"" + SECRET + "\"";
                texts.add("{\"kty\":\"oct\"," + note + atName + "}");
                texts.add("{\"kty\":\"oct\"," + note + atValue + "}");
                texts.add("{" + note + atName + ", \"kty\":\"oct\"}");
                texts.add("{" + note + atValue + ", \"kty\":\"oct\"}");
            }
        }
        return texts;
    }

    /**
     * Round 6: a delimiter spelled as an escape where no string is open to decode it, so the reading is ambiguous; the
     * private member's name, or its value, just past that span; the kty before or after.
     */
    static List<String> round6() {
        return round6(delimiters(), MEMBERS);
    }

    static List<String> round6(List<String> delimiters, List<String> members) {
        List<String> texts = new ArrayList<>();
        for (String delimiter : delimiters) {
            for (String m : members) {
                texts.add("{\"kty\":\"oct\",\"x\":1" + delimiter + "\"" + m + "\":\"" + SECRET + "\"}");
                texts.add("{\"kty\":\"oct\",\"x\":\"y\"" + delimiter + "\"" + m + "\":\"" + SECRET + "\"}");
                texts.add("{\"kty\":\"oct\",\"" + m + "\"" + delimiter + "\"" + SECRET + "\"}");
                texts.add("{\"x\":1" + delimiter + CHAIN + m + U + ":\"" + SECRET + "\nX\",\"kty\":\"oct\"}");
                texts.add("{\"" + m + "\"" + delimiter + "\"" + SECRET + "\",\"kty\":\"oct\"}");
                texts.add("{\"x\":\"y\"" + delimiter + U + m + U + ":" + U + SECRET + U + ",\"kty\":\"oct\"}");
            }
        }
        return texts;
    }

    /** {@code text} as the value of a JSON string member, escaped as a serializer escapes it. */
    private static String nested(String text) {
        return "{\"body\":" + JSON.writeValueAsString(text) + "}";
    }

    /**
     * {@code text} bare and stringified one to three levels; and for every fifth {@code index}, at one level of the band
     * around the levels the Redactor reads (one below, at, and one past {@link Redactor#NESTED_LEVELS}) in turn, so the
     * cases of a grid cover every shape, member, spelling and level of that band between them.
     */
    private static List<String> levels(String text, int index) {
        List<String> forms = new ArrayList<>();
        int last = index % 5 == 0 ? Redactor.NESTED_LEVELS - 1 + index / 5 % 3 : 3;
        String form = text;
        for (int depth = 0; depth <= last; depth++) {
            if (depth <= 3 || depth == last) {
                forms.add(form);
            }
            form = depth < last ? nested(form) : form;
        }
        return forms;
    }

    /** No character of the secret is left in what the Redactor makes of {@code in}, and that is the mask. */
    private static void assertMaskedWhole(String in, String label) {
        String out = Redactor.redact(in);
        for (char c : SECRET.toCharArray()) {
            assertTrue(out.indexOf(c) < 0, () -> label + ": a character of the secret is left");
        }
        // Not assertEquals: a failure message would print the output, and with it the input's spelling.
        assertTrue(Redactor.MASK.equals(out), () -> label + ": not the mask alone");
    }

    private static void assertGrid(String round, List<String> texts) {
        for (int i = 0; i < texts.size(); i++) {
            List<String> forms = levels(texts.get(i), i);
            for (int f = 0; f < forms.size(); f++) {
                assertMaskedWhole(forms.get(f), round + " case " + i + " form " + f);
            }
        }
    }

    @Test
    void masksTheWholeTextWhereAnAmbiguousQuoteReadingLeavesAPrivateMembersObjectUndecided() {
        assertGrid("round 3", round3());
    }

    @Test
    void masksTheWholeTextWhereAProseSkipStartsAtALineSeparatorBeforeAPrivateMember() {
        assertGrid("round 4", round4());
    }

    @Test
    void masksTheWholeTextWhereASkipInStringifiedTextEndsAtAPrivateMembersNameOrValue() {
        assertGrid("round 5", round5());
    }

    @Test
    void masksTheWholeTextWhereAnEscapedDelimiterOutsideAStringPrecedesAPrivateMembersNameOrValue() {
        assertGrid("round 6", round6());
    }

    /**
     * Every spelling with one member, and every member with one spelling, in every shape of each class: so each spelling,
     * member and shape runs at every level, 0 to one past {@link Redactor#NESTED_LEVELS}.
     */
    static List<List<String>> sweeps() {
        List<String> d = List.of("d");
        List<List<String>> sweeps = new ArrayList<>();
        sweeps.add(join(round3(notes(), d), round3(notes().subList(0, 1), MEMBERS)));
        sweeps.add(join(round4(separators(), spaces(), d), round4(separators().subList(0, 1), spaces().subList(0, 1), MEMBERS)));
        sweeps.add(join(round5(separators(), d), round5(separators().subList(0, 1), MEMBERS)));
        sweeps.add(join(round6(delimiters(), d), round6(delimiters().subList(0, 1), MEMBERS)));
        return sweeps;
    }

    private static List<String> join(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        b.stream().filter(text -> !out.contains(text)).forEach(out::add);
        return out;
    }

    @Test
    void masksEverySpellingMemberAndShapeOfEachClassAtEveryLevelUpToAndOnePastTheBound() {
        List<List<String>> sweeps = sweeps();
        for (int round = 0; round < sweeps.size(); round++) {
            List<String> texts = sweeps.get(round);
            for (int i = 0; i < texts.size(); i++) {
                String form = texts.get(i);
                for (int depth = 0; depth <= Redactor.NESTED_LEVELS + 1; depth++) {
                    assertMaskedWhole(form, "round " + (round + 3) + " sweep case " + i + " at level " + depth);
                    form = nested(form);
                }
            }
        }
    }

    @Test
    void readsAMaskedJwkCompletelyWithinTheLevelsReadAndMasksItWholeAtTheLastLevel() {
        // Levels 0 to NESTED_LEVELS - 1 are read canonically: a masked JWK there is kept as it is, and an unmasked one has
        // its private member masked in place. A JWK that needs reading at the last level or past it is masked whole.
        String masked = "{\"kty\":\"oct\",\"k\":\"[REDACTED]\"}";
        String leaked = "{\"kty\":\"oct\",\"k\":\"" + SECRET + "\"}";
        String maskedForm = masked;
        String leakedForm = leaked;
        for (int depth = 0; depth < Redactor.NESTED_LEVELS; depth++) {
            assertEquals(maskedForm, Redactor.redact(maskedForm), "masked, level " + depth);
            assertEquals(maskedForm, Redactor.redact(leakedForm), "leaked, level " + depth);
            maskedForm = nested(maskedForm);
            leakedForm = nested(leakedForm);
        }
        assertEquals(Redactor.MASK, Redactor.redact(maskedForm));
        assertEquals(Redactor.MASK, Redactor.redact(leakedForm));
        assertEquals(Redactor.MASK, Redactor.redact(nested(maskedForm)));
    }

    @Test
    void readsEveryMemberOfAJwkARepeatedNameToo() {
        // A repeated name is read each time: none of its values may hold the secret, whichever comes last.
        for (String text : List.of("{\"kty\":\"oct\",\"k\":\"" + SECRET + "\",\"k\":\"[REDACTED]\"}",
                "{\"kty\":\"oct\",\"k\":\"[REDACTED]\",\"k\":\"" + SECRET + "\"}")) {
            for (String form : List.of(text, nested(text), nested(nested(text)))) {
                assertMaskedLeavingNoSecret(form);
            }
        }
        assertTrue(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":\"[REDACTED]\",\"k\":\"[REDACTED]\"}"));
        assertFalse(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":\"x\",\"k\":\"[REDACTED]\"}"));
        assertFalse(WholeTextGuard.readsMasked("{\"k\":\"[REDACTED]\",\"k\":7,\"kty\":\"oct\"}"));
        assertFalse(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":{\"x\":1}}"));
        // A null holds nothing; a number or a boolean may be the secret.
        assertTrue(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":null}"));
        assertFalse(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":12345}"));
        assertFalse(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":true}"));
        // Only the JWK's own members: a private name in an object without a kty is ordinary.
        assertTrue(WholeTextGuard.readsMasked("{\"kty\":\"oct\",\"k\":\"[REDACTED]\",\"a\":{\"d\":\"x\"}}"));
        assertTrue(WholeTextGuard.readsMasked("[{\"d\":\"x\"},{\"kty\":\"RSA\",\"d\":\"[REDACTED]\"}]"));
    }

    /** No character of the secret is left in what the Redactor makes of {@code in}. */
    private static void assertMaskedLeavingNoSecret(String in) {
        String out = Redactor.redact(in);
        for (char c : SECRET.toCharArray()) {
            assertTrue(out.indexOf(c) < 0, "a character of the secret is left");
        }
    }

    @Test
    void readsStrictJsonOnly() {
        for (String json : List.of("{}", "[]", " [1, -0.5e+3, true, false, null, \"a\\u00e9\\n\"] ", "{\"a\":{\"b\":[{}]}}", "0",
                "-12.5E-2", "\"\\/\\b\\f\\r\\t\\\\\"")) {
            assertTrue(WholeTextGuard.readsCompletely(json), json);
        }
        for (String text : List.of("", "{", "[1,]", "{\"a\"}", "{\"a\":1,}", "{\"a\" 1}", "01", "1.", "1e", "-", "tru", "nul",
                "[1 2]", "{\"a\":1}x", "\"a\\x\"", "\"\\u12\"", "\"\\u12G4\"", "\"a\nb\"", "\"open", "\"a\\",
                "{1:2}", "[\"a\"}", "{\"a\":1]")) {
            assertFalse(WholeTextGuard.readsCompletely(text), text);
        }
        // A unicode escape takes four ASCII hex digits only: other Unicode digits (fullwidth, Arabic-Indic) are no hex digit.
        for (char digit : new char[] {'\uff10', '\uff41', '\u0660'}) {
            assertFalse(WholeTextGuard.readsCompletely("\"\\u00" + digit + "1\""), () -> Integer.toHexString(digit));
            // Loosely, it is no unicode escape either: the backslash goes, as before any other character.
            assertEquals("u00" + digit + "1", WholeTextGuard.looselyDecoded(B + "u00" + digit + "1"));
        }
        // A string whose content holds a quote at some escape level must be JSON in its turn; one with none need not be.
        assertTrue(WholeTextGuard.readsCompletely("{\"a\":\"x\\\\\\\\y\",\"b\":\"[1,{\\\"c\\\":2}]\"}"));
        assertFalse(WholeTextGuard.readsCompletely("{\"a\":\"say \\\"hi\\\"\"}"));
        assertFalse(WholeTextGuard.readsCompletely("{\"a\":\"x\\\\u0022y\"}"));
    }

    @Test
    void readsDeeplyNestedArraysWithoutRecursion() {
        // An explicit stack: a hundred thousand open brackets read in linear time, with no stack overflow.
        String deep = "{\"kty\":\"oct\",\"k\":\"" + SECRET + "\",\"x\":" + "[".repeat(100_000) + "]".repeat(100_000) + "}";
        String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(deep));
        assertMaskedLeavingNoSecret(deep);
        assertTrue(WholeTextGuard.readsMasked(out));
        assertFalse(WholeTextGuard.readsCompletely("[".repeat(100_000)));
    }

    @Test
    void findsAKtyAndAPrivateNameInAnySpellingAtAnyLevel() {
        String b = B;
        for (String text : List.of("{\"kty\":1,\"d\":2}", "{\"k" + b + "u0074y\":1," + U + "d" + U + ":2}",
                // A name letter whose own escape's u is an escape a level up.
                "{\"kty\":1,\"" + b + "u005c" + b + "u00750064\":2}",
                "{" + b + "u005cu0022kty" + b + "u005cu0022:1," + b + "u005cu0022oth" + b + "u005cu0022:2}")) {
            assertTrue(WholeTextGuard.mayHoldPrivateMember(text), text);
        }
        for (String text : List.of("{\"kty\":1,\"n\":2}", "{\"d\":2}", "{\"kty\":1,\"dpq\":2}", "plain prose with d and kty",
                "{\"kty\":1,\"D\":2}")) {
            assertFalse(WholeTextGuard.mayHoldPrivateMember(text), text);
        }
        // Escapes still left past the levels read: either name is enough.
        String chain = b.repeat(1 << 18);
        assertTrue(WholeTextGuard.mayHoldPrivateMember("kty " + chain));
        assertEquals("a\n\r\t\b\f\"/" + b + "u" + b, WholeTextGuard.looselyDecoded("a" + b + "n" + b + "r" + b + "t" + b + "b" + b + "f"
                + b + "\"" + b + "/" + b + b + b + "u" + b));
        assertEquals("\u00e9xu12", WholeTextGuard.looselyDecoded(b + "u00e9x" + b + "u12"));
    }

    @Test
    void masksTheWholeTextWhereThePassesThemselvesWouldLeaveAPrivateMemberUnmasked() {
        // The last check reads the output: a JWK that reads completely but whose private member the passes do not reach
        // (here a member name the passes read as an ordinary field) is masked whole rather than left.
        String text = "{\"kty\":\"oct\",\"k\":\"" + SECRET + "\"}";
        assertTrue(WholeTextGuard.readsCompletely(text));
        assertFalse(WholeTextGuard.readsMasked(text));
        assertTrue(WholeTextGuard.readsMasked(Redactor.redact(text)));
    }
}
