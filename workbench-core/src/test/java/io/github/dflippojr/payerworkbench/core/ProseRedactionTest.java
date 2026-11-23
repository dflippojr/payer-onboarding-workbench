package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * The structural path for text that is not one JSON value (#406, #377 stage 2): each JSON value embedded in it is read
 * on the tree, a JSON-looking start that does not read masks to the end when secret vocabulary follows, the text rules
 * read only the rest, and every decoding of the result must be settled. Everything here is synthetic.
 */
class ProseRedactionTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** The text inside a JSON string {@code levels} levels deep, each level the {@code body} of an object. */
    private static String nested(String text, int levels) {
        String out = text;
        for (int i = 0; i < levels; i++) {
            out = JSON.writeValueAsString(Map.of("body", out));
        }
        return out;
    }

    @Test
    void redactsEachJsonValueEmbeddedInProseOnTheTreeAndKeepsTheProseAroundIt() {
        assertEquals("payer said: {\"password\":\"[REDACTED]\",\"n\":1} then [1,2] and {\"a\":\"A\"} done",
                Redactor.redact("payer said: {\"password\":\"s3cr3t\",\"n\":1} then [1,2] and {\"a\":\"\\u0041\"} done"));
        // A JWK's private member, a scheme credential and a key block in a value, each as on the tree.
        assertEquals("keys: {\"kty\":\"oct\",\"k\":\"[REDACTED]\"}; auth {\"h\":\"Bearer [REDACTED]\"}; {\"pem\":\"[REDACTED]\"}",
                Redactor.redact("keys: {\"kty\":\"oct\",\"k\":\"FAKEK\"}; auth {\"h\":\"Bearer 9f8a7b6c5d4e\"};"
                        + " {\"pem\":\"-----BEGIN PRIVATE KEY-----\\nFAKEKEY\\n-----END PRIVATE KEY-----\"}"));
        // Brackets that start no JSON value are prose.
        assertEquals("[INFO] {code} ok", Redactor.redact("[INFO] {code} ok"));
        // The same text held in a JSON string, at every level the tree path reads.
        for (int levels = 1; levels < JsonRedaction.MAX_LEVELS; levels++) {
            String text = nested("payer said: {\"password\":\"s3cr3t\"} done", levels);
            String out = Redactor.redact(text);
            assertFalse(out.contains("s3cr3t"), out);
            assertEquals(nested("payer said: {\"password\":\"[REDACTED]\"} done", levels), out);
        }
    }

    @Test
    void masksAnEmbeddedValueThatASecretNameFormKeyOrHeaderLineBeforeItMakesASecretOne() {
        // The value reads on the tree, where it holds no secret name; the text around it makes it one. Shapes x value
        // kinds x where the line starts x levels: the inner bytes are gone from every output.
        List<String> shapes = List.of("\"password\": %s", "\\\"password\\\": %s", "password=%s", "client_secret=%s&x=1",
                "Cookie: %s", "Authorization: %s", "\"x-api-key\":%s", "\"kty\":\"oct\",\"k\": %s",
                "\\\"kty\\\":\\\"oct\\\",\\\"d\\\":%s");
        List<String> values = List.of("{\"v\":\"INNERVAL\"}", "[\"INNERVAL\",{\"w\":\"INNERVAL\"}]", "{ \"v\" : [ \"INNERVAL\" ] }");
        List<String> missed = new ArrayList<>();
        int cases = 0;
        for (String shape : shapes) {
            for (String value : values) {
                for (String before : List.of("", "note\n")) {
                    for (int levels = 0; levels <= 2; levels++) {
                        String text = nested(before + shape.formatted(value) + " tail", levels);
                        cases++;
                        if (Redactor.redact(text).contains("INNERVAL")) {
                            missed.add(text);
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), missed, missed.size() + " of " + cases);
        // A header name in the middle of a line is prose, as before (#262): the value after it is the tree's alone.
        assertEquals("log: Cookie: {\"v\":\"kept\"}", Redactor.redact("log: Cookie: {\"v\":\"kept\"}"));
    }

    @Test
    void masksFromAJsonLookingStartThatDoesNotReadToTheEndWhenSecretVocabularyFollows() {
        assertEquals("error [REDACTED]", Redactor.redact("error {\"password\": oops"));
        // Spelled with an escape, and in a value that reads after the start.
        assertEquals("x [REDACTED]", Redactor.redact("x {\"p\\u0061ssword\": oops"));
        assertEquals("x [REDACTED]", Redactor.redact("x {\"a\": oops} then {\"client_secret\":\"s3cr3t\"}"));
        // A credential the text rules would mask counts as vocabulary too.
        assertEquals("x [REDACTED]", Redactor.redact("x [\"a\" oops Bearer 9f8a7b6c5d4e"));
        // No vocabulary after it: kept as it is.
        assertEquals("error {\"note\": oops} and more", Redactor.redact("error {\"note\": oops} and more"));
        // A bracket that does not look like JSON is not such a start, whatever follows it.
        assertEquals("see {code} and [INFO] password", Redactor.redact("see {code} and [INFO] password"));
        // A value whose names repeat does not read: with no vocabulary it is kept as it is spelled.
        assertEquals("x {\"a\":1,\"a\":\"\\u0041\"} y", Redactor.redact("x {\"a\":1,\"a\":\"\\u0041\"} y"));
        assertEquals("x [REDACTED]", Redactor.redact("x {\"a\":1,\"a\":2,\"secret\":3} y"));
    }

    @Test
    void masksTheRestOfAFragmentWhoseSecretValueClosesEarlyBeforeMoreBytes() {
        // Automated review round 1 on #408: in prose with no brace, a secret value whose quote closes before more of its
        // bytes was masked only up to that quote. Main masked from the colon on; so does the head, plain, one level deep,
        // after a scheme kept and before a value the rules mask as a whole string.
        for (String text : List.of("note \"password\":\"abc\"defSECRETTAIL more", "note \"password\": \"abc\"defSECRETTAIL",
                "note \\\"password\\\":\\\"abc\\\"defSECRETTAIL more", "note \"authorization\":\"Bearer abc\"defSECRETTAIL",
                "note \"password\":123SECRETTAIL x", "line\n\"client_secret\":\"\"SECRETTAIL\"")) {
            String out = Redactor.redact(text);
            assertFalse(out.contains("SECRETTAIL"), () -> text + " => " + out);
        }
        // #406 decisions (stage 2): a value that was not already masked masks from the colon on even where it ends at a
        // strict value end, as main did (on dcfa2f5 what followed it was kept); an already-masked one keeps what follows.
        assertEquals("note \"password\":\"[REDACTED]\"", Redactor.redact("note \"password\":\"abc\", \"n\":1 tail"));
        assertEquals("note \"password\":\"[REDACTED]\", \"n\":1 tail", Redactor.redact("note \"password\":\"[REDACTED]\", \"n\":1 tail"));
    }

    @Test
    void aFragmentValueCountsAsMaskedOnlyInAFormTheRulesWriteAtAStrictValueEnd() {
        // #406 decisions (stage 2), closing the review family of rounds 1 to 3 on #408 and #409: in prose with no brace, a
        // secret name's value is taken as already masked only when the ORIGINAL text, before any rule rewrites it, holds
        // exactly a form the rules write (the mask, a kept scheme and the mask, or null), quoted as its name is, followed
        // by the end, whitespace, a comma or a closing bracket. Anything else masks from the colon to the end, separator
        // or not. Grid: value start x suffix x depth (plain, one level deep, each inside a JSON string) x name class.
        record Name(String prefix, String name, List<String> starts) {}
        List<String> plainStarts = List.of("\"[REDACTED]\"", "null", "\"abc\"", "123", "true", "\"\"");
        List<String> schemeStarts = new ArrayList<>(plainStarts);
        schemeStarts.addAll(List.of("\"Bearer [REDACTED]\"", "\"Bearer abc\"", "\"Token [REDACTED]\""));
        List<String> masked = List.of("\"[REDACTED]\"", "null", "\"Bearer [REDACTED]\"", "\"Token [REDACTED]\"");
        List<Name> names = List.of(new Name("note ", "password", plainStarts),
                new Name("note ", "client_secret", plainStarts), new Name("note ", "authorization", schemeStarts),
                new Name("note \"kty\":\"RSA\", ", "d", plainStarts));
        List<String> suffixes = List.of("SECRETTAIL", "7SECRETTAIL", ".SECRETTAIL", "-SECRETTAIL", "_SECRETTAIL",
                ":SECRETTAIL", "\"SECRETTAIL", "'SECRETTAIL", "\\SECRETTAIL", "\\nSECRETTAIL", "\\\\SECRETTAIL",
                "\\\"SECRETTAIL", "\\u0041SECRETTAIL", "/SECRETTAIL", "+SECRETTAIL", "=SECRETTAIL");
        // Separators: a strict value end, then more bytes. They are kept only after a value that already was masked.
        List<String> separators = List.of(" SECRETTAIL", ", SECRETTAIL", ",SECRETTAIL", "\tSECRETTAIL", "\nSECRETTAIL",
                "}SECRETTAIL", "] SECRETTAIL", "  , SECRETTAIL");
        List<String> failures = new ArrayList<>();
        int cases = 0;
        for (boolean inString : new boolean[] {false, true}) {
            for (boolean embedded : new boolean[] {false, true}) {
                String q = embedded ? "\\\"" : "\"";
                for (Name n : names) {
                    String prefix = embedded ? n.prefix().replace("\"", "\\\"") : n.prefix();
                    for (String start : n.starts()) {
                        String value = embedded ? start.replace("\"", "\\\"") : start;
                        for (String suffix : concat(suffixes, separators)) {
                            String fragment = prefix + q + n.name() + q + ":" + value + suffix + " more";
                            String text = inString ? JSON.writeValueAsString(Map.of("msg", fragment)) : fragment;
                            String out = Redactor.redact(text);
                            cases++;
                            boolean keeps = masked.contains(start) && separators.contains(suffix);
                            if (keeps ? !out.contains("SECRETTAIL") : out.contains("SECRETTAIL") || out.contains("more")) {
                                failures.add((keeps ? "kept form changed: " : "") + text + " => " + out);
                            }
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), failures, () -> failures.size() + " grid texts kept bytes after the value");
        assertTrue(cases > 1500, "grid size " + cases);
        // The masked forms at a strict value end keep what follows them, plain and one level deep.
        for (String end : List.of("", " tail", ", \"n\":1", "} tail", "] tail", "\ttail", "\ntail")) {
            for (String form : List.of("\"password\":\"[REDACTED]\"", "\"password\": null", "\"authorization\":\"Bearer [REDACTED]\"",
                    "\\\"password\\\":\\\"[REDACTED]\\\"", "\\\"authorization\\\":\\\"Token [REDACTED]\\\"")) {
                String text = "note " + form + end;
                assertEquals(text, Redactor.redact(text), text);
            }
        }
    }

    @Test
    void masksAJwtWholeWhenADecodedClaimInItsHeaderOrPayloadIsSecretBearing() {
        // #406 decision (stage 2): the option-A keep of a JWT's header and payload applies only where no decoded claim is
        // secret-bearing. Claims are generated at runtime, so no fixed token can satisfy the test by accident.
        java.util.Random rnd = new java.util.Random();
        String secret = "FAKE-CLAIM-" + Long.toString(rnd.nextLong() & Long.MAX_VALUE, 36);
        List<String> claims = List.of("{\"client_secret\":\"" + secret + "\"}", "{\"sub\":\"x\",\"password\":\"" + secret + "\"}",
                "{\"ctx\":{\"apiKey\":\"" + secret + "\"}}", "{\"jwk\":{\"kty\":\"RSA\",\"d\":\"" + secret + "\"}}",
                "{\"note\":\"Bearer " + secret + "\"}", "{\"body\":\"{\\\"access_token\\\":\\\"" + secret + "\\\"}\"}",
                "{\"pem\":\"-----BEGIN PRIVATE KEY-----\\n" + secret + "\\n-----END PRIVATE KEY-----\"}");
        String plainHeader = base64Url("{\"alg\":\"none\"}");
        String harmless = base64Url("{\"sub\":\"user-" + rnd.nextInt(1000) + "\"}");
        List<String> failures = new ArrayList<>();
        for (String claim : claims) {
            for (boolean inHeader : new boolean[] {false, true}) {
                String header = inHeader ? base64Url("{\"alg\":\"none\"," + claim.substring(1)) : plainHeader;
                String jwt = header + "." + (inHeader ? harmless : base64Url(claim)) + ".FAKESIG" + rnd.nextInt(1000);
                for (String text : jwtContexts(jwt)) {
                    String out = Redactor.redact(text);
                    if (leaksAtAnyDecoding(out, secret)) {
                        failures.add(claim + (inHeader ? " in header: " : " in payload: ") + text + " => " + out);
                    }
                }
            }
        }
        // The same token cut short: no signature, an empty one, no payload; and spelled with unicode escapes in a cut body.
        for (String claim : claims) {
            String header = plainHeader + "." + base64Url(claim);
            String claimHeader = base64Url("{\"alg\":\"none\"," + claim.substring(1));
            for (String jwt : List.of(header + ".", header, claimHeader, claimHeader + "." + harmless + ".",
                    claimHeader + "." + harmless)) {
                String respelled = jwt.replace("y", "\\u0079").replace("J", "\\u004A");
                for (String text : List.of("x " + jwt + " y", "{\"jwt\":\"" + jwt + "\",\"n\":1}",
                        "{\"a\":\"plain words\",\"jwt\":\"" + respelled + "\",\"b\":\"\\u")) {
                    String out = Redactor.redact(text);
                    if (leaksAtAnyDecoding(out, secret)) {
                        failures.add(claim + " cut short: " + text + " => " + out);
                    }
                }
            }
        }
        assertEquals(List.of(), failures, () -> failures.size() + " JWT texts kept a secret-bearing claim");
        // A JWT whose claims hold no secret keeps its header and payload, the signature masked, in every context.
        String jwt = plainHeader + "." + harmless + ".FAKESIG";
        for (String text : jwtContexts(jwt)) {
            String out = Redactor.redact(text);
            assertTrue(out.contains(plainHeader + "." + harmless + ".") && !out.contains("FAKESIG"), () -> text + " => " + out);
        }
    }

    @Test
    void fuzzTextsWithCredentialClaimsInTheirJwtsKeepNoSecretAtAnyDecoding() {
        // #406 decision (stage 2): the fuzz families, with every JWT carrying a claim drawn at runtime (a secret-named
        // claim, a JWK private member, a scheme credential, a key block or JSON in a string holding one, or a harmless
        // claim), in the payload or the header. No synthetic secret may survive in the output at any decoding of its
        // escapes or of its base64url tokens.
        long seed = System.nanoTime();
        List<String> failures = new ArrayList<>();
        for (String text : FuzzCorpus.textsWithClaims(seed, 3_000)) {
            String out = Redactor.redact(text);
            if (leaksAtAnyDecoding(out, "FAKE-FUZZ")) {
                failures.add(text + " => " + out);
            }
        }
        assertEquals(List.of(), failures.subList(0, Math.min(5, failures.size())),
                () -> failures.size() + " of 3000 fuzz texts kept a secret (seed " + seed + ")");
    }

    /** {@code jwt} in prose, as a JSON value, in a JSON value in prose, inside a JSON string and after a scheme word. */
    private static List<String> jwtContexts(String jwt) {
        return List.of("x " + jwt + " y", "{\"jwt\":\"" + jwt + "\",\"n\":1}", "x {\"jwt\":\"" + jwt + "\",\"n\":1} y",
                JSON.writeValueAsString(Map.of("body", "{\"jwt\":\"" + jwt + "\"}")), "token=" + jwt + "&a=b");
    }

    private static String base64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Whether {@code marker} is in {@code out} at any decoding of its JSON escapes, or in the base64url decoding of a run
     * of token characters at any of those decodings.
     */
    static boolean leaksAtAnyDecoding(String out, String marker) {
        String pass = out;
        for (int level = 0; pass != null && level <= JsonRedaction.MAX_KEY_LEVELS; level++) {
            if (pass.contains(marker)) {
                return true;
            }
            for (String run : pass.split("[^A-Za-z0-9_-]+")) {
                if (run.length() >= 8) {
                    try {
                        byte[] bytes = java.util.Base64.getUrlDecoder().decode(run.length() % 4 == 1 ? run.substring(1) : run);
                        if (new String(bytes, java.nio.charset.StandardCharsets.UTF_8).contains(marker)) {
                            return true;
                        }
                    } catch (IllegalArgumentException notBase64) {
                        // not a token
                    }
                }
            }
            pass = JsonRedaction.unescaped(pass);
        }
        return false;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> all = new ArrayList<>(a);
        all.addAll(b);
        return all;
    }

    @Test
    void masksTheOutermostTextWhenAnEmbeddedValueOrAFailedStartOpensAKeyBlockItDoesNotClose() {
        String opener = "\"-----BEGIN PRIVATE KEY-----\"";
        // A value that reads, one whose names repeat, one cut short, and one nested past the depth bound before it.
        for (String text : List.of("x {\"a\":" + opener + "} y \"FAKEKEYMATERIAL\"",
                "x {\"a\":1,\"a\":" + opener + "} y \"FAKEKEYMATERIAL\"",
                "x {\"a\":" + opener + ", \"FAKEKEYMATERIAL\"",
                "x " + "[".repeat(JsonRedaction.MAX_DEPTH + 1) + opener + "] \"FAKEKEYMATERIAL\"")) {
            assertEquals(Redactor.MASK, Redactor.redact(text), text);
        }
        // Controls: closed blocks, and the depth bound with no opener.
        assertEquals("x {\"a\":\"[REDACTED]\"} y", Redactor.redact(
                "x {\"a\":\"-----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----\"} y"));
        String deep = "x " + "[".repeat(JsonRedaction.MAX_DEPTH + 1) + "1" + "]".repeat(JsonRedaction.MAX_DEPTH + 1) + " y";
        assertEquals(deep, Redactor.redact(deep));
    }

    @Test
    void readsNoValuePastTheLevelOrLengthBoundAndMasksAJsonLookingStartWithVocabularyThere() {
        // At the level bound the text is no value's: kept as spelled, or masked from a start with vocabulary after it.
        assertEquals("note {\"a\":\"\\u0041\"}", ProseRedaction.redact("note {\"a\":\"\\u0041\"}", JsonRedaction.MAX_LEVELS));
        assertEquals("note [REDACTED]", ProseRedaction.redact("note {\"password\":\"s3cr3t\"}", JsonRedaction.MAX_LEVELS));
        // Past the length bound the same.
        String pad = "p".repeat(JsonRedaction.MAX_CHARS);
        assertEquals("[REDACTED]", Redactor.redact("{\"password\":\"s3cr3t\",\"pad\":\"" + pad + "\"}"));
        String plain = "{\"a\":\"\\u0041\",\"pad\":\"" + pad + "\"}";
        assertEquals(plain, Redactor.redact(plain));
    }

    @Test
    void masksAllOrKeepsAllWhenTheTextHoldsAPlaceholderCharacter() {
        assertEquals(Redactor.MASK, Redactor.redact("\uE000 {\"password\":\"x\"}"));
        assertEquals("\uE000 {\"a\":\"\\u0041\"}", Redactor.redact("\uE000 {\"a\":\"\\u0041\"}"));
        // With no embedded value no placeholder is needed: the text rules read it as any other text.
        assertEquals("\uE001 Bearer [REDACTED]", Redactor.redact("\uE001 Bearer 9f8a7b6c5d4e"));
    }

    @Test
    void restoresEachPlaceholderTheTextRulesKeptAndRefusesOneCutRepeatedOrMoved() {
        List<String> values = List.of("{\"a\":1}", "[2]");
        String first = "{\uE000\uE001\uE001}";
        String second = "{\uE000\uE001\uE002}";
        assertEquals("x {\"a\":1} y [2] z", ProseRedaction.restore("x " + first + " y " + second + " z", values));
        // One masked with the text around it is gone, the other restored.
        assertEquals("x [REDACTED] y [2]", ProseRedaction.restore("x [REDACTED] y " + second, values));
        // Cut, repeated, out of order, out of range, or a stray digit: refused.
        for (String broken : List.of("x \uE000\uE001\uE001}", "x {\uE000\uE001", first + first, second + first,
                "{\uE000\uE001\uE003}", "x \uE001 y", "{\uE000\uE000\uE001}")) {
            assertNull(ProseRedaction.restore(broken, values), broken);
        }
    }

    @Test
    void readsEveryDecodingOfAnOutputUpToTheBoundAndCountsOnePastItAsUnsettled() {
        String chain = "x" + "\\".repeat(1) + "u005c".repeat(JsonRedaction.MAX_KEY_LEVELS - 2) + "u0041";
        assertTrue(ProseRedaction.settled(chain, false), chain);
        String past = "x\\" + "u005c".repeat(JsonRedaction.MAX_KEY_LEVELS + 1) + "u0041";
        assertFalse(ProseRedaction.settled(past, false));
        assertTrue(ProseRedaction.hasVocabulary(past));
        assertEquals(Redactor.MASK, Redactor.redact(past));
        // A decoding that shows a secret field the text spells only with escapes is not settled.
        assertFalse(ProseRedaction.settled("\\u0022password\\u0022: \\u0022s3cr3t\\u0022", false));
        // One whose text rules only move a quote or a bracket is (a header line's value runs over its string's quote).
        assertEquals("{\"debug\":\"echo:\\nX-Auth-Token: [REDACTED]\"}",
                Redactor.redact("{\"debug\":\"echo:\\nX-Auth-Token: tok\"}"));
    }

    @Test
    void readsManyStartsBeforeALongUnterminatedStringInLinearTime() {
        // In prose (a text that starts with them is one JSON value nested past the depth bound, masked whole): each failed
        // attempt reads to the depth bound or the end of the string, and the attempts' budget stops them after about
        // twice the text's length.
        String text = "x " + "[".repeat(100_000) + "\"" + "a".repeat(1_000_000) + " password=hunter2long";
        String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(text));
        assertEquals("x " + Redactor.MASK, out);
        String clean = "x " + "{\"a\":".repeat(100_000) + "\"" + "a".repeat(1_000_000);
        assertEquals(clean, assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(clean)));
    }

    @Test
    void readsProseWithEmbeddedJsonAtEveryLevelInBoundedTime() {
        // Prose holding JSON whose string holds prose holding JSON, to the level bound, many times over: about 1 MB.
        String text = "end {\"password\":\"s3cr3t\"}";
        for (int level = 0; level < JsonRedaction.MAX_LEVELS; level++) {
            text = "said " + JSON.writeValueAsString(Map.of("note", text)) + " then";
        }
        String unit = text;
        String big = (unit + "\n").repeat(Math.max(1, 1_000_000 / unit.length()));
        String out = assertTimeoutPreemptively(Duration.ofSeconds(30), () -> Redactor.redact(big));
        assertFalse(out.contains("s3cr3t"));
    }
}
