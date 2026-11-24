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
            if (leaksInTokens(pass, marker, 0)) {
                return true;
            }
            pass = JsonRedaction.unescaped(pass);
        }
        return false;
    }

    /** Whether {@code marker} is in {@code text} or in the base64url decoding of a run of token characters in it, again and again. */
    private static boolean leaksInTokens(String text, String marker, int depth) {
        if (text.contains(marker)) {
            return true;
        }
        if (depth > 64) {
            return false;
        }
        for (String run : text.split("[^A-Za-z0-9_-]+")) {
            if (run.length() >= 8) {
                try {
                    byte[] bytes = java.util.Base64.getUrlDecoder().decode(run.length() % 4 == 1 ? run.substring(1) : run);
                    String decoded = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                    for (String pass = decoded; pass != null; pass = JsonRedaction.unescaped(pass)) {
                        if (leaksInTokens(pass, marker, depth + 1)) {
                            return true;
                        }
                    }
                } catch (IllegalArgumentException notBase64) {
                    // not a token
                }
            }
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
    void masksATextHoldingAPlaceholderCharacterWhenAnEmbeddedValueMeetsASecretTheTextPatternsCannotName() {
        // Automated review r1 on #412: with a placeholder character in the text, the fail-closed branch kept the text as
        // it came unless the regex vocabulary named a secret; a name the tree's secret-field rules read but the patterns
        // do not (separators in runs, or past their 64-character limit) kept its value. The branch now also masks when
        // reading any embedded value met a sensitive value (the structural signal). Names and values built at runtime.
        String secret = "FAKE-PH-" + Long.toString(new java.util.Random().nextLong() & Long.MAX_VALUE, 36);
        List<String> names = List.of("p" + "_".repeat(70) + "assword", "client" + "-_".repeat(40) + "secret",
                "a_p_i_k_e_y".repeat(1).replace("_", "__"), "access" + "_".repeat(64) + "token");
        List<String> failures = new ArrayList<>();
        for (char placeholder : new char[] {'\uE000', '\uE0FF', '\uEFFF'}) {
            for (String name : names) {
                for (String value : List.of(secret, ",", Redactor.MASK + Redactor.MASK, "")) {
                    String json = JSON.writeValueAsString(Map.of(name, value));
                    for (String text : List.of(placeholder + " " + json, "see " + json + " then " + placeholder,
                            placeholder + " " + JSON.writeValueAsString(Map.of("kty", "oct", "k", value)) + " x")) {
                        String out = Redactor.redact(text);
                        if (!out.equals(Redactor.MASK)) {
                            failures.add(names.indexOf(name) + "/" + value.length() + "/" + (int) placeholder + " => kept");
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), failures.subList(0, Math.min(8, failures.size())), () -> failures.size() + " texts kept");
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

    @Test
    void checksTheClaimsOfJwtsNestedInClaimsAndOfALongTokenInBoundedTime() {
        // #406 decisions (stage 2): a JWT's claims are redacted to decide whether it is secret-bearing, and a claim may
        // hold another JWT. Tokens nested in claims up to about 2 MiB, the innermost secret-bearing, and one 4 MiB token.
        String header = base64Url("{\"alg\":\"none\"}");
        String jwt = header + "." + base64Url("{\"client_secret\":\"FAKE-NESTED\"}") + ".sig";
        int levels = 1;
        while (jwt.length() < 2_000_000) {
            jwt = header + "." + base64Url("{\"sub\":\"x\",\"n\":{\"t\":[\"" + jwt + "\"]}}") + ".sig";
            levels++;
        }
        String nested = "x " + jwt + " y";
        String out = assertTimeoutPreemptively(Duration.ofSeconds(60), () -> Redactor.redact(nested));
        assertEquals("x [REDACTED] y", out, "levels " + levels);
        String longToken = "x " + header + "." + base64Url("{\"sub\":\"" + "a".repeat(3_000_000) + "\"}") + ".sig y";
        String kept = assertTimeoutPreemptively(Duration.ofSeconds(30), () -> Redactor.redact(longToken));
        assertTrue(kept.endsWith(".[REDACTED] y") && kept.length() > 4_000_000);
    }

    @Test
    void checksEveryTokenRunFromAnEyjWhateverFollowsItSegmentBySegment() {
        // #406 owner card (after automated review r4 on 8ff735c): a token is recognised by its run of token characters
        // from an eyJ at a word start, whatever punctuation ends it, and each segment is checked. Grid: shape x what
        // follows x context, with a secret claim generated at runtime; and harmless tokens keep header and payload.
        java.util.Random rnd = new java.util.Random();
        String secret = "FAKE-RUN-" + Long.toString(rnd.nextLong() & Long.MAX_VALUE, 36);
        String plainHeader = base64Url("{\"alg\":\"none\"}");
        String claimHeader = base64Url("{\"alg\":\"none\",\"api_key\":\"" + secret + "\"}");
        String harmless = base64Url("{\"sub\":\"user-" + rnd.nextInt(1000) + "\"}");
        String claim = base64Url("{\"sub\":\"x\",\"client_secret\":\"" + secret + "\"}");
        List<String> shapes = List.of(plainHeader + "." + claim + ".SIG", plainHeader + "." + claim + ".",
                plainHeader + "." + claim, claimHeader, claimHeader + "." + harmless + ".SIG", claimHeader + "." + harmless + ".",
                claimHeader + "." + harmless, plainHeader + "." + claim + ".SIG.more", "id-" + plainHeader + "." + claim + ".");
        List<String> follows = List.of("", ".", "..", "...", ",", ")", ".)", "\"", "'", "\\", " ", ";", ":", "!", "?", ".\n",
                "\\n", "]", "}", "&a=b", "=", ". Next");
        List<String> failures = new ArrayList<>();
        int cases = 0;
        for (String shape : shapes) {
            for (String after : follows) {
                String token = shape + after;
                for (String text : List.of("see " + token + " then", "see " + token, token,
                        JSON.writeValueAsString(Map.of("jwt", token)), "x " + JSON.writeValueAsString(Map.of("jwt", token)) + " y",
                        JSON.writeValueAsString(Map.of("body", JSON.writeValueAsString(Map.of("jwt", token)))),
                        "Authorization: Bearer " + token, "token=" + token + "&a=b")) {
                    cases++;
                    String out = Redactor.redact(text);
                    if (leaksAtAnyDecoding(out, secret)) {
                        failures.add(text + " => " + out);
                    }
                }
            }
        }
        assertEquals(List.of(), failures.subList(0, Math.min(5, failures.size())), failures.size() + " of grid texts kept a claim");
        assertTrue(cases > 1500, "grid size " + cases);
        for (String after : follows) {
            String text = "see " + plainHeader + "." + harmless + ".SIG" + after + " then";
            String out = Redactor.redact(text);
            assertTrue(out.contains(plainHeader + "." + harmless + ".") && !out.contains("SIG"), () -> text + " => " + out);
        }
    }

    @Test
    void checksClaimsNestedWithAnEscapeBetweenLevelsInLinearTime() {
        // #406 owner card (after automated review r4 on 8ff735c): tokens nested in claims with an escape between levels
        // were checked again by every pass, so the work grew with each level. One shared budget per call and a memo of
        // each segment's decision keep it linear; past the budget the token is masked.
        String header = base64Url("{\"alg\":\"none\"}");
        // A harmless innermost claim is the slow case: nothing is masked, so every pass reads the whole chain again.
        for (String innermost : List.of("{\"sub\":\"x\"}", "{\"client_secret\":\"FAKE-NEST\"}"))
        for (String escape : List.of("\\t", "\\n", "\\\\", "\\\"", "\\u0041")) {
            for (String end : List.of(".", "", ".SIG")) {
                String token = header + "." + base64Url(innermost) + end;
                int levels = 1;
                while (levels < 26) {
                    token = header + "." + base64Url("{\"n\":\"" + token + escape + "\"}") + end;
                    levels++;
                }
                String text = "x " + token + " y";
                String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> Redactor.redact(text),
                        () -> "escape " + escape + ", end '" + end + "', " + text.length() + " chars");
                assertFalse(leaksAtAnyDecoding(out, "FAKE-NEST"), () -> escape + end);
            }
        }
    }

    @Test
    void judgesAClaimSecretBearingByTheSecretFieldRulesOverTheWholeCredentialValueDomain() {
        // #406 redesign (owner card after Codex security r2 on #408): a claim is secret-bearing when the secret-field
        // rules meet a sensitive value in it, whatever its bytes are. Only the exact forms the rules write (the mask, a
        // known scheme then the mask under an Authorization-style name, and null, which no rule rewrites) keep a token's
        // header and payload. Grid: value class (punctuation only, masking markers only, empty and whitespace, short
        // ordinary values, non-string values) x secret name class x nesting x token shape x where the claim sits x
        // context. Every value is built at runtime; the claim's segment must be absent from the output at any decoding.
        String m = Redactor.MASK;
        List<Object> values = new ArrayList<>();
        for (String punctuation : List.of(",", ":", "\"", "'", "{}", "[]", "}", "]", "\\", ",:", " , ", "\",\"", "-", ".", "!")) {
            values.add(punctuation);
        }
        for (String markers : List.of(m + m, m + " " + m, m + ",", m + ":", m + "\"", "\"" + m, m + "}", m + " ", " " + m,
                "[" + m + "]", "Bearer " + m + m, "Bearer " + m + " " + m, "Bearer  " + m, "bearer " + m + ",")) {
            values.add(markers);
        }
        for (String blank : List.of("", " ", "\t", "\n", "  \r\n ")) {
            values.add(blank);
        }
        values.add("x");
        values.add("Bearer x");
        values.add(0);
        values.add(true);
        values.add(Map.of());
        values.add(List.of());
        values.add(List.of(","));
        values.add(List.of(m, m));
        values.add(Map.of("v", ","));
        List<java.util.function.Function<Object, Map<String, Object>>> claims = List.of(
                v -> Map.of("client_secret", v), v -> Map.of("password", v), v -> Map.of("authorization", v),
                v -> Map.of("apiKey", v), v -> Map.of("kty", "oct", "k", v),
                v -> Map.of("ctx", Map.of("access_token", v)), v -> Map.of("list", List.of(Map.of("password", v))),
                v -> Map.of("body", JSON.writeValueAsString(Map.of("client_secret", v))),
                v -> Map.of("jwk", Map.of("kty", "RSA", "d", v)),
                // A token in a claim whose own claim holds the value, unsigned so no signature is masked in it: the
                // inner decision must reach the outer one through the memo.
                v -> Map.of("inner", base64Url("{\"alg\":\"none\"}") + "." + base64Url(JSON.writeValueAsString(Map.of("password", v))) + "."));
        String plainHeader = base64Url("{\"alg\":\"none\"}");
        String harmless = base64Url("{\"sub\":\"x\"}");
        List<String> failures = new ArrayList<>();
        int cases = 0;
        for (Object value : values) {
            for (var claim : claims) {
                Map<String, Object> claimSet = new java.util.LinkedHashMap<>();
                claimSet.put("sub", "x");
                claimSet.putAll(claim.apply(value));
                String segment = base64Url(JSON.writeValueAsString(claimSet));
                for (boolean inHeader : new boolean[] {false, true}) {
                    String head = inHeader ? segment : plainHeader;
                    String body = inHeader ? harmless : segment;
                    for (String jwt : List.of(head + "." + body + ".SIG", head + "." + body + ".", head + "." + body)) {
                        for (String text : List.of("see " + jwt + " then", JSON.writeValueAsString(Map.of("jwt", jwt)),
                                JSON.writeValueAsString(Map.of("body", "x " + jwt)))) {
                            cases++;
                            String out = Redactor.redact(text);
                            if (holdsAtAnyDecoding(out, segment)) {
                                failures.add(claimSet.keySet() + " value class " + values.indexOf(value)
                                        + (inHeader ? " in header" : " in payload"));
                            }
                        }
                    }
                }
            }
        }
        assertTrue(cases > 4000, "grid size " + cases);
        assertEquals(List.of(), failures.subList(0, Math.min(8, failures.size())),
                () -> failures.size() + " of " + values.size() * claims.size() * 18 + " grid texts kept a claim segment");
        // The exact forms the rules write keep the header and payload; the signature is masked.
        for (Map<String, ?> claimSet : List.<Map<String, ?>>of(Map.<String, Object>of("sub", "x", "password", m),
                Map.<String, Object>of("sub", "x", "authorization", "Bearer " + m), Map.of("sub", "x", "kty", "oct", "k", m),
                Map.<String, Object>of("sub", "x", "ctx", Map.of("client_secret", m)),
                new java.util.HashMap<>(java.util.Collections.singletonMap("password", null)),
                new java.util.HashMap<>(Map.of("kty", "oct", "x", "y", "k", "")) {{ put("k", null); }},
                Map.<String, Object>of("sub", "x", "authorization", List.of("Bearer " + m)))) {
            String segment = base64Url(JSON.writeValueAsString(claimSet));
            String text = "see " + plainHeader + "." + segment + ".SIG then";
            String out = Redactor.redact(text);
            assertTrue(out.contains(plainHeader + "." + segment + ".") && !out.contains("SIG"), () -> claimSet + " => " + out);
        }
    }

    @Test
    void judgesTheSettledAndFailedStartChecksByTheSecretFieldRulesOverTheSameValueDomain() {
        // #406 redesign: the settled check (a decoding of the output) and the vocabulary check after a failed start
        // decide by the same structural signal as the claim check, not by comparing text with punctuation and masks
        // dropped. A secret-named field at a depth only a decoding reads, or after a failed start, with a value of
        // punctuation, masking markers or whitespace, must not come back as it was written.
        String m = Redactor.MASK;
        List<String> values = List.of(",", ":", "{}", "[]", " , ", "-", m + m, m + " " + m, m + ",", m + ":", m + "}", " " + m,
                m + " ", "", " ", "Bearer " + m + m);
        List<String> failures = new ArrayList<>();
        int cases = 0;
        for (String v : values) {
            for (String name : List.of("password", "client_secret", "authorization")) {
                String field = JSON.writeValueAsString(Map.of(name, v));
                String inner = field.substring(1, field.length() - 1);
                // Two and three escape levels deep in prose and in a JSON value: only a decoding of the output reads it.
                String twice = JSON.writeValueAsString(JSON.writeValueAsString(inner));
                String thrice = JSON.writeValueAsString(twice);
                List<String> texts = List.of("note " + twice.substring(1, twice.length() - 1) + " end",
                        "note " + thrice.substring(1, thrice.length() - 1) + " end",
                        JSON.writeValueAsString(Map.of("note", "x " + thrice.substring(1, thrice.length() - 1))),
                        // After a failed start.
                        "he said {\"a\":1,, " + inner + " more", "he said [\"a\" " + inner + "] more");
                for (String text : texts) {
                    cases++;
                    String out = Redactor.redact(text);
                    if (holdsAtAnyDecoding(out, inner)) {
                        failures.add(name + " value class " + values.indexOf(v) + " text form " + texts.indexOf(text));
                    }
                }
            }
        }
        assertTrue(cases >= 240, "grid size " + cases);
        assertEquals(List.of(), failures.subList(0, Math.min(8, failures.size())), () -> failures.size() + " of " + 240 + " texts kept the field");
    }

    @Test
    void judgesTheWholeValueOfAHeaderLineOnlyADecodingShowsInStringsAndInTokenClaims() {
        // #406 redesign (Codex security r1 on #412): a header line that only a decoding of the output shows as a line is
        // judged over its whole value, unless a parser proves where its string ends. A value that is the written form
        // up to a quote, with more bytes after it on the line, is no written form, in a string or in a token claim,
        // whatever check reads it. Grid: header name x escape level x line spelling class x written-form prefix x
        // suffix class x context. Every input is built at runtime from parts; the suffix bytes must be absent from the
        // output at any decoding of its escapes and of its tokens.
        String m = Redactor.MASK;
        String marker = "FAKE-HDR-" + Long.toString(System.nanoTime() & Long.MAX_VALUE, 36);
        List<String> failures = new ArrayList<>();
        int cases = 0;
        Map<String, String> lines = new java.util.LinkedHashMap<>();
        for (String name : List.of("Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token")) {
            for (int levels = 1; levels <= 2; levels++) {
                String below = "\\".repeat((1 << (levels - 1)) - 1);
                String unicode = below + "\\u00";
                String lineBreak = below + "\\n";
                String escapedQuote = "\\".repeat((1 << levels) - 1) + "\"";
                String spelled = name.charAt(0) + unicode + Integer.toHexString(name.charAt(1)) + name.substring(2);
                List<String[]> spellings = List.of(new String[] {spelled, escapedQuote},
                        new String[] {spelled, unicode + "22"}, new String[] {unicode + "20" + name, escapedQuote},
                        new String[] {name, below + "\""});
                List<String> suffixes = List.of(" " + marker, marker, "," + marker, " x=" + marker + "; y");
                for (int form = 0; form < spellings.size(); form++) {
                    String[] spelling = spellings.get(form);
                    for (String prefix : List.of(m, "Bearer " + m)) {
                        for (int suffix = 0; suffix < suffixes.size(); suffix++) {
                            lines.put(name + " level " + levels + " spelling " + form + " prefix " + prefix.length()
                                    + " suffix form " + suffix, "GET / HTTP/1.1" + lineBreak + spelling[0] + ": " + prefix
                                    + spelling[1] + suffixes.get(suffix));
                        }
                    }
                    // A quoted attribute, then another attribute holding the suffix.
                    lines.put(name + " level " + levels + " spelling " + form + " quoted attribute", "GET / HTTP/1.1"
                            + lineBreak + spelling[0] + ": a=" + spelling[1] + "v" + spelling[1] + "; s=" + marker);
                }
            }
        }
        String plainHeader = base64Url("{\"alg\":\"none\"}");
        for (var line : lines.entrySet()) {
            List<String> texts = new ArrayList<>(List.of("note " + line.getValue() + " end",
                    "he said {\"a\":1,, " + line.getValue(), "x {\"raw\":\"" + line.getValue() + "\"} y"));
            // The same line as the text of a token's claim: prose, and a claim holding it as a string.
            for (String claim : List.of(line.getValue(), "{\"note\":\"" + line.getValue() + "\"}")) {
                String jwt = plainHeader + "." + base64Url(claim) + ".";
                texts.add("see " + jwt + " then");
                texts.add(JSON.writeValueAsString(Map.of("jwt", jwt)));
            }
            for (int form = 0; form < texts.size(); form++) {
                cases++;
                if (leaksAtAnyDecoding(Redactor.redact(texts.get(form)), marker)) {
                    failures.add(line.getKey() + " text form " + form);
                }
            }
        }
        assertEquals(2520, cases, "grid size");
        assertEquals(List.of(), failures.subList(0, Math.min(8, failures.size())),
                () -> failures.size() + " of 2520 texts kept the bytes after a header line's written form");
        // A parser proves the end of a line in a JSON string: a header line there, its value the written form, keeps the
        // members after its string, in a text and in a token claim.
        for (String[] form : List.of(new String[] {"Authorization", m}, new String[] {"Authorization", "Bearer " + m},
                new String[] {"Cookie", m})) {
            String name = form[0];
            String json = JSON.writeValueAsString(Map.of("raw", "GET /\n" + name + ": " + form[1]));
            String text = "{\"note\":\"plain words\",\"echo\":" + JSON.writeValueAsString(json) + "}";
            assertEquals(text, Redactor.redact(text), () -> name + " written form in a string");
            String jwt = base64Url("{\"alg\":\"none\"}") + "." + base64Url(json) + ".";
            String inToken = "see " + jwt + " then";
            assertEquals(inToken, Redactor.redact(inToken), () -> name + " written form in a token claim");
        }
    }

    /** Whether {@code out} holds {@code part} at any decoding of its JSON escapes. */
    private static boolean holdsAtAnyDecoding(String out, String part) {
        String pass = out;
        for (int level = 0; pass != null && level <= JsonRedaction.MAX_KEY_LEVELS; level++, pass = JsonRedaction.unescaped(pass)) {
            if (pass.contains(part)) {
                return true;
            }
        }
        return false;
    }
}
