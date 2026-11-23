package io.github.dflippojr.payerworkbench.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * A seeded fuzz corpus of payer-like texts with synthetic secrets (#377 criterion 2): JSON objects with secret-named and
 * ordinary members, scheme credentials, JWTs, form fields, key blocks and JWKs, in ten families (plain, escaped names,
 * nested 1 to 4 levels, unicode-escaped quotes, respelled, cut, after prose, JWK, schemes, mixed). The same seed gives
 * the same texts, so the Redactor's outputs for them can be committed as a scanner grid.
 */
final class FuzzCorpus {

    private static final String[] FAMILIES = {"plain", "escapedNames", "nested", "unicodeQuotes", "respelled", "cut",
        "prose", "jwk", "schemes", "mixed"};
    private static final String[] SECRET_NAMES = {"client_secret", "access_token", "refresh_token", "id_token",
        "password", "apiKey", "private_key", "secret", "client_assertion", "assertion", "Authorization", "Cookie",
        "x-api-key"};
    private static final String[] ORDINARY = {"id", "status", "note", "body", "message", "token_type", "expires_in",
        "scope", "error_description", "secretary", "d", "k", "data"};

    private final Random rnd;
    private final boolean claims;
    private int counter;

    private FuzzCorpus(long seed, boolean claims) {
        rnd = new Random(seed);
        this.claims = claims;
    }

    /** {@code count} texts from seed {@code seed}, cycling through the families. */
    static List<String> texts(long seed, int count) {
        return texts(new FuzzCorpus(seed, false), count);
    }

    /**
     * {@code count} texts from seed {@code seed} whose JWTs carry claims (#406 decision, stage 2): a secret-named claim,
     * a JWK private member, a scheme credential or a key block in the payload or the header, each holding a synthetic
     * secret, or a harmless claim. Every other draw is as in {@link #texts}, so the same families hold these tokens.
     */
    static List<String> textsWithClaims(long seed, int count) {
        return texts(new FuzzCorpus(seed, true), count);
    }

    private static List<String> texts(FuzzCorpus corpus, int count) {
        List<String> texts = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            texts.add(corpus.generate(FAMILIES[i % FAMILIES.length]));
        }
        return texts;
    }

    private String secret() {
        return "FAKE-FUZZ-" + (counter++) + "x" + Integer.toString(rnd.nextInt(1 << 20), 36);
    }

    private String generate(String family) {
        String json = object(0, family);
        return switch (family) {
            case "nested" -> wrap(json, 1 + rnd.nextInt(4));
            case "unicodeQuotes" -> nestedUnicode(json);
            case "respelled" -> respell(json);
            case "cut" -> cut(rnd.nextBoolean() ? json : nested(json));
            case "prose" -> "payer said: " + json + (rnd.nextBoolean() ? " then " + scheme() : "");
            case "mixed" -> respell(wrap(json, rnd.nextInt(3)));
            default -> json;
        };
    }

    private String object(int depth, String family) {
        StringBuilder b = new StringBuilder("{");
        int members = 1 + rnd.nextInt(4);
        if (family.equals("jwk") && rnd.nextBoolean()) {
            b.append("\"kty\":\"RSA\",\"d\":\"").append(secret()).append("\",");
        }
        for (int i = 0; i < members; i++) {
            if (i > 0) {
                b.append(rnd.nextBoolean() ? "," : " , ");
            }
            boolean secretName = rnd.nextInt(3) == 0;
            String name = secretName ? SECRET_NAMES[rnd.nextInt(SECRET_NAMES.length)]
                    : ORDINARY[rnd.nextInt(ORDINARY.length)] + i;
            if (family.equals("escapedNames") && rnd.nextBoolean()) {
                name = escapeSome(name);
            }
            b.append('"').append(name).append('"').append(rnd.nextBoolean() ? ":" : " : ");
            int kind = rnd.nextInt(8);
            if (secretName) {
                b.append(kind < 6 ? "\"" + (name.equalsIgnoreCase("authorization") ? "Bearer " : "") + secret() + "\""
                        : "{\"x\":\"" + secret() + "\"}");
            } else if (kind == 0 && depth < 2) {
                b.append(object(depth + 1, family));
            } else if (kind == 1 && depth < 2) {
                b.append(quote(object(depth + 1, family)));
            } else if (kind == 2) {
                b.append('"').append(scheme()).append('"');
            } else if (kind == 3) {
                b.append(rnd.nextInt(100_000)).append(rnd.nextBoolean() ? ".5e3" : "");
            } else if (kind == 4) {
                b.append('[').append(quote(scheme())).append(",null,true]");
            } else {
                b.append("\"plain words here\"");
            }
        }
        return b.append('}').toString();
    }

    private String scheme() {
        return switch (rnd.nextInt(5)) {
            case 0 -> "Bearer " + secret();
            case 1 -> "Authorization: Basic " + secret() + "==";
            case 2 -> claims ? claimJwt() : "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." + secret();
            case 3 -> "client_secret=" + secret() + "&a=b";
            default -> "-----BEGIN PRIVATE KEY-----\n" + secret() + "\n-----END PRIVATE KEY-----";
        };
    }

    /** A JWT whose payload or header holds a claim drawn at random, its signature a synthetic secret. */
    private String claimJwt() {
        String claim = switch (rnd.nextInt(7)) {
            case 0 -> "\"" + SECRET_NAMES[rnd.nextInt(SECRET_NAMES.length)] + "\":\"" + secret() + "\"";
            case 1 -> "\"ctx\":{\"" + SECRET_NAMES[rnd.nextInt(SECRET_NAMES.length)] + "\":\"" + secret() + "\"}";
            case 2 -> "\"jwk\":{\"kty\":\"RSA\",\"d\":\"" + secret() + "\"}";
            case 3 -> "\"note\":\"Bearer " + secret() + "\"";
            case 4 -> "\"pem\":\"-----BEGIN PRIVATE KEY-----\\n" + secret() + "\\n-----END PRIVATE KEY-----\"";
            case 5 -> "\"body\":" + quote("{\"" + SECRET_NAMES[rnd.nextInt(SECRET_NAMES.length)] + "\":\"" + secret() + "\"}");
            default -> "\"sub\":\"user-" + rnd.nextInt(1000) + "\"";
        };
        boolean inHeader = rnd.nextInt(4) == 0;
        String header = inHeader ? "{\"alg\":\"none\"," + claim + "}" : "{\"alg\":\"none\"}";
        String payload = inHeader ? "{\"sub\":\"x\"}" : "{\"iss\":\"p\"," + claim + "}";
        return base64Url(header) + "." + base64Url(payload) + "." + secret();
    }

    private static String base64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String escapeSome(String name) {
        StringBuilder b = new StringBuilder();
        for (char c : name.toCharArray()) {
            b.append(rnd.nextInt(3) == 0 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
        }
        return b.toString();
    }

    private static String quote(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    private static String nested(String text) {
        return "{\"body\":" + quote(text) + "}";
    }

    private static String wrap(String text, int levels) {
        String out = text;
        for (int i = 0; i < levels; i++) {
            out = nested(out);
        }
        return out;
    }

    private static String nestedUnicode(String text) {
        return "{\"body\":\"" + text.replace("\\", "\\\\").replace("\"", "\\u0022").replace("\n", "\\n") + "\"}";
    }

    /** Respells some quotes, backslashes and letters inside the text as unicode escapes, as a serializer might. */
    private String respell(String text) {
        StringBuilder b = new StringBuilder();
        boolean inString = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\' && i + 1 < text.length()) {
                char next = text.charAt(i + 1);
                if (next == '"' && rnd.nextInt(3) == 0) {
                    b.append("\\u0022");
                } else if (next == '\\' && rnd.nextInt(3) == 0) {
                    b.append("\\u005c");
                } else {
                    b.append(c).append(next);
                }
                i++;
                continue;
            }
            if (c == '"') {
                inString = !inString;
            } else if (inString && Character.isLetter(c) && rnd.nextInt(6) == 0) {
                b.append(String.format("\\u%04X", (int) c));
                continue;
            }
            b.append(c);
        }
        return b.toString();
    }

    private String cut(String text) {
        return text.length() < 4 ? text : text.substring(0, text.length() / 2 + rnd.nextInt(text.length() / 2));
    }
}
