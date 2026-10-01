package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parsing and formatting helpers shared by the built-in checks. */
final class Support {

    /** Longest body excerpt quoted in evidence. */
    static final int MAX_BODY_EXCERPT = 600;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A JWT as it survives redaction: readable header and payload, masked signature. */
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]*\\.(eyJ[A-Za-z0-9_-]*)\\.");

    private Support() {
    }

    /** Parses {@code text} as JSON; empty if it is blank or not JSON. */
    static Optional<JsonNode> parseJson(String text) {
        if (text == null || text.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(MAPPER.readTree(text));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /** One-line summary of an exchange plus a short excerpt of the response body. */
    static String describe(HttpExchange exchange) {
        StringBuilder sb = new StringBuilder()
                .append(exchange.method()).append(' ').append(exchange.url()).append(" -> ");
        if (exchange.responded()) {
            sb.append("HTTP ").append(exchange.status());
        } else {
            sb.append("no response");
        }
        sb.append(" in ").append(exchange.latency().toMillis()).append(" ms");
        if (exchange.transportError() != null) {
            sb.append("\nerror: ").append(exchange.transportError());
        }
        String body = exchange.responseBody();
        if (body != null && !body.isBlank()) {
            sb.append("\nresponse body: ").append(excerpt(body));
        }
        return sb.toString();
    }

    static String excerpt(String text) {
        String flat = text.strip();
        return flat.length() <= MAX_BODY_EXCERPT ? flat : flat.substring(0, MAX_BODY_EXCERPT) + " ...";
    }

    /** First value of a header, matched case-insensitively. */
    static Optional<String> header(Map<String, List<String>> headers, String name) {
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)
                    && e.getValue() != null && !e.getValue().isEmpty()) {
                return Optional.ofNullable(e.getValue().get(0));
            }
        }
        return Optional.empty();
    }

    /** The payer's clock, from the response {@code Date} header. */
    static Optional<Instant> serverDate(HttpExchange exchange) {
        return header(exchange.responseHeaders(), "Date").flatMap(value -> {
            try {
                return Optional.of(ZonedDateTime.parse(value.strip(), DateTimeFormatter.RFC_1123_DATE_TIME)
                        .toInstant());
            } catch (Exception e) {
                return Optional.empty();
            }
        });
    }

    /** The last exchange sent to the connection's token endpoint, if any. */
    static Optional<HttpExchange> tokenExchange(RunObservations obs) {
        String endpoint = obs.connection().tokenEndpoint();
        if (endpoint == null) {
            return Optional.empty();
        }
        HttpExchange found = null;
        for (HttpExchange e : obs.exchanges()) {
            if (withoutQuery(e.url()).equals(withoutQuery(endpoint))) {
                found = e;
            }
        }
        return Optional.ofNullable(found);
    }

    static String withoutQuery(String url) {
        int cut = url.length();
        int q = url.indexOf('?');
        int f = url.indexOf('#');
        if (q >= 0) {
            cut = q;
        }
        if (f >= 0 && f < cut) {
            cut = f;
        }
        return url.substring(0, cut);
    }

    /** The decoded payloads of every JWT visible in the request headers and body. */
    static List<JsonNode> requestJwtClaims(HttpExchange exchange) {
        List<JsonNode> claims = new ArrayList<>();
        exchange.requestHeaders().values().forEach(values -> {
            if (values != null) {
                values.forEach(v -> collectJwtClaims(v, claims));
            }
        });
        collectJwtClaims(exchange.requestBody(), claims);
        return claims;
    }

    private static void collectJwtClaims(String text, List<JsonNode> out) {
        if (text == null) {
            return;
        }
        Matcher m = JWT.matcher(text);
        while (m.find()) {
            try {
                String json = new String(Base64.getUrlDecoder().decode(m.group(1)), StandardCharsets.UTF_8);
                parseJson(json).filter(JsonNode::isObject).ifPresent(out::add);
            } catch (IllegalArgumentException ignored) {
                // Not valid base64url; not a JWT after all.
            }
        }
    }

    /** A claim's string values; a JSON array (as {@code aud} may be) yields each element. */
    static List<String> stringValues(JsonNode node) {
        List<String> out = new ArrayList<>();
        if (node == null) {
            return out;
        }
        if (node.isArray()) {
            node.forEach(n -> {
                if (n.isTextual()) {
                    out.add(n.asText());
                }
            });
        } else if (node.isTextual()) {
            out.add(node.asText());
        }
        return out;
    }

    static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
