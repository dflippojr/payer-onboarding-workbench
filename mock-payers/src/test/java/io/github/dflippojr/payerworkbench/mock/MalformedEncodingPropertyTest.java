package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.Example;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Class-level check (#219): generates text with one malformed percent escape in it ({@code %zz}, a lone
 * {@code %}, {@code %4}, {@code %%41} and so on) and sends it to every place a mock payer decodes
 * form data: the Basic client id and secret, the token form body of Northwind and Tailspin, and query
 * parameters. Each request must get a 4xx with its fixed error code, never a 5xx, and no response body
 * may name a Java exception class. Catches any uncaught runtime exception that malformed
 * percent-encoding reaches in a mock payer.
 */
class MalformedEncodingPropertyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    /**
     * Text with one malformed escape. A truncated escape ({@code %}, {@code %1}, {@code %4}) is only malformed at
     * the end of the text, so it is generated there; anywhere else the next characters could complete it.
     */
    @Provide
    Arbitrary<String> malformedEncoding() {
        Arbitrary<String> safe = Arbitraries.strings().withChars("abcXYZ019-_.~").ofMaxLength(6);
        Arbitrary<String> badEscape = Arbitraries.of("%z", "%zz", "%G0", "%0g", "%%41", "%-1", "%+1", "% 1");
        Arbitrary<String> truncated = Arbitraries.of("%", "%1", "%4");
        Arbitrary<String> inside = Combinators.combine(safe, badEscape, safe).as((before, escape, after) -> before + escape + after);
        Arbitrary<String> atEnd = Combinators.combine(safe, truncated).as((before, escape) -> before + escape);
        return Arbitraries.oneOf(inside, atEnd);
    }

    @Property(tries = 30)
    void malformedClientIdOrSecretInBasicCredentialsIsInvalidClient(@ForAll("malformedEncoding") String encoded)
            throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            String url = fixture.payer.baseUrl() + NorthwindPayer.TOKEN_PATH;

            assertClientError(post(url, "grant_type=client_credentials", basic(encoded + ":secret")), 401, "invalid_client");
            assertClientError(post(url, "grant_type=client_credentials", basic(PayerFixture.CLIENT_ID + ":" + encoded)),
                    401, "invalid_client");
        }
    }

    @Property(tries = 30)
    void malformedFormBodyIsInvalidRequestOnNorthwind(@ForAll("malformedEncoding") String encoded) throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            String secret = fixture.credentials.resolve("northwind-client-secret").orElseThrow();

            assertClientError(post(fixture.payer.baseUrl() + NorthwindPayer.TOKEN_PATH,
                    "grant_type=client_credentials&x=" + encoded, basic(PayerFixture.CLIENT_ID + ":" + secret)),
                    400, "invalid_request");
        }
    }

    @Property(tries = 30)
    void malformedFormBodyIsInvalidRequestOnTailspin(@ForAll("malformedEncoding") String encoded) throws Exception {
        try (TailspinPayer payer = TailspinPayer.builder().build().start(0)) {
            assertClientError(post(payer.baseUrl() + TailspinPayer.TOKEN_PATH,
                    "grant_type=client_credentials&x=" + encoded), 400, "invalid_request");
        }
    }

    @Property(tries = 100)
    void malformedQueryParameterIsInvalidRequest(@ForAll("malformedEncoding") String encoded) throws Exception {
        assertInvalidRequest(assertThrows(MockPayer.HttpError.class,
                () -> MockPayer.Request.formParameters("delayMs=" + encoded)));
    }

    /** URLDecoder decodes {@code %+1} as 0x01, so only the RFC 3986 check rejects it: pinned here, not left to chance. */
    @Example
    void signedHexEscapeIsRejectedLikeAnyOtherMalformedEscape() throws Exception {
        assertInvalidRequest(assertThrows(MockPayer.HttpError.class,
                () -> MockPayer.Request.formParameters("delayMs=%+1")));
    }

    /** A pair with no {@code =} is a name with an empty value, and a malformed name is rejected too. */
    @Example
    void pairWithoutEqualsIsANameWithAnEmptyValue() throws Exception {
        assertEquals("", MockPayer.Request.formParameters("flag").get("flag"));
        assertInvalidRequest(assertThrows(MockPayer.HttpError.class, () -> MockPayer.Request.formParameters("%zz")));
    }

    /** The 400 a malformed escape gets: the fixed code, the status, and no Java class name in the body. */
    private static void assertInvalidRequest(MockPayer.HttpError error) throws Exception {
        assertEquals(400, error.status());
        String body = error.response(MAPPER).body();
        assertEquals("invalid_request", MAPPER.readTree(body).path("error").asText(), body);
        assertFalse(body.contains("java."), body);
    }

    private static void assertClientError(HttpResponse<String> response, int status, String error) throws Exception {
        assertEquals(status, response.statusCode(), response.body());
        assertEquals(error, MAPPER.readTree(response.body()).path("error").asText(), response.body());
        assertFalse(response.body().contains("java."), response.body());
    }

    private static HttpResponse<String> post(String url, String body, String authorization) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(String url, String body) throws Exception {
        return post(url, body, null);
    }

    private static String basic(String pair) {
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }
}
