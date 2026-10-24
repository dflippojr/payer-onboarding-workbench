package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.payerworkbench.mock.PayerBehaviour;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * {@code payer-matrix.json}, read as typed rows. Rows reject unknown fields, so a misspelt behaviour
 * or expectation fails the load instead of being silently ignored.
 */
@JsonIgnoreProperties({"description", "legend"})
record PayerMatrix(List<String> dimensions, List<Row> rows) {

    static final String RESOURCE = "/payer-matrix.json";

    /** The {@code tokenType} a row gives to leave {@code token_type} out of the token response. */
    static final String TOKEN_TYPE_OMITTED = "OMITTED";

    static PayerMatrix load() {
        try (InputStream in = PayerMatrix.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(RESOURCE + " is not on the test classpath");
            }
            return new ObjectMapper().readValue(in, PayerMatrix.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** One payer behaviour, the spec clause it is judged by, and what that clause says the run must report. */
    record Row(String id, String dimension, String value, AuthType auth, Behaviour behaviour, String spec,
               String clause, Expect expect, String knownDefect) {

        @Override
        public String toString() {
            return id;
        }
    }

    /** The {@link PayerBehaviour} fields a row changes; {@code null} keeps the standard value. */
    record Behaviour(PayerBehaviour.AccessToken accessToken, String tokenType, PayerBehaviour.ExpiresIn expiresIn,
                     Boolean extraTokenFields, String tokenContentType, Boolean tokenErrorWith200,
                     PayerBehaviour.HookAuthentication hookAuthentication, Long clockOffsetSeconds,
                     Redirect redirect, PayerBehaviour.Discovery discovery) {

        /**
         * @param otherHost base URL of the second server an other-host redirect points at
         * @param tokenPath the payer's token endpoint path
         */
        PayerBehaviour toPayerBehaviour(String otherHost, String tokenPath) {
            PayerBehaviour b = PayerBehaviour.STANDARD;
            if (accessToken != null) { b = b.withAccessToken(accessToken); }
            if (tokenType != null) { b = b.withTokenType(TOKEN_TYPE_OMITTED.equals(tokenType) ? null : tokenType); }
            if (expiresIn != null) { b = b.withExpiresIn(expiresIn); }
            if (extraTokenFields != null) { b = b.withExtraTokenFields(extraTokenFields); }
            if (tokenContentType != null) { b = b.withTokenContentType(tokenContentType); }
            if (tokenErrorWith200 != null) { b = b.withTokenErrorWith200(tokenErrorWith200); }
            if (hookAuthentication != null) { b = b.withHookAuthentication(hookAuthentication); }
            if (clockOffsetSeconds != null) { b = b.withClockOffset(Duration.ofSeconds(clockOffsetSeconds)); }
            if (discovery != null) { b = b.withDiscovery(discovery); }
            if (redirect != null) {
                String path = redirect.endpoint().equals("token") ? tokenPath : "/cds-services";
                b = b.withRedirect(redirect.otherHost()
                        ? new PayerBehaviour.Redirect(path, redirect.status(), otherHost + path)
                        : PayerBehaviour.Redirect.sameHost(path, redirect.status()));
            }
            return b;
        }
    }

    /**
     * @param endpoint {@code discovery} or {@code token}
     * @param to       {@code same-host} or {@code other-host}
     */
    record Redirect(String endpoint, int status, String to) {

        Redirect {
            if (!List.of("discovery", "token").contains(endpoint) || !List.of("same-host", "other-host").contains(to)) {
                throw new IllegalArgumentException("redirect needs endpoint discovery|token and to same-host|other-host");
            }
        }

        boolean otherHost() {
            return to.equals("other-host");
        }
    }

    /**
     * @param verdict            {@code RunVerdict} status
     * @param brokeAt            the first failed step, or {@code null} for none
     * @param findings           check id to its most severe expected finding, or {@code ABSENT}
     * @param otherHostUntouched the other-host redirect target must see no request
     */
    record Expect(String verdict, String brokeAt, Map<String, String> findings, boolean otherHostUntouched) {

        Expect {
            findings = findings == null ? Map.of() : Map.copyOf(findings);
        }
    }
}
