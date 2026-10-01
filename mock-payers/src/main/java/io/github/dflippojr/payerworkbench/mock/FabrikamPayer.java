package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Payer B, "Fabrikam Benefits (synthetic)": quirky but realistic, modeled on
 * the HL7 CRD reference implementation and an older IG version (CRD 2.0.1).
 *
 * <ul>
 *   <li>Service ids are {@code order-sign-crd} and {@code order-select-crd}, and
 *       the prefetch keys are non-standard: {@code coverageBundle} and
 *       {@code deviceRequestBundle} instead of {@code coverage} and {@code patient}.</li>
 *   <li>Coverage information arrives inside card suggestions (an {@code update}
 *       action carrying the order), never in {@code systemActions}, and uses the
 *       RI's {@code identifier} sub-extension instead of {@code coverage-assertion-id}.</li>
 *   <li>Auth is the CDS Hooks 2.0 client JWT. Each registered issuer has a JWKS
 *       URL the payer fetches (and refetches when it sees an unknown {@code kid}).
 *       It checks the signature (RS384 or ES384 only), {@code iss}, that
 *       {@code aud} is exactly the URL of the service called, {@code exp}, and
 *       that a {@code jti} is never reused. Discovery is open.</li>
 * </ul>
 *
 * <p>Outcomes by code: E0250 is conditional, with prior authorization and clinical
 * documentation needed; E0424 is covered with no authorization; anything else is not covered.
 */
public final class FabrikamPayer extends MockPayer {

    public static final String DISPLAY_NAME = "Fabrikam Benefits (synthetic)";
    public static final String IG_VERSION = "2.0.1";
    public static final int DEFAULT_PORT = 8182;

    /** The audience base the payer expects while {@link Fault#WRONG_AUDIENCE_REJECT} is on. */
    public static final String WRONG_AUDIENCE_BASE = "https://crd.fabrikam-benefits.example";

    /** The pre-2.1 CRD card type code system the reference implementation used. */
    static final String CARD_TYPE_SYSTEM = "http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp";

    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(JWSAlgorithm.RS384, JWSAlgorithm.ES384);

    private static final Map<String, CoverageDetermination> RULES = Map.of(
            "E0250", new CoverageDetermination("conditional", "auth-needed", List.of("clinical"),
                    "Prior authorization and clinical documentation required"),
            "E0424", new CoverageDetermination("covered", "no-auth", List.of(),
                    "Covered; no prior authorization needed"));
    private static final CoverageDetermination OTHERWISE = new CoverageDetermination(
            "not-covered", "no-auth", List.of(), "Not a covered benefit under this plan");

    private static final List<ServiceDefinition> SERVICES = List.of(
            new ServiceDefinition("order-sign-crd", "order-sign", "Fabrikam order-sign CRD",
                    "Fabrikam coverage requirements discovery for orders being signed.", riPrefetch()),
            new ServiceDefinition("order-select-crd", "order-select", "Fabrikam order-select CRD",
                    "Fabrikam coverage guidance for selected orders.", riPrefetch()));

    private final Map<String, URI> jwksUrls;
    private final Map<String, JWKSet> jwksCache = new ConcurrentHashMap<>();
    private final Map<String, Instant> usedJtis = new ConcurrentHashMap<>();
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private FabrikamPayer(Builder builder) {
        super(builder.clock, builder.publicBaseUrl);
        this.jwksUrls = Map.copyOf(builder.jwksUrls);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public FabrikamPayer start(int port) throws IOException {
        super.start(port);
        return this;
    }

    @Override
    public String displayName() {
        return DISPLAY_NAME;
    }

    @Override
    public String igVersion() {
        return IG_VERSION;
    }

    @Override
    public List<ServiceDefinition> services() {
        return SERVICES;
    }

    private static Map<String, String> riPrefetch() {
        Map<String, String> prefetch = new LinkedHashMap<>();
        prefetch.put("coverageBundle", "Coverage?patient={{context.patientId}}&status=active");
        prefetch.put("deviceRequestBundle", "DeviceRequest?_id={{context.draftOrders.DeviceRequest.id}}"
                + "&_include=DeviceRequest:patient&_include=DeviceRequest:performer"
                + "&_include=DeviceRequest:insurance:Coverage");
        return prefetch;
    }

    // ---- CDS Hooks client JWT ----

    @Override
    protected void authenticate(Request request) {
        String token = request.bearerToken();
        if (token == null) {
            throw unauthorized("CDS Hooks client JWT required in Authorization: Bearer");
        }
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw unauthorized("Bearer token is not a signed JWT");
        }
        JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        if (!ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw unauthorized("JWT alg " + algorithm + " is not accepted; use RS384 or ES384");
        }
        String issuer = claims.getIssuer();
        if (issuer == null || !jwksUrls.containsKey(issuer)) {
            throw unauthorized("Unknown iss '" + issuer + "'; register the client with Fabrikam first");
        }
        String keyId = jwt.getHeader().getKeyID();
        if (keyId == null) {
            throw unauthorized("JWT header has no kid");
        }
        verifySignature(jwt, issuer, keyId);

        String expectedAudience = (faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT)
                ? WRONG_AUDIENCE_BASE : publicBaseUrl()) + request.path();
        if (!List.of(expectedAudience).equals(claims.getAudience())) {
            HttpError error = unauthorized("aud must be exactly '" + expectedAudience + "', got " + claims.getAudience());
            throw faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT) ? error.fault(Fault.WRONG_AUDIENCE_REJECT) : error;
        }

        Instant now = clock.instant();
        if (claims.getExpirationTime() == null) {
            throw unauthorized("JWT has no exp");
        }
        Instant expiry = claims.getExpirationTime().toInstant();
        if (faults().isEnabled(Fault.EXPIRED_TOKEN_401)) {
            throw unauthorized("JWT expired").fault(Fault.EXPIRED_TOKEN_401);
        }
        if (!now.isBefore(expiry)) {
            throw unauthorized("JWT expired at " + expiry);
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw unauthorized("JWT has no jti");
        }
        usedJtis.values().removeIf(seenExpiry -> !now.isBefore(seenExpiry));
        if (usedJtis.putIfAbsent(issuer + "|" + jti, expiry) != null) {
            throw unauthorized("jti '" + jti + "' was already used (replay)");
        }
    }

    private void verifySignature(SignedJWT jwt, String issuer, String keyId) {
        JWK key = jwksCache.computeIfAbsent(issuer, this::fetchJwks).getKeyByKeyId(keyId);
        if (key == null) {
            // The client may have rotated keys since we cached its JWKS.
            JWKSet refreshed = fetchJwks(issuer);
            jwksCache.put(issuer, refreshed);
            key = refreshed.getKeyByKeyId(keyId);
        }
        if (!(key instanceof AsymmetricJWK asymmetric)) {
            throw unauthorized("No public key with kid '" + keyId + "' in the JWKS for iss '" + issuer + "'");
        }
        try {
            if (!jwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), asymmetric.toPublicKey()))) {
                throw unauthorized("JWT signature does not verify against kid '" + keyId + "'");
            }
        } catch (JOSEException e) {
            throw unauthorized("JWT signature could not be checked with kid '" + keyId + "': " + e.getMessage());
        }
    }

    private JWKSet fetchJwks(String issuer) {
        URI url = jwksUrls.get(issuer);
        try {
            HttpResponse<String> response = httpClient.send(
                    HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw unauthorized("Could not fetch JWKS for iss '" + issuer + "' from " + url
                        + ": HTTP " + response.statusCode());
            }
            return JWKSet.parse(response.body());
        } catch (IOException | ParseException e) {
            throw unauthorized("Could not fetch JWKS for iss '" + issuer + "' from " + url + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unauthorized("Interrupted fetching JWKS for iss '" + issuer + "'");
        }
    }

    private static HttpError unauthorized(String description) {
        return new HttpError(401, "unauthorized", description);
    }

    // ---- hooks ----

    @Override
    protected ObjectNode handleHook(ServiceDefinition service, ObjectNode hookRequest) {
        String hookInstance = hookRequest.path("hookInstance").asText();
        JsonNode prefetch = hookRequest.path("prefetch");
        ObjectNode response = mapper.createObjectNode();
        ArrayNode cards = response.putArray("cards");

        for (JsonNode order : draftOrders(hookRequest.path("context").path("draftOrders"))) {
            String code = orderCode(order);
            String label = orderLabel(order);
            CoverageDetermination determination = CoverageDetermination.lookup(RULES, code, OTHERWISE);
            String seed = hookInstance + "|" + label;
            String summary = "Fabrikam: " + (code == null ? "order" : code) + " - " + determination.summary();
            if (service.hook().equals("order-select")) {
                cards.add(card(seed, summary, "info", "Final requirements are returned when the order is signed.",
                        CARD_TYPE_SYSTEM, "coverage", "Coverage"));
                continue;
            }
            String indicator = "not-covered".equals(determination.covered()) ? "warning" : "info";
            ObjectNode card = card(seed, summary, indicator, null, CARD_TYPE_SYSTEM, "coverage", "Coverage");
            ObjectNode suggestion = card.putArray("suggestions").addObject();
            suggestion.put("label", "Save coverage information to the order");
            suggestion.put("isRecommended", true);
            ObjectNode action = suggestion.putArray("actions").addObject();
            action.put("type", "update");
            action.put("description", "Add coverage information to " + label);
            action.set("resource", withCoverageInformation(order, determination,
                    coverageReference(order, prefetch.path("coverageBundle"), prefetch.path("deviceRequestBundle")),
                    "identifier", "FAB-" + label.replace('/', '-') + "-" + (code == null ? "NOCODE" : code)));
            cards.add(card);
        }
        return response;
    }

    /** Configures a {@link FabrikamPayer}. */
    public static final class Builder {

        private final Map<String, URI> jwksUrls = new LinkedHashMap<>();
        private Clock clock = Clock.systemUTC();
        private String publicBaseUrl;

        private Builder() { }

        /** Registers a client by its {@code iss} and the URL its public JWK Set is served from. */
        public Builder client(String issuer, URI jwksUrl) {
            jwksUrls.put(Objects.requireNonNull(issuer, "issuer"), Objects.requireNonNull(jwksUrl, "jwksUrl"));
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        public Builder publicBaseUrl(String publicBaseUrl) {
            this.publicBaseUrl = publicBaseUrl;
            return this;
        }

        public FabrikamPayer build() {
            return new FabrikamPayer(this);
        }
    }

    /**
     * Runs Fabrikam standalone until the process is stopped.
     * Options: {@code --port N} (default {@value #DEFAULT_PORT}; 0 for ephemeral),
     * {@code --client ISS=JWKS_URL} (repeatable), {@code --public-base-url URL}.
     */
    public static void main(String[] args) throws IOException {
        StandaloneArgs options = StandaloneArgs.parse(args);
        Builder builder = builder().publicBaseUrl(options.single("public-base-url", null));
        for (String client : options.all("client")) {
            int eq = client.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("--client expects ISS=JWKS_URL, got '" + client + "'");
            }
            builder.client(client.substring(0, eq), URI.create(client.substring(eq + 1)));
        }
        FabrikamPayer payer = builder.build().start(Integer.parseInt(options.single("port", String.valueOf(DEFAULT_PORT))));
        Runtime.getRuntime().addShutdownHook(new Thread(payer::stop));
        System.out.println(DISPLAY_NAME + " listening at " + payer.baseUrl() + " (CRD " + IG_VERSION + ")");
        if (payer.jwksUrls.isEmpty()) {
            System.out.println("  no clients registered: every hook call will get 401 (add --client ISS=JWKS_URL)");
        }
        payer.jwksUrls.forEach((iss, url) -> System.out.println("  client iss=" + iss + "  jwks=" + url));
        System.out.println("  faults: " + payer.baseUrl() + "/admin/faults");
    }
}
