package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Payer A, "Northwind Health (synthetic)": a spec-conformant CRD 2.2.1 payer.
 *
 * <ul>
 *   <li>Discovery lists {@code order-sign} and {@code order-select} with the
 *       standard CRD prefetch keys {@code patient}, {@code encounter} and {@code coverage}.</li>
 *   <li>Auth is OAuth2 client credentials with {@code client_secret_basic} at
 *       {@value #TOKEN_PATH}. Access tokens are opaque, expire after the
 *       configured lifetime and are bound to {@link #publicBaseUrl()} as their audience.
 *       Hook calls without a valid token get 401; discovery is open.</li>
 *   <li>{@code order-sign} returns coverage information as {@code systemActions}
 *       (one {@code update} per draft order), plus one card per order.</li>
 * </ul>
 *
 * <p>Outcomes are keyed by the order's code: E0250 is covered with prior
 * authorization required, E0424 is covered with no authorization, and anything
 * else is conditional with clinical documentation needed.
 */
public final class NorthwindPayer extends MockPayer {

    public static final String DISPLAY_NAME = "Northwind Health (synthetic)";
    public static final String IG_VERSION = "2.2.1";
    public static final String TOKEN_PATH = "/oauth/token";
    public static final Duration DEFAULT_TOKEN_LIFETIME = Duration.ofMinutes(5);
    public static final int DEFAULT_PORT = 8181;

    /** The audience the resource server expects while {@link Fault#WRONG_AUDIENCE_REJECT} is on. */
    public static final String WRONG_AUDIENCE = "https://crd.northwind-health.example";

    static final String CARD_TYPE_SYSTEM = "http://hl7.org/fhir/us/davinci-crd/CodeSystem/cardType";

    private static final Map<String, CoverageDetermination> RULES = Map.of(
            "E0250", new CoverageDetermination("covered", "auth-needed", List.of(),
                    "Covered; prior authorization required"),
            "E0424", new CoverageDetermination("covered", "no-auth", List.of(),
                    "Covered; no prior authorization needed"));
    private static final CoverageDetermination OTHERWISE = new CoverageDetermination(
            "conditional", "no-auth", List.of("clinical"), "Coverage is conditional; clinical documentation needed");

    private static final List<ServiceDefinition> SERVICES = List.of(
            new ServiceDefinition("order-sign", "order-sign", "Northwind coverage requirements (order-sign)",
                    "Coverage and prior authorization requirements for orders being signed.", standardPrefetch()),
            new ServiceDefinition("order-select", "order-select", "Northwind coverage requirements (order-select)",
                    "Early coverage guidance for orders as they are selected.", standardPrefetch()));

    private final Map<String, String> clientSecrets;
    private final Duration tokenLifetime;
    private final Map<String, IssuedToken> tokens = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private NorthwindPayer(Builder builder) {
        super(builder.clock, builder.publicBaseUrl);
        this.clientSecrets = Map.copyOf(builder.clientSecrets);
        this.tokenLifetime = builder.tokenLifetime;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public NorthwindPayer start(int port) throws IOException {
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

    /** The full token endpoint URL, for a {@code ConnectionRecord}. */
    public String tokenEndpoint() {
        return baseUrl() + TOKEN_PATH;
    }

    private static Map<String, String> standardPrefetch() {
        Map<String, String> prefetch = new LinkedHashMap<>();
        prefetch.put("patient", "Patient/{{context.patientId}}");
        prefetch.put("encounter", "Encounter/{{context.encounterId}}");
        prefetch.put("coverage", "Coverage?patient={{context.patientId}}&status=active");
        return prefetch;
    }

    // ---- OAuth2 token endpoint ----

    @Override
    protected Response handleOther(Request request) {
        if (!request.path().equals(TOKEN_PATH)) {
            return null;
        }
        if (!request.method().equals("POST")) {
            throw new HttpError(405, "method_not_allowed", "Use POST");
        }
        String clientId = authenticateClient(request.header("Authorization"));
        Map<String, String> form = Request.formParameters(request.body());
        if (!"client_credentials".equals(form.get("grant_type"))) {
            throw new HttpError(400, "unsupported_grant_type", "Only grant_type=client_credentials is supported");
        }

        Instant now = clock.instant();
        // Keep expired tokens for a while so their use is reported as "expired", not "unknown".
        tokens.values().removeIf(t -> !now.isBefore(t.expiresAt().plus(Duration.ofHours(1))));
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        tokens.put(token, new IssuedToken(clientId, publicBaseUrl(), now.plus(tokenLifetime)));

        ObjectNode body = mapper.createObjectNode()
                .put("access_token", token)
                .put("token_type", "Bearer")
                .put("expires_in", tokenLifetime.toSeconds());
        if (form.get("scope") != null) {
            body.put("scope", form.get("scope"));
        }
        return Response.json(mapper, 200, body)
                .withHeader("Cache-Control", "no-store")
                .withHeader("Pragma", "no-cache");
    }

    /** {@code client_secret_basic}: both parts are form-urlencoded before Base64 (RFC 6749 §2.3.1). */
    private String authenticateClient(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            throw invalidClient("Client authentication required (client_secret_basic)");
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(authorization.substring(6).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw invalidClient("Malformed Basic credentials");
        }
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            throw invalidClient("Malformed Basic credentials");
        }
        Map<String, String> parts = Request.formParameters(
                "id=" + decoded.substring(0, colon) + "&secret=" + decoded.substring(colon + 1));
        String expected = clientSecrets.get(parts.get("id"));
        if (expected == null || !MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), parts.get("secret").getBytes(StandardCharsets.UTF_8))) {
            throw invalidClient("Unknown client or wrong secret");
        }
        return parts.get("id");
    }

    private static HttpError invalidClient(String description) {
        return new HttpError(401, "invalid_client", description)
                .header("WWW-Authenticate", "Basic realm=\"northwind\"");
    }

    // ---- resource server ----

    @Override
    protected void authenticate(Request request) {
        String token = request.bearerToken();
        if (token == null) {
            throw new HttpError(401, "unauthorized", "Authorization: Bearer access token required")
                    .header("WWW-Authenticate", "Bearer realm=\"northwind\"");
        }
        IssuedToken issued = tokens.get(token);
        if (issued == null) {
            throw invalidToken("Unknown or revoked access token");
        }
        if (faults().isEnabled(Fault.EXPIRED_TOKEN_401)) {
            throw invalidToken("The access token expired").fault(Fault.EXPIRED_TOKEN_401);
        }
        if (!clock.instant().isBefore(issued.expiresAt())) {
            throw invalidToken("The access token expired");
        }
        String expectedAudience = faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT) ? WRONG_AUDIENCE : publicBaseUrl();
        if (!issued.audience().equals(expectedAudience)) {
            HttpError error = invalidToken("The access token audience '" + issued.audience()
                    + "' does not match this resource server ('" + expectedAudience + "')");
            throw faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT) ? error.fault(Fault.WRONG_AUDIENCE_REJECT) : error;
        }
    }

    private static HttpError invalidToken(String description) {
        return new HttpError(401, "invalid_token", description)
                .header("WWW-Authenticate", "Bearer realm=\"northwind\", error=\"invalid_token\", error_description=\""
                        + description.replace("\"", "'") + "\"");
    }

    // ---- hooks ----

    @Override
    protected ObjectNode handleHook(ServiceDefinition service, ObjectNode hookRequest) {
        String hookInstance = hookRequest.path("hookInstance").asText();
        JsonNode coverageBundle = hookRequest.path("prefetch").path("coverage");
        ObjectNode response = mapper.createObjectNode();
        ArrayNode cards = response.putArray("cards");
        ArrayNode systemActions = response.putArray("systemActions");

        for (JsonNode order : draftOrders(hookRequest.path("context").path("draftOrders"))) {
            String code = orderCode(order);
            String label = orderLabel(order);
            CoverageDetermination determination = CoverageDetermination.lookup(RULES, code, OTHERWISE);
            String seed = hookInstance + "|" + label;
            if (service.hook().equals("order-select")) {
                cards.add(card(seed, (code == null ? "Order" : code) + ": " + determination.summary(), "info",
                        "Preliminary guidance. Northwind returns the coverage determination at order-sign.",
                        CARD_TYPE_SYSTEM, "coverage-info", "Coverage Information"));
                continue;
            }
            String indicator = "auth-needed".equals(determination.paNeeded()) ? "warning" : "info";
            cards.add(card(seed, (code == null ? "Order" : code) + ": " + determination.summary(), indicator,
                    "See the coverage information recorded on " + label + ".",
                    CARD_TYPE_SYSTEM, "coverage-info", "Coverage Information"));
            ObjectNode action = systemActions.addObject();
            action.put("type", "update");
            action.put("description", "Record Northwind coverage information on " + label);
            action.set("resource", withCoverageInformation(order, determination, coverageReference(order, coverageBundle),
                    "coverage-assertion-id", "NW-" + label.replace('/', '-') + "-" + (code == null ? "NOCODE" : code)));
        }
        return response;
    }

    private record IssuedToken(String clientId, String audience, Instant expiresAt) { }

    /** Configures a {@link NorthwindPayer}. Register at least one client before calling {@link #build()}. */
    public static final class Builder {

        private final Map<String, String> clientSecrets = new LinkedHashMap<>();
        private Duration tokenLifetime = DEFAULT_TOKEN_LIFETIME;
        private Clock clock = Clock.systemUTC();
        private String publicBaseUrl;

        private Builder() { }

        /** Registers an OAuth2 client. Generate the secret at runtime; never hard-code one. */
        public Builder client(String clientId, String clientSecret) {
            clientSecrets.put(Objects.requireNonNull(clientId, "clientId"), Objects.requireNonNull(clientSecret, "clientSecret"));
            return this;
        }

        public Builder tokenLifetime(Duration lifetime) {
            if (lifetime.isNegative() || lifetime.isZero()) {
                throw new IllegalArgumentException("token lifetime must be positive");
            }
            this.tokenLifetime = lifetime;
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

        public NorthwindPayer build() {
            return new NorthwindPayer(this);
        }
    }

    /**
     * Runs Northwind standalone until the process is stopped.
     * Options: {@code --port N} (default {@value #DEFAULT_PORT}; 0 for ephemeral),
     * {@code --client-id ID}, {@code --client-secret SECRET} (generated and printed if omitted),
     * {@code --token-lifetime-seconds N}, {@code --public-base-url URL}.
     */
    public static void main(String[] args) throws IOException {
        StandaloneArgs options = StandaloneArgs.parse(args);
        String clientId = options.single("client-id", "workbench-demo");
        String secret = options.single("client-secret", null);
        boolean generated = secret == null;
        if (generated) {
            secret = StandaloneArgs.randomSecret();
        }
        NorthwindPayer payer = builder()
                .client(clientId, secret)
                .tokenLifetime(Duration.ofSeconds(Long.parseLong(
                        options.single("token-lifetime-seconds", String.valueOf(DEFAULT_TOKEN_LIFETIME.toSeconds())))))
                .publicBaseUrl(options.single("public-base-url", null))
                .build()
                .start(Integer.parseInt(options.single("port", String.valueOf(DEFAULT_PORT))));
        Runtime.getRuntime().addShutdownHook(new Thread(payer::stop));
        System.out.println(DISPLAY_NAME + " listening at " + payer.baseUrl() + " (CRD " + IG_VERSION + ")");
        System.out.println("  token endpoint: " + payer.tokenEndpoint() + "  (client_secret_basic)");
        System.out.println("  client id:      " + clientId);
        if (generated) {
            System.out.println("  client secret:  " + secret + "  (generated for this run; pass --client-secret to fix it)");
        }
        System.out.println("  faults:         " + payer.baseUrl() + "/admin/faults");
    }
}
