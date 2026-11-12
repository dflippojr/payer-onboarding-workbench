package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
 *       {@code aud} is exactly the URL of the service called. Its times must be valid: an
 *       {@code iat} is required and at most an hour ahead of the payer's clock, {@code exp} minus
 *       {@code iat} is at most five minutes, and a {@code jti} is never reused while its assertion is
 *       still valid. Discovery is open.</li>
 * </ul>
 *
 * <p>Outcomes by code: E0250 is conditional, with prior authorization and clinical
 * documentation needed; E0424 is covered with no authorization; anything else is not covered.
 */
public final class FabrikamPayer extends MockPayer {

    public static final String DISPLAY_NAME = "Fabrikam Benefits (synthetic)";
    public static final String IG_VERSION = "2.0.1";
    public static final int DEFAULT_PORT = 8182;

    /**
     * The audience base the payer expects while {@link Fault#WRONG_AUDIENCE_REJECT} is on: a public
     * gateway URL. Exported replays show the payer at {@code https://crd.fabrikam-benefits.example},
     * so this must stay a different host for the replayed {@code aud} to still mismatch.
     */
    public static final String WRONG_AUDIENCE_BASE = "https://api.fabrikam-benefits.example";

    /** The pre-2.1 CRD card type code system the reference implementation used. */
    static final String CARD_TYPE_SYSTEM = "http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp";

    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(JWSAlgorithm.RS384, JWSAlgorithm.ES384);

    /**
     * The longest client assertion this mock accepts, measured as exp minus iat. SMART Backend Services
     * caps it at five minutes; this is the mock's profile choice, not a CDS Hooks rule.
     */
    private static final Duration MAX_ASSERTION_LIFETIME = Duration.ofMinutes(5);

    /**
     * How far an assertion's iat may be ahead of the payer's clock. The payer's clock behind by an hour (the
     * matrix's clock/cds-hooks-jwt-payer-behind-1h row) is the widest skew accepted; anything further is refused.
     */
    private static final Duration MAX_ISSUED_AHEAD = Duration.ofHours(1);

    /**
     * Fabrikam's client-JWT rules. Each replay-cache entry is kept until its exp: at most five minutes after iat, and
     * iat is at most an hour ahead of now, so an entry lives at most about 65 minutes past the current time. The
     * sweeper removes expired entries even when no request arrives.
     */
    private static final ClientJwtValidator.Policy POLICY = new ClientJwtValidator.Policy(
            ALLOWED_ALGORITHMS, false,
            new ClientJwtValidator.Messages(
                    "CDS Hooks client JWT required in Authorization: Bearer",
                    "Bearer token is not a signed JWT",
                    algorithm -> "JWT alg " + algorithm + " is not accepted; use RS384 or ES384",
                    issuer -> "Unknown iss '" + issuer + "'; register the client with Fabrikam first",
                    "JWT header has no kid",
                    "JWT has no exp",
                    "JWT expired",
                    expiry -> "JWT expired at " + expiry,
                    "JWT has no jti",
                    jti -> "jti '" + jti + "' was already used (replay)"),
            null,
            new ClientJwtValidator.IssuedAtRule(MAX_ASSERTION_LIFETIME, MAX_ISSUED_AHEAD, "JWT has no iat",
                    lifetime -> "JWT lifetime (exp minus iat) must be positive and at most 5 minutes, got "
                            + lifetime.toSeconds() + " seconds",
                    // The matrix's one-hour-behind payer clock needs an iat an hour ahead: the largest lead accepted.
                    ahead -> "JWT iat is ahead of the payer's clock by more than 1 hour, got "
                            + ahead.toSeconds() + " seconds"));

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

    /** How often a running payer drops expired jtis, so an idle payer does not keep them. */
    static final Duration SWEEP_INTERVAL = Duration.ofSeconds(1);

    private final Map<String, URI> jwksUrls;
    private final ClientJwtValidator validator;
    private volatile ScheduledExecutorService sweeper;

    private FabrikamPayer(Builder builder) {
        super(builder);
        this.jwksUrls = Map.copyOf(builder.jwksUrls);
        this.validator = new ClientJwtValidator(jwksUrls, FabrikamPayer::unauthorized, clock, POLICY);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public synchronized FabrikamPayer start(int port) throws IOException {
        super.start(port);
        sweeper = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "fabrikam-replay-sweep");
            thread.setDaemon(true);
            return thread;
        });
        long interval = SWEEP_INTERVAL.toMillis();
        sweeper.scheduleAtFixedRate(this::sweepExpiredJtis, interval, interval, TimeUnit.MILLISECONDS);
        return this;
    }

    @Override
    public synchronized void stop() {
        super.stop();
        if (sweeper != null) {
            sweeper.shutdownNow();
            sweeper = null;
        }
    }

    /** Drops every jti whose exp has passed on the payer's clock. */
    void sweepExpiredJtis() {
        validator.sweepExpired();
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

    /** The jtis this payer is holding against replay, for tests. */
    int replayCacheSize() {
        return validator.replayCacheSize();
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
        boolean wrongAudience = faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT);
        String expectedAudience = (wrongAudience ? WRONG_AUDIENCE_BASE : publicBaseUrl()) + request.path();
        validator.validate(request.bearerToken(), expectedAudience, wrongAudience,
                faults().isEnabled(Fault.EXPIRED_TOKEN_401), (issuer, claims) -> { });
    }

    private static HttpError unauthorized(String description) {
        return new HttpError(401, "unauthorized", description)
                .header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\""
                        + description.replace("\\", "\\\\").replace("\"", "\\\"") + "\"");
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
            // CDS Hooks 2.0: selectionBehavior MUST be provided when a card has suggestions.
            card.put("selectionBehavior", "at-most-one");
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
    public static final class Builder extends BaseBuilder<Builder> {

        private final Map<String, URI> jwksUrls = new LinkedHashMap<>();

        private Builder() { }

        /** Registers a client by its {@code iss} and the URL its public JWK Set is served from. */
        public Builder client(String issuer, URI jwksUrl) {
            jwksUrls.put(Objects.requireNonNull(issuer, "issuer"), Objects.requireNonNull(jwksUrl, "jwksUrl"));
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
        StandaloneArgs.stopOnShutdown(launch(args, System.out));
    }

    /** Starts a payer as {@link #main} would and prints how to reach it; the caller stops it. */
    static FabrikamPayer launch(String[] args, PrintStream out) throws IOException {
        StandaloneArgs options = StandaloneArgs.parse(args);
        Builder builder = builder().publicBaseUrl(options.single("public-base-url", null));
        options.clients(client -> "--client expects ISS=JWKS_URL, got '" + client + "'", builder::client);
        FabrikamPayer payer = options.startFrom(builder.build(), DEFAULT_PORT);
        StandaloneArgs.printHeader(out, payer);
        if (payer.jwksUrls.isEmpty()) {
            out.println("  no clients registered: every hook call will get 401 (add --client ISS=JWKS_URL)");
        }
        payer.jwksUrls.forEach((iss, url) -> out.println("  client iss=" + iss + "  jwks=" + url));
        out.println("  faults: " + payer.baseUrl() + "/admin/faults");
        return payer;
    }
}
