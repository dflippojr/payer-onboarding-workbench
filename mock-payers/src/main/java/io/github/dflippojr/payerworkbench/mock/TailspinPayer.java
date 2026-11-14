package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Synthetic SMART Backend Services payer; keys and tokens are held in memory only. */
public final class TailspinPayer extends MockPayer {
    public static final String DISPLAY_NAME = "Tailspin Health Plan (synthetic)";
    public static final String IG_VERSION = "2.2.1";
    public static final int DEFAULT_PORT = 8183;
    public static final String TOKEN_PATH = "/oauth/token";
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String WRONG_AUDIENCE = "https://auth.tailspin-health.example/token";
    private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS384, JWSAlgorithm.ES384);
    private static final List<ServiceDefinition> SERVICES = List.of(
            new ServiceDefinition("order-sign", "order-sign", "Tailspin coverage requirements (order-sign)",
                    "Coverage and prior authorization requirements for orders being signed.", NorthwindPayer.standardPrefetch()),
            new ServiceDefinition("order-select", "order-select", "Tailspin coverage requirements (order-select)",
                    "Early coverage guidance for orders being selected.", NorthwindPayer.standardPrefetch()));
    private static final String EXP_WINDOW = "exp must be in the future and no more than 5 minutes ahead";
    /** SMART Backend Services: exp at most five minutes ahead; no iat rule. */
    private static final ClientJwtValidator.Policy POLICY = new ClientJwtValidator.Policy(
            ALGORITHMS, true,
            new ClientJwtValidator.Messages(
                    "client_assertion is required",
                    "client_assertion must be a signed JWT",
                    algorithm -> "alg must be RS384 or ES384",
                    issuer -> "iss is not a registered client id",
                    "kid is required",
                    "exp is required",
                    null,
                    expiry -> EXP_WINDOW,
                    "jti is required",
                    jti -> "jti was already used (replay)"),
            new ClientJwtValidator.ExpiryCap(Duration.ofMinutes(5), EXP_WINDOW),
            null);
    private final Map<String, URI> clients;
    private final ClientJwtValidator validator;
    private final Map<String, Instant> tokens = new ConcurrentHashMap<>();

    private TailspinPayer(Builder builder) {
        super(builder);
        clients = Map.copyOf(builder.clients);
        validator = new ClientJwtValidator(clients, TailspinPayer::invalidClient, clock, POLICY);
    }
    public static Builder builder() { return new Builder(); }
    @Override public String displayName() { return DISPLAY_NAME; }
    @Override public String igVersion() { return IG_VERSION; }
    @Override public List<ServiceDefinition> services() { return SERVICES; }
    @Override public synchronized TailspinPayer start(int port) throws IOException {
        super.start(port);
        return this;
    }
    public String tokenEndpoint() { return baseUrl() + TOKEN_PATH; }

    @Override
    protected Response handleOther(Request request) {
        if (!TOKEN_PATH.equals(request.path())) { return null; }
        if (!"POST".equals(request.method())) { throw new HttpError(405, "method_not_allowed", "Use POST"); }
        Map<String, String> form = Request.formParameters(request.body());
        if (!"client_credentials".equals(form.get("grant_type"))) {
            throw new HttpError(400, "unsupported_grant_type", "Use grant_type=client_credentials");
        }
        if (!ASSERTION_TYPE.equals(form.get("client_assertion_type"))) {
            throw invalidClient("client_assertion_type must be " + ASSERTION_TYPE);
        }
        String clientId = validateAssertion(form.get("client_assertion"), form.get("client_id"));
        Instant now = clock.instant();
        tokens.values().removeIf(exp -> !now.isBefore(exp));
        String token = newAccessToken(clientId, now, now.plus(Duration.ofMinutes(5)));
        tokens.put(token, now.plus(Duration.ofMinutes(5)));
        return tokenResponse(token, 300, form.get("scope"));
    }

    /** @return the authenticated client id */
    private String validateAssertion(String assertion, String clientId) {
        boolean wrongAudience = faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT);
        String expected = wrongAudience ? WRONG_AUDIENCE : publicBaseUrl() + TOKEN_PATH;
        return validator.validate(assertion, expected, wrongAudience, false, (issuer, claims) -> {
            if (!issuer.equals(claims.getSubject()) || (clientId != null && !issuer.equals(clientId))) {
                throw invalidClient("iss and sub must equal the registered client id");
            }
        });
    }
    private static HttpError invalidClient(String message) { return new HttpError(401, "invalid_client", message); }

    @Override
    protected void authenticate(Request request) {
        String token = request.bearerToken();
        Instant exp = token == null ? null : tokens.get(token);
        if (exp == null) { throw new HttpError(401, "invalid_token", "Unknown or missing access token"); }
        if (faults().isEnabled(Fault.EXPIRED_TOKEN_401)) {
            throw new HttpError(401, "invalid_token", "The access token expired").fault(Fault.EXPIRED_TOKEN_401);
        }
        if (!clock.instant().isBefore(exp)) { throw new HttpError(401, "invalid_token", "The access token expired"); }
    }
    @Override protected ObjectNode handleHook(ServiceDefinition service, ObjectNode request) {
        return StandardCoverage.response(this, service, request, "TS");
    }

    public static final class Builder extends BaseBuilder<Builder> {
        private final Map<String, URI> clients = new LinkedHashMap<>();
        private Builder() { }
        public Builder client(String clientId, URI jwksUrl) {
            clients.put(Objects.requireNonNull(clientId), Objects.requireNonNull(jwksUrl));
            return this;
        }
        public TailspinPayer build() { return new TailspinPayer(this); }
    }
    public static void main(String[] args) throws IOException {
        StandaloneArgs.stopOnShutdown(launch(args, System.out));
    }
    static TailspinPayer launch(String[] args, PrintStream out) throws IOException {
        StandaloneArgs options = StandaloneArgs.parse(args);
        Builder builder = builder().publicBaseUrl(options.single("public-base-url", null));
        options.clients(client -> "--client expects ID=JWKS_URL", builder::client);
        TailspinPayer payer = options.startFrom(builder.build(), DEFAULT_PORT);
        StandaloneArgs.printHeader(out, payer);
        out.println("  token endpoint: " + payer.tokenEndpoint() + " (private_key_jwt)");
        payer.clients.forEach((id, url) -> out.println("  client id=" + id + " jwks=" + url));
        out.println("  faults: " + payer.baseUrl() + "/admin/faults");
        return payer;
    }
}
