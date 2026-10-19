package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.mock.MockPayerHooks;
import io.github.dflippojr.payerworkbench.samples.PrefetchVariant;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.github.dflippojr.payerworkbench.samples.SampleMetadata;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * The conformance corpus in {@code src/test/resources/conformance-corpus/}: the healthy
 * responses of the three mock payers to every sample they serve, plus mutants of them, each
 * breaking one rule of CDS Hooks 2.0 or Da Vinci CRD 2.2.1. {@link ConformanceCorpusTest}
 * fails when the committed files drift from what this class generates; run it with
 * {@code -Dconformance.corpus.write=true} to rewrite them. The HL7 FHIR Validator judges the
 * committed files in {@link HL7ValidatorConformanceTest}.
 */
final class ConformanceCorpus {

    /** The corpus directory, relative to the diagnostics module (Maven's working directory for tests). */
    static final Path DIR = Path.of("src/test/resources/conformance-corpus");
    static final String INDEX = "index.json";
    static final String ALLOWLIST = "conformance-allowlist.json";

    /** Fixed so coverage-information {@code date} values never change between runs. */
    static final Instant CLOCK = Instant.parse("2026-03-02T15:00:00Z");

    static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** Healthy systemActions base (Northwind) and suggestions base (Fabrikam) for the mutants. */
    static final String SYSTEM_ACTIONS_BASE = "healthy-northwind-order-sign-hospital-bed";
    static final String SUGGESTIONS_BASE = "healthy-fabrikam-order-sign-hospital-bed";

    /** One corpus file: a CDS Hooks response body. */
    record Item(String id, String base, String rule, String description, ObjectNode body) {
        String file() {
            return id + ".json";
        }

        ObjectNode indexEntry() {
            ObjectNode entry = MAPPER.createObjectNode().put("id", id).put("file", file());
            if (base != null) {
                entry.put("base", base).put("rule", rule);
            }
            return entry.put("description", description);
        }
    }

    private ConformanceCorpus() {
    }

    static List<Item> items() {
        List<Item> items = new ArrayList<>(healthy());
        ObjectNode system = find(items, SYSTEM_ACTIONS_BASE).body();
        ObjectNode suggestions = find(items, SUGGESTIONS_BASE).body();
        items.addAll(mutants(system, suggestions));
        return items;
    }

    static Item find(List<Item> items, String id) {
        return items.stream().filter(i -> i.id().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalStateException("no corpus item " + id));
    }

    /** Each mock payer's answer to each sample whose hook it serves, in the prefetch style it advertises. */
    static List<Item> healthy() {
        SampleCatalog catalog = new SampleCatalog();
        List<Item> items = new ArrayList<>();
        for (MockPayer payer : MockPayerHooks.payers(Clock.fixed(CLOCK, ZoneOffset.UTC))) {
            String name = payer.displayName().split(" ")[0].toLowerCase(Locale.ROOT);
            PrefetchVariant variant = payer instanceof FabrikamPayer ? PrefetchVariant.PAYER_B : PrefetchVariant.STANDARD;
            for (SampleMetadata meta : catalog.list()) {
                ObjectNode request = (ObjectNode) catalog.load(meta.id(), variant).toJson();
                if (request.path("prefetch").isEmpty()) {
                    // The no-prefetch sample is answered with an error, not a CDS Hooks response.
                    continue;
                }
                for (MockPayer.ServiceDefinition service : payer.services()) {
                    if (service.hook().equals(meta.hook())) {
                        items.add(new Item("healthy-" + name + "-" + meta.id(), null, null,
                                payer.displayName() + " answering sample " + meta.id() + " on " + service.id(),
                                MockPayerHooks.answer(payer, service, request)));
                    }
                }
            }
        }
        return items;
    }

    private record Mutation(String id, String rule, String description, boolean suggestions, Consumer<ObjectNode> edit) { }

    private static final String CI_URL = CoverageLocationCheck.COVERAGE_INFORMATION_URL;

    /** Each mutation edits a copy of one healthy response. */
    private static final List<Mutation> MUTATIONS = List.of(
            card("card-summary-removed", "required element removed",
                    "cards[0].summary removed (CDS Hooks 2.0 Card: summary REQUIRED)",
                    card -> card.remove("summary")),
            card("card-indicator-removed", "required element removed",
                    "cards[0].indicator removed (CDS Hooks 2.0 Card: indicator REQUIRED)",
                    card -> card.remove("indicator")),
            card("card-source-label-removed", "required element removed",
                    "cards[0].source.label removed (CDS Hooks 2.0 Source: label REQUIRED)",
                    card -> ((ObjectNode) card.path("source")).remove("label")),
            new Mutation("cards-removed", "required element removed",
                    "the cards array removed (CDS Hooks 2.0 response: cards REQUIRED, [] when empty)", false,
                    body -> body.remove("cards")),
            card("card-source-repeated", "cardinality broken",
                    "cards[0].source sent as an array of two sources (CDS Hooks 2.0 Card: source is one object)",
                    card -> {
                        JsonNode source = card.remove("source");
                        card.putArray("source").add(source).add(source.deepCopy());
                    }),
            card("card-indicator-unknown-code", "wrong code",
                    "cards[0].indicator is hard-stop (CDS Hooks 2.0: info, warning or critical)",
                    card -> card.put("indicator", "hard-stop")),
            card("card-summary-too-long", "cardinality broken",
                    "cards[0].summary is 160 characters (CDS Hooks 2.0: <140 characters)",
                    card -> card.put("summary", "x".repeat(160))),
            coverage("ci-covered-removed", "required element removed",
                    "the covered sub-extension removed (CRD 2.2.1 ext-coverage-information: covered 1..1)",
                    ci -> removeSub(ci, "covered")),
            coverage("ci-coverage-assertion-id-removed", "required element removed",
                    "the coverage-assertion-id sub-extension removed (CRD 2.2.1: coverage-assertion-id 1..1)",
                    ci -> removeSub(ci, "coverage-assertion-id")),
            coverage("ci-date-repeated", "cardinality broken",
                    "a second date sub-extension added (CRD 2.2.1: date 1..1)",
                    ci -> subs(ci).addObject().put("url", "date").put("valueDate", "2026-03-03")),
            coverage("ci-covered-unknown-code", "wrong code",
                    "covered is yes (CRD 2.2.1: required binding to coverageInfo)",
                    ci -> sub(ci, "covered").put("valueCode", "yes")),
            coverage("ci-reason-wrong-code-system", "wrong code system",
                    "a reason coding from a code system outside coverageAssertionReasons, with no text "
                            + "(CRD 2.2.1 invariant crd-ci-q7)",
                    ci -> subs(ci).addObject().put("url", "reason").putObject("valueCodeableConcept")
                            .putArray("coding").addObject()
                            .put("system", "http://example.org/fhir/CodeSystem/not-crd").put("code", "gold-card")),
            coverage("ci-covered-wrong-value-type", "wrong coverage-information extension structure",
                    "covered carried as valueString instead of valueCode",
                    ci -> {
                        ObjectNode covered = sub(ci, "covered");
                        covered.put("valueString", covered.remove("valueCode").asText());
                    }),
            coverage("ci-value-on-complex-extension", "wrong coverage-information extension structure",
                    "a valueString on the complex extension itself (FHIR ext-1: value or extensions, not both)",
                    ci -> ci.put("valueString", "covered")),
            coverage("ci-conditional-without-info-needed", "wrong coverage-information extension structure",
                    "covered is conditional with no info-needed (CRD 2.2.1 invariant crd-ci-q3)",
                    ci -> sub(ci, "covered").put("valueCode", "conditional")),
            coverage("ci-coverage-not-a-coverage", "wrong coverage-information extension structure",
                    "coverage references a Patient (CRD 2.2.1: coverage is Reference(Coverage))",
                    ci -> ((ObjectNode) sub(ci, "coverage").path("valueReference"))
                            .put("reference", "Patient/pat-synthetic-001")),
            coverage("ci-date-not-a-date", "wrong coverage-information extension structure",
                    "date is 2026-13-01 (FHIR date)",
                    ci -> sub(ci, "date").put("valueDate", "2026-13-01")),
            coverage("ci-unknown-sub-extension", "unknown extension",
                    "an unknown relative sub-extension made-up-flag (the profile slices sub-extensions by url)",
                    ci -> subs(ci).addObject().put("url", "made-up-flag").put("valueBoolean", true)),
            coverage("ci-unknown-absolute-extension", "unknown extension",
                    "an unknown absolute-URL extension inside coverage-information",
                    ci -> subs(ci).addObject().put("url", "http://example.org/fhir/StructureDefinition/unknown")
                            .put("valueBoolean", true)),
            new Mutation("ci-on-coding", "wrong coverage-information extension structure",
                    "the coverage-information extension moved from the order onto its code's coding "
                            + "(CRD 2.2.1: the extension's context is the order resources)", false,
                    body -> {
                        ObjectNode order = (ObjectNode) body.path("systemActions").path(0).path("resource");
                        ArrayNode extensions = (ArrayNode) order.path("extension");
                        JsonNode ci = extensions.remove(indexOf(extensions, CI_URL));
                        if (extensions.isEmpty()) {
                            order.remove("extension");
                        }
                        ((ObjectNode) order.path("codeCodeableConcept").path("coding").path(0))
                                .putArray("extension").add(ci);
                    }),
            new Mutation("card-selection-behavior-removed", "required element removed",
                    "selectionBehavior removed from a card with suggestions (CDS Hooks 2.0 Card: required when "
                            + "suggestions are present)", true,
                    body -> ((ObjectNode) body.path("cards").path(0)).remove("selectionBehavior")),
            new Mutation("card-selection-behavior-unknown-code", "wrong code",
                    "selectionBehavior is all (CDS Hooks 2.0: at-most-one or any)", true,
                    body -> ((ObjectNode) body.path("cards").path(0)).put("selectionBehavior", "all")),
            new Mutation("suggestion-ci-covered-removed", "required element removed",
                    "covered removed from coverage-information inside a card suggestion", true,
                    body -> removeSub(firstCoverageInformation(body.path("cards")), "covered")));

    private static Mutation card(String id, String rule, String description, Consumer<ObjectNode> edit) {
        return new Mutation(id, rule, description, false, body -> edit.accept((ObjectNode) body.path("cards").path(0)));
    }

    private static Mutation coverage(String id, String rule, String description, Consumer<ObjectNode> edit) {
        return new Mutation(id, rule, description, false,
                body -> edit.accept(firstCoverageInformation(body.path("systemActions"))));
    }

    static List<Item> mutants(ObjectNode systemActionsBase, ObjectNode suggestionsBase) {
        List<Item> items = new ArrayList<>();
        for (Mutation m : MUTATIONS) {
            ObjectNode body = (m.suggestions() ? suggestionsBase : systemActionsBase).deepCopy();
            m.edit().accept(body);
            items.add(new Item("mutant-" + m.id(), m.suggestions() ? SUGGESTIONS_BASE : SYSTEM_ACTIONS_BASE,
                    m.rule(), m.description(), body));
        }
        return items;
    }

    /** The first coverage-information extension anywhere under {@code node}. */
    static ObjectNode firstCoverageInformation(JsonNode node) {
        ObjectNode found = search(node);
        if (found == null) {
            throw new IllegalStateException("no coverage-information extension");
        }
        return found;
    }

    private static ObjectNode search(JsonNode node) {
        if (node.isObject() && CI_URL.equals(node.path("url").asText())) {
            return (ObjectNode) node;
        }
        for (JsonNode child : node) {
            ObjectNode found = search(child);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static ArrayNode subs(ObjectNode ci) {
        return (ArrayNode) ci.path("extension");
    }

    private static ObjectNode sub(ObjectNode ci, String url) {
        return (ObjectNode) subs(ci).get(indexOf(subs(ci), url));
    }

    private static void removeSub(ObjectNode ci, String url) {
        subs(ci).remove(indexOf(subs(ci), url));
    }

    private static int indexOf(ArrayNode extensions, String url) {
        for (int i = 0; i < extensions.size(); i++) {
            if (url.equals(extensions.get(i).path("url").asText())) {
                return i;
            }
        }
        throw new IllegalStateException("no extension " + url);
    }

    /** The index file: every item, in corpus order. */
    static ArrayNode index(List<Item> items) {
        ArrayNode index = MAPPER.createArrayNode();
        items.forEach(item -> index.add(item.indexEntry()));
        return index;
    }

    static String json(JsonNode node) {
        try {
            // Jackson indents with the platform line separator; the committed corpus is LF on every OS.
            return MAPPER.writeValueAsString(node).replace("\r\n", "\n") + "\n";
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static JsonNode read(Path file) {
        try {
            return MAPPER.readTree(Files.readString(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Rewrites every corpus file and the index, and deletes files no longer generated. */
    static void write(List<Item> items) throws IOException {
        Files.createDirectories(DIR);
        try (var existing = Files.list(DIR)) {
            for (Path file : existing.toList()) {
                String name = file.getFileName().toString();
                if (name.endsWith(".json") && !name.equals(ALLOWLIST)) {
                    Files.delete(file);
                }
            }
        }
        for (Item item : items) {
            Files.writeString(DIR.resolve(item.file()), json(item.body()));
        }
        Files.writeString(DIR.resolve(INDEX), json(index(items)));
    }
}
