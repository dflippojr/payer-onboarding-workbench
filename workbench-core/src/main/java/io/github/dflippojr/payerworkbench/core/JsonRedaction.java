package io.github.dflippojr.payerworkbench.core;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.core.io.JsonStringEncoder;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonReadFeature;

/**
 * The structural path of {@link Redactor#redact(String)} (#377, stage 1): text that is one JSON value is read with
 * Jackson, redacted on the tree and written back with the escape spellings Jackson writes.
 *
 * <p>The parser is strict (no comments, single quotes, unquoted names, trailing commas or unescaped control
 * characters), and an object whose names repeat once decoded, or nesting deeper than {@link #MAX_DEPTH}, makes the text
 * {@link Unreadable}: {@link Redactor} masks it whole. Text that is not one JSON value goes to the text engine as
 * before. On the tree:
 *
 * <ul>
 *   <li>the value of a member named like a secret or a credential header ({@link Redactor#isSecretKey(String)}) is
 *       the mask; an {@code Authorization}-style string keeps its scheme ({@code Bearer [REDACTED]}), and so does
 *       each string of an array that holds only such strings, as a header's values; {@code null} stays {@code null};
 *   <li>in an object with a {@code kty} member (a JWK) the value of each {@link Redactor#JWK_PRIVATE_MEMBERS} member
 *       is the mask, also {@code null} kept;
 *   <li>every other string, and every member name, is decoded and redacted again: a string that is itself one JSON
 *       value takes this path one level deeper, down to {@link #MAX_LEVELS}, and any other string goes to the text
 *       engine, which then reads it without the escape spellings the parser removed.
 * </ul>
 *
 * <p>The output keeps the text's whitespace between tokens, its member order and each number's spelling; only the
 * strings are written anew. Each level reads only strings the level above decoded, so the work is linear in the text
 * for each of the {@link #MAX_LEVELS} levels.
 *
 * <p>{@link Redactor#redactTree(Object)} reads JSON-shaped plain data into the same nodes ({@link #redactTree}) and
 * redacts them by the same rules, so a tree and the same tree written as JSON text are redacted alike.
 */
final class JsonRedaction {

    /** Text longer than this goes to the text engine; it is longer than any payer body the workbench keeps (4 MiB). */
    static final int MAX_CHARS = 8 * 1024 * 1024;

    /** The deepest nesting of objects and arrays in one text; deeper JSON is {@link Unreadable}. */
    static final int MAX_DEPTH = 128;

    /** The most levels of JSON in a JSON string read on the tree; a string past it goes to the text engine. */
    static final int MAX_LEVELS = 8;

    private static final JsonFactory FACTORY = JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_DEPTH)
                    .maxDocumentLength(MAX_CHARS)
                    .maxStringLength(MAX_CHARS)
                    .maxNameLength(MAX_CHARS)
                    .maxNumberLength(MAX_CHARS)
                    .build())
            .build();

    /**
     * {@link #FACTORY} that also takes control characters in a string, as the text engine writes a line break into a
     * masked private key block ({@link #decodedString}).
     */
    private static final JsonFactory LENIENT = FACTORY.rebuild()
            .enable(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS)
            .build();

    private static final JsonStringEncoder ENCODER = JsonStringEncoder.getInstance();

    /** The member that makes an object a JWK. */
    private static final String KTY = "kty";

    private JsonRedaction() {
    }

    /**
     * Thrown for text that is JSON this path will not read: names that repeat in one object once decoded, or nesting
     * deeper than {@link #MAX_DEPTH}. {@link Redactor} masks such a text whole.
     */
    static final class Unreadable extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Unreadable() {
            super(null, null, false, false);
        }
    }

    /**
     * Thrown for a JSON text one of whose strings opens a private key block it does not close
     * ({@link Redactor#opensAnUnterminatedKey(String)}): the key material may be in any later string, at this level or
     * an outer one, so {@link Redactor#redact(String)} masks the outermost text whole.
     */
    static final class UnterminatedKey extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UnterminatedKey() {
            super(null, null, false, false);
        }
    }

    /**
     * Whether {@code text} may be one JSON value worth reading on the tree: no longer than {@link #MAX_CHARS}, and its
     * first character after JSON whitespace opens an object, an array or a string. A number, {@code true},
     * {@code false} or {@code null} on its own holds nothing to mask.
     */
    static boolean mayBeJson(String text) {
        if (text.length() > MAX_CHARS) {
            return false;
        }
        int at = skipSpace(text, 0);
        if (at == text.length()) {
            return false;
        }
        char c = text.charAt(at);
        return c == '{' || c == '[' || c == '"';
    }

    /**
     * {@code text}, one JSON value at JSON-in-string level {@code level}, redacted and written back; {@code null} if
     * it is not one JSON value.
     *
     * @throws Unreadable if it is JSON this path will not read
     */
    static String redact(String text, int level) {
        Node root = parse(text, level);
        if (root == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        write(redact(root, level, Place.ROOT), out);
        return out.append(text, endOfValue(text), text.length()).toString();
    }

    /**
     * {@code text}, at JSON-in-string level {@code level}, read into nodes; {@code null} if it is not one JSON value.
     * The one place this path reads a text, for {@link #redact(String, int)} and {@link #checkNested} alike.
     *
     * <p>A text this path rejects (not one JSON value, a name that repeats, nesting past {@link #MAX_DEPTH}) is first
     * read for any key block it opens ({@link #opensAKeyAnywhere}): the key material may sit in a later string that
     * the rejected text's own handling (the text engine, or the mask over this one string) does not cover.
     *
     * @throws UnterminatedKey if a string or name it decodes, at any level down to {@link #MAX_LEVELS}, opens a private
     *     key block it does not close, whether or not the text is rejected
     * @throws Unreadable if it is JSON this path will not read
     */
    private static Node parse(String text, int level) {
        Node root;
        Reader reader;
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), text)) {
            reader = new Reader(text, parser);
            root = reader.read(parser.nextToken());
            if (parser.nextToken() != null) {
                rejected(text, level);
                return null;
            }
        } catch (Unreadable repeatedName) {
            rejected(text, level);
            throw repeatedName;
        } catch (StreamConstraintsException tooDeep) {
            rejected(text, level);
            throw new Unreadable();
        } catch (StreamReadException notJson) {
            rejected(text, level);
            return null;
        }
        if (reader.opensAKey) {
            throw new UnterminatedKey();
        }
        return root;
    }

    /**
     * For a text at level {@code level} that this path rejects.
     *
     * @throws UnterminatedKey if any string or name in it opens a key block it does not close ({@link #opensAKeyAnywhere})
     */
    private static void rejected(String text, int level) {
        if (opensAKeyAnywhere(text, level)) {
            throw new UnterminatedKey();
        }
    }

    /**
     * Whether a string or name that {@code text}, at level {@code level}, decodes opens a private key block it does
     * not close, or one in JSON held in such a string does, down to {@link #MAX_LEVELS}. Every token Jackson can read
     * is read, with no check for repeated names, up to the first read error or past the nesting bound, so a block
     * before or after the point where the text is rejected is found; what follows a read error is not JSON this path
     * can decode.
     */
    static boolean opensAKeyAnywhere(String text, int level) {
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), text)) {
            for (JsonToken token = parser.nextToken(); token != null; token = parser.nextToken()) {
                String decoded = token == JsonToken.PROPERTY_NAME ? parser.currentName()
                        : token == JsonToken.VALUE_STRING ? parser.getString() : null;
                if (decoded != null && (Redactor.opensAnUnterminatedKey(decoded)
                        || (level + 1 < MAX_LEVELS && mayBeJson(decoded) && opensAKeyAnywhere(decoded, level + 1)))) {
                    return true;
                }
            }
        } catch (StreamReadException | StreamConstraintsException stopped) {
            // What was decoded before the error was read; nothing after it can be.
        }
        return false;
    }

    /**
     * The most a tree given to {@link #redactTree} may weigh: one for each value, container and member name, and the
     * length of each string and name as JSON spells it, quotes included. A heavier tree is not read further.
     */
    static final long MAX_WEIGHT = 16L * 1024 * 1024;

    /** The number types a tree may hold: the JDK's own, matched by exact class, so reading one runs no caller code. */
    static final Set<Class<?>> NUMBERS = Set.of(Integer.class, Long.class, Short.class, Byte.class, Double.class,
            Float.class, BigInteger.class, BigDecimal.class);

    /** Thrown for a tree that holds anything but JSON-shaped plain data ({@link #redactTree}). */
    static final class NotPlain extends RuntimeException {
        private static final long serialVersionUID = 1L;

        NotPlain() {
            super(null, null, false, false);
        }
    }

    /**
     * {@code value}, JSON-shaped plain data, redacted by the same tree rules as a JSON text ({@link #redact(String, int)}),
     * as new plain data: {@code null}, a {@link String}, a {@link Boolean}, a number of one of the {@link #NUMBERS}
     * types, a {@link Map} whose keys are all strings, or a {@link List}, holding only the same. A Jackson tree is not
     * plain data: a caller converts it first, as any other typed value. Maps come back as unmodifiable maps that keep
     * their order, lists as unmodifiable lists, and numbers and booleans as they are.
     *
     * <p>The tree is read once, each map entry and list item in turn, into this class's own nodes, and only those are
     * redacted, so no caller object runs its code after it is read or is returned. Reading stops as soon as the tree
     * weighs more than {@link #MAX_WEIGHT} or nests deeper than {@link #MAX_DEPTH}.
     *
     * @throws NotPlain if it holds anything else
     * @throws Unreadable if it nests deeper than {@link #MAX_DEPTH}, an object's names repeat, or two names redact
     *     to one, as for a text
     * @throws UnterminatedKey if a string or name opens a private key block it does not close, as for a text
     * @throws IllegalArgumentException if it weighs more than {@link #MAX_WEIGHT}
     */
    static Object redactTree(Object value) {
        TreeReader reader = new TreeReader();
        Node root = reader.read(value, 0);
        if (reader.opensAKey) {
            throw new UnterminatedKey();
        }
        return plain(redact(root, 0, Place.ROOT));
    }

    /** A redacted node read from a tree, as plain data. */
    private static Object plain(Node node) {
        if (node instanceof Scalar scalar) {
            return scalar.string() ? scalar.text() : scalar.value();
        }
        Container container = (Container) node;
        if (container.object()) {
            Map<String, Object> out = new LinkedHashMap<>();
            container.members().forEach(member -> out.put(member.name(), plain(member.value())));
            return Collections.unmodifiableMap(out);
        }
        List<Object> out = new ArrayList<>(container.members().size());
        container.members().forEach(member -> out.add(plain(member.value())));
        return Collections.unmodifiableList(out);
    }

    /** Reads JSON-shaped plain data into nodes, as {@link Reader} reads a text, keeping the tree's weight. */
    private static final class TreeReader {
        private long weight;

        /** Whether a string or name opens a private key block it does not close. */
        boolean opensAKey;

        Node read(Object value, int depth) {
            if (value == null) {
                return value(null, "null");
            }
            if (value instanceof String string) {
                return string(string);
            }
            if (value instanceof Boolean bool) {
                return value(bool, bool.toString());
            }
            if (NUMBERS.contains(value.getClass())) {
                return number((Number) value);
            }
            if (value instanceof Map<?, ?> map) {
                enter(depth);
                List<Member> members = new ArrayList<>();
                Names names = new Names();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String name)) {
                        throw new NotPlain();
                    }
                    members.add(new Member("", name(name, names), quoted(name), read(entry.getValue(), depth + 1)));
                }
                return new Container("", true, members, "");
            }
            if (value instanceof List<?> list) {
                enter(depth);
                List<Member> members = new ArrayList<>();
                for (Object item : list) {
                    members.add(new Member(null, null, null, read(item, depth + 1)));
                }
                return new Container("", false, members, "");
            }
            throw new NotPlain();
        }

        /** A container at {@code depth}, the root's being 0: nesting past {@link #MAX_DEPTH} is unreadable. */
        private void enter(int depth) {
            if (depth >= MAX_DEPTH) {
                throw new Unreadable();
            }
            weigh(1);
        }

        private Node string(String string) {
            String raw = spelled(string);
            opensAKey |= Redactor.opensAnUnterminatedKey(string);
            return new Scalar("", true, string, raw, null);
        }

        /** A member name; a name that repeats in one object is unreadable, as it is in a text. */
        private String name(String name, Names names) {
            spelled(name);
            opensAKey |= Redactor.opensAnUnterminatedKey(name);
            if (!names.add(name)) {
                throw new Unreadable();
            }
            return name;
        }

        /** A big number weighs about its digits, counted from its bits so it is never written out. */
        private Node number(Number number) {
            if (number instanceof BigInteger big) {
                weigh(1 + big.bitLength() / 3);
            } else if (number instanceof BigDecimal big) {
                weigh(1 + big.unscaledValue().bitLength() / 3);
            }
            return value(number, "number");
        }

        private Node value(Object value, String kind) {
            weigh(1);
            return new Scalar("", false, kind, null, value);
        }

        /** {@code text} as JSON spells it, weighed: its length is checked before it is spelled. */
        private String spelled(String text) {
            weigh(1 + text.length() + 2);
            String raw = quoted(text);
            weigh(raw.length() - text.length() - 2);
            return raw;
        }

        private void weigh(long more) {
            weight += more;
            if (weight > MAX_WEIGHT) {
                throw new IllegalArgumentException("the tree weighs more than " + MAX_WEIGHT);
            }
        }
    }

    /**
     * The member names of one object, to tell whether a name is already among them (#398): a crit-bit tree over the
     * names, compared exactly as {@link String#equals} compares them, that takes no hash of a name. A hashed set costs
     * a log factor more per name on names chosen to collide; this index costs at most a constant times the name's
     * length plus one, whatever the other names are, and keeps only references to the names.
     *
     * <p>A name is read as the sequence {@code key(name, i)}: {@code charAt(i) + 1} for {@code i} below its length,
     * {@code 0} past it, so a name differs from a longer name it begins at its own length. Each inner node tests one
     * bit ({@code bit}, of 17) of one position ({@code at}), and every name under it agrees on every bit before that
     * one, positions first, higher bits first; on the path from the root the tested bits only go later. A new name
     *
     * <ol>
     *   <li>walks down from the root by its own bits, but only through nodes testing a position no later than its
     *       length, to a leaf or to a node testing a later position, and takes that node's representative (a name
     *       under it, {@code sample}): every name under such a node agrees with the representative up to and
     *       including the new name's length, so all of them first differ from the new name where the representative
     *       does;
     *   <li>compares itself with that one name up to its own length, which finds whether it is new and, if so, the
     *       first bit where it differs from every name it shares the most with;
     *   <li>walks down again to where that bit belongs, before the first node testing a later bit, and puts a node
     *       testing it there, with the new name on one side and what was there on the other.
     * </ol>
     *
     * <p>Both walks pass only nodes testing positions no later than the name's length, each a later bit than the one
     * before, so each takes at most 17 times the length plus one steps, and the compare reads the length plus one
     * characters.
     */
    static final class Names {
        /** The number of bits in a key: {@code key(name, i)} is at most {@code Character.MAX_VALUE + 1}. */
        private static final int KEY_BITS = 17;

        /** The names, in the order added; a leaf is the index of one, written {@code ~index} where a node points to it. */
        private String[] leaves = new String[4];
        private int size;

        /** Per inner node: the position and the bit it tests, its two sides and the leaf it keeps as representative. */
        private int[] at = new int[4];
        private int[] bit = new int[4];
        private int[] clear = new int[4];
        private int[] set = new int[4];
        private int[] sample = new int[4];
        private int nodes;

        /** The root: {@code ~0}, the first name, until a second name adds a node; then node {@code 0} or a later one. */
        private int root = ~0;

        /** Whether {@code name} was not among the names; it is among them after. */
        boolean add(String name) {
            if (size == 0) {
                leaf(name);
                return true;
            }
            int length = name.length();
            int node = root;
            while (node >= 0 && at[node] <= length) {
                node = side(name, node);
            }
            String other = leaves[node >= 0 ? sample[node] : ~node];
            int end = Math.min(length, other.length());
            int differ = 0;
            while (differ < end && name.charAt(differ) == other.charAt(differ)) {
                differ++;
            }
            if (differ == length && differ == other.length()) {
                return false;
            }
            int otherKey = key(other, differ);
            int newBit = Integer.highestOneBit(otherKey ^ key(name, differ));
            int parent = -1;
            boolean parentSet = false;
            node = root;
            while (node >= 0 && (at[node] < differ || (at[node] == differ && bit[node] > newBit))) {
                parent = node;
                parentSet = (key(name, at[node]) & bit[node]) != 0;
                node = parentSet ? set[node] : clear[node];
            }
            int leaf = ~leaf(name);
            int inner = node(differ, newBit, (otherKey & newBit) != 0 ? leaf : node,
                    (otherKey & newBit) != 0 ? node : leaf, ~leaf);
            if (parent < 0) {
                root = inner;
            } else if (parentSet) {
                set[parent] = inner;
            } else {
                clear[parent] = inner;
            }
            return true;
        }

        /** The side of inner node {@code node} that {@code name} goes to. */
        private int side(String name, int node) {
            return (key(name, at[node]) & bit[node]) != 0 ? set[node] : clear[node];
        }

        /** {@code name}'s key at position {@code i}: its character there plus one, or {@code 0} past its end. */
        private static int key(String name, int i) {
            return i < name.length() ? name.charAt(i) + 1 : 0;
        }

        /** Adds {@code name} as a leaf and returns its index. */
        private int leaf(String name) {
            if (size == leaves.length) {
                leaves = Arrays.copyOf(leaves, 2 * size);
            }
            leaves[size] = name;
            return size++;
        }

        /** Adds an inner node and returns its index. */
        private int node(int position, int tested, int clearSide, int setSide, int representative) {
            if (nodes == at.length) {
                int grown = 2 * nodes;
                at = Arrays.copyOf(at, grown);
                bit = Arrays.copyOf(bit, grown);
                clear = Arrays.copyOf(clear, grown);
                set = Arrays.copyOf(set, grown);
                sample = Arrays.copyOf(sample, grown);
            }
            at[nodes] = position;
            bit[nodes] = tested;
            clear[nodes] = clearSide;
            set[nodes] = setSide;
            sample[nodes] = representative;
            return nodes++;
        }
    }

    /** {@code text} as Jackson's encoder spells a JSON string, quotes included. */
    private static String quoted(String text) {
        StringBuilder out = new StringBuilder(text.length() + 2);
        quote(text, out);
        return out.toString();
    }

    /** A JSON value read from the text, with the text between it and the token before it ({@code lead}). */
    private sealed interface Node permits Container, Scalar {
        String lead();
    }

    /**
     * An object ({@code object}) or an array; an array's members have no name. {@code closeLead} is the text before
     * its closing bracket.
     */
    private record Container(String lead, boolean object, List<Member> members, String closeLead) implements Node {
    }

    /**
     * A member of an object: the text before its name, its name decoded and as the text spells it ({@code rawName},
     * quotes included), and its value; or an item of an array (no name).
     */
    private record Member(String lead, String name, String rawName, Node value) {
    }

    /**
     * A string (its decoded value, {@code string}, and as the text spells it, {@code raw}, quotes included) or a
     * number, {@code true}, {@code false} or {@code null} (as the text spells it, no {@code raw}). A number, boolean or
     * {@code null} read from a tree ({@link #redactTree}) is {@code value}, and its {@code text} only says which it is:
     * {@code number}, {@code true}, {@code false} or {@code null}.
     */
    private record Scalar(String lead, boolean string, String text, String raw, Object value) implements Node {
        static Scalar masked(String lead, String mask) {
            return new Scalar(lead, true, mask, null, null);
        }
    }

    /** Builds the tree from the parser's tokens, taking the text between tokens from the text itself. */
    private static final class Reader {
        private final String text;
        private final JsonParser parser;

        /** Whether a string or name opens a private key block it does not close. */
        boolean opensAKey;

        Reader(String text, JsonParser parser) {
            this.text = text;
            this.parser = parser;
        }

        Node read(JsonToken token) {
            if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                return readContainer(token == JsonToken.START_OBJECT);
            }
            int start = tokenStart(expected(token));
            String lead = text.substring(leadStart(start), start);
            if (token == JsonToken.VALUE_STRING) {
                String value = checked(parser.getString());
                int end = Math.toIntExact(parser.currentLocation().getCharOffset());
                if (end <= start || end > text.length() || text.charAt(end - 1) != '"') {
                    throw new IllegalStateException("string end not found");
                }
                return new Scalar(lead, true, value, text.substring(start, end), null);
            }
            return switch (token) {
                case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT, VALUE_TRUE, VALUE_FALSE, VALUE_NULL ->
                        new Scalar(lead, false, parser.getText(), null, null);
                default -> throw new IllegalStateException("unexpected token " + token);
            };
        }

        /** An object or array; the parser's nesting limit ({@link #MAX_DEPTH}) bounds the recursion. */
        private Container readContainer(boolean object) {
            String lead = lead(object ? '{' : '[');
            List<Member> members = new ArrayList<>();
            Names names = object ? new Names() : null;
            JsonToken end = object ? JsonToken.END_OBJECT : JsonToken.END_ARRAY;
            JsonToken token;
            while ((token = parser.nextToken()) != end) {
                if (object) {
                    int nameStart = tokenStart('"');
                    String nameLead = text.substring(leadStart(nameStart), nameStart);
                    String name = checked(parser.currentName());
                    if (!names.add(name)) {
                        throw new Unreadable();
                    }
                    JsonToken value = parser.nextToken();
                    // The name ends where the text before its value (the colon and any whitespace) starts.
                    String rawName = text.substring(nameStart, leadStart(tokenStart(firstOf(value))));
                    members.add(new Member(nameLead, name, rawName, read(value)));
                } else {
                    members.add(new Member(null, null, null, read(token)));
                }
            }
            return new Container(lead, object, List.copyOf(members), lead(object ? '}' : ']'));
        }

        /** The text between the current token, which starts with {@code first}, and the token before it. */
        private String lead(char first) {
            int start = tokenStart(first);
            return text.substring(leadStart(start), start);
        }

        /** Where the current token starts in the text; it must start with {@code first}. */
        private int tokenStart(char first) {
            int start = Math.toIntExact(parser.currentTokenLocation().getCharOffset());
            if (start < 0 || start >= text.length() || text.charAt(start) != first) {
                throw new IllegalStateException("token start not found");
            }
            return start;
        }

        /**
         * Where the text before the token at {@code start} starts: JSON whitespace, at most one comma or colon, and
         * JSON whitespace, read back from the token's start, so no string is read by hand.
         */
        private int leadStart(int start) {
            int from = start;
            while (from > 0 && isSpace(text.charAt(from - 1))) {
                from--;
            }
            if (from > 0 && (text.charAt(from - 1) == ',' || text.charAt(from - 1) == ':')) {
                from--;
                while (from > 0 && isSpace(text.charAt(from - 1))) {
                    from--;
                }
            }
            return from;
        }

        /** {@code string}, a decoded string or name, noting whether it opens a private key block it does not close. */
        private String checked(String string) {
            opensAKey |= Redactor.opensAnUnterminatedKey(string);
            return string;
        }

        /** The first character of the current token, {@code token}. */
        private char expected(JsonToken token) {
            return switch (token) {
                case VALUE_STRING -> '"';
                case VALUE_TRUE -> 't';
                case VALUE_FALSE -> 'f';
                case VALUE_NULL -> 'n';
                default -> parser.getText().charAt(0);
            };
        }

        /** The first character of the current token, {@code token}, a value. */
        private char firstOf(JsonToken token) {
            return switch (token) {
                case START_OBJECT -> '{';
                case START_ARRAY -> '[';
                default -> expected(token);
            };
        }
    }

    /**
     * Where a string stands in the JSON, as the text engine's reading of the string as the text spells it sees it
     * ({@link #redactString}): the text around it, so the engine reads its quotes as a value's, a name's or an item's,
     * as it read them in the whole text before the structural path.
     */
    private enum Place {
        ROOT("", ""), VALUE("{\"v\":", "}"), ITEM("[", "]"), NAME("{", ":null}");

        private final String before;
        private final String after;

        Place(String before, String after) {
            this.before = before;
            this.after = after;
        }
    }

    /** {@code node} redacted, at JSON-in-string level {@code level}, in its {@code place}. */
    private static Node redact(Node node, int level, Place place) {
        if (node instanceof Scalar scalar) {
            return scalar.string()
                    ? new Scalar(scalar.lead(), true, redactString(scalar.text(), scalar.raw(), level, place), null, null)
                    : scalar;
        }
        Container container = (Container) node;
        boolean jwk = container.object() && container.members().stream().anyMatch(m -> KTY.equals(m.name()));
        List<Member> members = new ArrayList<>(container.members().size());
        Names names = container.object() ? new Names() : null;
        for (Member member : container.members()) {
            if (!container.object()) {
                members.add(new Member(null, null, null, redact(member.value(), level, Place.ITEM)));
                continue;
            }
            String name = member.name();
            Node value;
            if (Redactor.isSecretKey(name)) {
                checkMaskedValue(member.value(), level);
                value = maskSecret(name, member.value());
            } else if (jwk && Redactor.JWK_PRIVATE_MEMBERS.contains(name)) {
                checkMaskedValue(member.value(), level);
                value = maskPrivate(member.value());
            } else {
                value = redact(member.value(), level, Place.VALUE);
            }
            String redactedName = redactString(name, member.rawName(), level, Place.NAME);
            if (!names.add(redactedName)) {
                // Two names the redaction made one: the output would not read back as the same JSON.
                throw new Unreadable();
            }
            members.add(new Member(member.lead(), redactedName, null, value));
        }
        return new Container(container.lead(), container.object(), members, container.closeLead());
    }

    /**
     * Before a member's value at JSON-in-string level {@code level} is masked whole, each string and name in it is read as
     * JSON down to {@link #MAX_LEVELS}, as any other string is ({@link Redactor#redactAt}), and one that opens a private
     * key block it does not close at any level makes the outermost text the mask: the key material may sit in a later
     * string the mask does not cover.
     *
     * @throws UnterminatedKey if one does
     */
    private static void checkMaskedValue(Node value, int level) {
        if (value instanceof Scalar scalar) {
            if (scalar.string()) {
                checkNested(scalar.text(), level + 1);
            }
            return;
        }
        Container container = (Container) value;
        for (Member member : container.members()) {
            if (container.object()) {
                checkNested(member.name(), level + 1);
            }
            checkMaskedValue(member.value(), level);
        }
    }

    /**
     * Reads {@code text}, a decoded string, as JSON at level {@code level} if it may be one JSON value there, as
     * {@link Redactor#redactAt} does ({@link #parse}, which also reads a text it rejects for a key block it opens), and
     * checks each string and name in it for a key block it does not close, one level deeper each time.
     *
     * @throws UnterminatedKey if a string or name at any level opens a key block it does not close
     */
    private static void checkNested(String text, int level) {
        if (level >= MAX_LEVELS || !mayBeJson(text)) {
            return;
        }
        Node root;
        try {
            root = parse(text, level);
        } catch (Unreadable notRead) {
            return;
        }
        if (root != null) {
            checkMaskedValue(root, level);
        }
    }

    /**
     * A string or name, decoded ({@code decoded}) and as the text spells it ({@code raw}), redacted: one JSON value on
     * the tree one level deeper, any other text by the text engine.
     *
     * <p>Until the text engine's escape-level readers go (#377 stage 2), the text engine also reads the string as the
     * text spells it, in its {@code place}, as it read every string before the structural path: a secret it finds
     * through a spelling that decoding removes (a quote spelled as an escape of an escape, say) is masked too. If it
     * masks anything there, the string it leaves is decoded and redacted instead, and if what it leaves is no longer one
     * JSON string in that place, the whole string is the mask. So no string keeps anything the text engine masks in it.
     * A spelling with no backslash is the decoded string in quotes, so only the decoded string is read.
     *
     * <p>Check first: before any of that, the decoded string, a value, a name or an item, is read for a key block it
     * opens and does not close at any level ({@link #checkNested}). The text engine's reading of the spelling may mask
     * the part that opens the block, and what it leaves would then pass the check while the key material, in a later
     * string, is kept; so the check reads the string as it came, never what a rewrite left.
     *
     * @throws UnterminatedKey if a string or name in the decoded string, at any level, opens a key block it does not
     *     close
     */
    private static String redactString(String decoded, String raw, int level, Place place) {
        checkNested(decoded, level + 1);
        if (raw.indexOf('\\') < 0) {
            // No escape in the spelling: it is the decoded string in quotes, with no spelling for decoding to remove.
            return Redactor.redactAt(decoded, level + 1);
        }
        String spelled = place.before + raw + place.after;
        String spelledOut = Redactor.redact(spelled, null);
        if (spelledOut.equals(spelled)) {
            return Redactor.redactAt(decoded, level + 1);
        }
        String kept = spelledOut.startsWith(place.before) && spelledOut.endsWith(place.after)
                && spelledOut.length() >= place.before.length() + place.after.length()
                ? decodedString(spelledOut.substring(place.before.length(), spelledOut.length() - place.after.length()))
                : null;
        return kept == null ? Redactor.MASK : Redactor.redactAt(kept, level + 1);
    }

    /**
     * The value of {@code text} if it is one JSON string, otherwise {@code null}; the text engine's output, so a control
     * character it wrote into the string is taken as it is.
     */
    private static String decodedString(String text) {
        try (JsonParser parser = LENIENT.createParser(ObjectReadContext.empty(), text)) {
            if (parser.nextToken() != JsonToken.VALUE_STRING) {
                return null;
            }
            String value = parser.getString();
            return parser.nextToken() == null ? value : null;
        } catch (StreamReadException | StreamConstraintsException notOneString) {
            return null;
        }
    }

    /** Where the JSON value in {@code text} ends: before the JSON whitespace that ends the text. */
    private static int endOfValue(String text) {
        int end = text.length();
        while (end > 0 && isSpace(text.charAt(end - 1))) {
            end--;
        }
        return end;
    }

    /**
     * The value of a secret-named member: a string keeps an {@code Authorization}-style scheme ({@link Redactor#masked})
     * and {@code null} stays. An array of such strings, as a credential header's list of values, keeps each one's
     * scheme so; any other value, an array with any other item among them, is the mask.
     */
    private static Node maskSecret(String name, Node value) {
        if (value instanceof Scalar scalar && !scalar.string()) {
            return isNull(scalar) ? scalar : Scalar.masked(scalar.lead(), Redactor.MASK);
        }
        if (value instanceof Scalar scalar) {
            return Scalar.masked(scalar.lead(), Redactor.masked(name, scalar.text()));
        }
        Container container = (Container) value;
        if (!container.object()) {
            List<Member> items = new ArrayList<>(container.members().size());
            for (Member item : container.members()) {
                String masked = item.value() instanceof Scalar scalar && scalar.string()
                        ? Redactor.masked(name, scalar.text()) : Redactor.MASK;
                if (masked.equals(Redactor.MASK)) {
                    return Scalar.masked(value.lead(), Redactor.MASK);
                }
                items.add(new Member(null, null, null, Scalar.masked(item.value().lead(), masked)));
            }
            return new Container(container.lead(), false, items, container.closeLead());
        }
        return Scalar.masked(value.lead(), Redactor.MASK);
    }

    /** The value of a JWK private member: the mask, unless it is {@code null}. */
    private static Node maskPrivate(Node value) {
        return value instanceof Scalar scalar && isNull(scalar) ? scalar : Scalar.masked(value.lead(), Redactor.MASK);
    }

    private static boolean isNull(Scalar scalar) {
        return !scalar.string() && scalar.text().equals("null");
    }

    private static void write(Node node, StringBuilder out) {
        out.append(node.lead());
        if (node instanceof Scalar scalar) {
            if (scalar.string()) {
                quote(scalar.text(), out);
            } else {
                out.append(scalar.text());
            }
            return;
        }
        Container container = (Container) node;
        out.append(container.object() ? '{' : '[');
        for (Member member : container.members()) {
            if (container.object()) {
                out.append(member.lead());
                quote(member.name(), out);
            }
            write(member.value(), out);
        }
        out.append(container.closeLead()).append(container.object() ? '}' : ']');
    }

    private static void quote(String text, StringBuilder out) {
        out.append('"');
        ENCODER.quoteAsString(text, out);
        out.append('"');
    }

    private static int skipSpace(String text, int from) {
        int at = from;
        while (at < text.length() && isSpace(text.charAt(at))) {
            at++;
        }
        return at;
    }

    /** JSON whitespace: space, tab, line feed and carriage return. */
    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }
}
