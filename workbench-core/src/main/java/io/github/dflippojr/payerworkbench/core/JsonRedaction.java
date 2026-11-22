package io.github.dflippojr.payerworkbench.core;

import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.AbstractCollection;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
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

    /**
     * The most levels of JSON escapes {@link #hidesAKey} decodes; escapes that still decode past it make the text the
     * mask. JSON held in strings as Jackson writes it doubles the backslashes before a quote at each level, so a text
     * within {@link #MAX_CHARS} holds it about 23 levels deep at most; a backslash spelled as a unicode escape at each
     * level goes deeper, and is masked.
     */
    static final int MAX_KEY_LEVELS = 32;

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
     * Whether a decoding of {@code text}'s JSON escapes, at JSON-in-string level {@code level}, shows a private key
     * header that {@code text} does not spell plainly, or could: the one rule for every bound where the structural path
     * stops reading a string (#389). Past the level bound, the nesting bound, a read error, text after the root value,
     * text that is not JSON or the length bound, the text engine reads the string as it is spelled and cannot make an
     * outer level's text the mask; a key opener it does not see would leave the key material in a later string kept.
     *
     * <p>Each pass decodes every JSON escape in the whole text, left to right, whether or not it sits in a string; an
     * escape that is not one ({@code \q}) is kept. Every string the structural path decodes, at any depth, is a
     * decoding of part of the text, one pass per level, so its text appears in the pass for its level: this
     * over-approximates every decoding that path can make. A header the text spells plainly has no backslash in it, so
     * no pass changes it, and no pass has fewer header starts ({@link Redactor#privateKeyHeaderStarts}) than the text:
     * a pass with more holds a header only a decoding shows. Each pass, at level 1 or deeper, is also read by the one
     * open-key predicate ({@link Redactor#opensAnUnterminatedKey}), whose quote-split pieces are the strings of every
     * level up to the pass's: a header whose own string does not close it, spelled plainly or not, is found there. A
     * text with no backslash has no pass; its callers read the text itself with that predicate, with no shortcut
     * ({@link TreeReader}, and the parser's strings for a text). The passes stop when one decodes nothing; a text whose
     * escapes still decode after {@link #MAX_KEY_LEVELS} levels counts as hiding one. Each pass is linear in the text
     * and no longer than the one before.
     *
     * @param level the level of {@code text}: 0 for a text, 1 for a string in a tree, which is already decoded once
     */
    static boolean hidesAKey(String text, int level) {
        if (text.indexOf('\\') < 0) {
            return false;
        }
        int plain = Redactor.privateKeyHeaderStarts(text);
        String current = text;
        for (int at = level; ; at++) {
            String next = unescaped(current);
            if (next == null) {
                return false;
            }
            // Each pass is a level of 1 or deeper: a string there whose own piece does not close a block it opens is
            // read by the one open-key predicate, which the structural path stops applying string by string past
            // MAX_LEVELS, past the nesting bound or at a read error.
            if (at + 1 > MAX_KEY_LEVELS || Redactor.privateKeyHeaderStarts(next) > plain
                    || Redactor.opensAnUnterminatedKey(next)) {
                return true;
            }
            current = next;
        }
    }

    /**
     * {@code text} with each JSON escape in it decoded, left to right, or {@code null} if it has none: a backslash and
     * one of {@code " \ / b f n r t}, or a {@code u} and four hex digits. Any other backslash is kept as it is.
     */
    static String unescaped(String text) {
        int at = text.indexOf('\\');
        if (at < 0) {
            return null;
        }
        StringBuilder out = null;
        int copied = 0;
        for (; at >= 0 && at < text.length() - 1; at = text.indexOf('\\', at)) {
            char c = text.charAt(at + 1);
            char decoded;
            int length = 2;
            switch (c) {
                case '"', '\\', '/' -> decoded = c;
                case 'b' -> decoded = '\b';
                case 'f' -> decoded = '\f';
                case 'n' -> decoded = '\n';
                case 'r' -> decoded = '\r';
                case 't' -> decoded = '\t';
                case 'u' -> {
                    int code = at + 6 <= text.length() ? hex4(text, at + 2) : -1;
                    if (code < 0) {
                        at++;
                        continue;
                    }
                    decoded = (char) code;
                    length = 6;
                }
                default -> {
                    at++;
                    continue;
                }
            }
            if (out == null) {
                out = new StringBuilder(text.length());
            }
            out.append(text, copied, at).append(decoded);
            at += length;
            copied = at;
        }
        return out == null ? null : out.append(text, copied, text.length()).toString();
    }

    /** The value of the four hex digits at {@code from}, or -1 if they are not four hex digits. */
    private static int hex4(String text, int from) {
        int value = 0;
        for (int i = from; i < from + 4; i++) {
            int digit = Character.digit(text.charAt(i), 16);
            if (digit < 0) {
                return -1;
            }
            value = value * 16 + digit;
        }
        return value;
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

    /**
     * A redacted node read from a tree, as plain data. An object's members go into a {@link PlainObject}, in order,
     * wrapped as {@link Collections#unmodifiableMap} wraps any map: its names are indexed without a hash (#402).
     */
    private static Object plain(Node node) {
        if (node instanceof Scalar scalar) {
            return scalar.string() ? scalar.text() : scalar.value();
        }
        Container container = (Container) node;
        if (container.object()) {
            PlainObject out = new PlainObject(container.members().size());
            container.members().forEach(member -> out.append(member.name(), plain(member.value())));
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
                    members.add(new Member("", name, name(name, names), read(entry.getValue(), depth + 1)));
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
            opensAKey |= Redactor.opensAnUnterminatedKey(string) || hidesAKey(string, 1);
            return new Scalar("", true, string, raw, null);
        }

        /**
         * A member name as JSON spells it, quotes included: the one spelling both weighs it and is the node's
         * {@code rawName} (#389). A name that repeats in one object is unreadable, as it is in a text.
         */
        private String name(String name, Names names) {
            String raw = spelled(name);
            opensAKey |= Redactor.opensAnUnterminatedKey(name) || hidesAKey(name, 1);
            if (!names.add(name)) {
                throw new Unreadable();
            }
            return raw;
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
     * a log factor more per name on names chosen to collide; this index's walks and compare cost at most a constant
     * times the name's length plus one, whatever the other names are, and it keeps only references to the names. Its
     * backing arrays double when full, so the add that fills them also copies them, in proportion to the names already
     * there: one add is bounded only amortized, and adding all of an object's names stays linear in their total length.
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
     * characters. Growing the arrays at a capacity boundary adds a copy of the index so far; doubling makes the copies
     * sum to less than twice the final size, so that cost is amortized, not per name.
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
            String other = leaves[closest(name)];
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
            int node = root;
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

        /** The index of {@code name} among the names, in the order added, or {@code -1} if it is not among them. */
        int indexOf(String name) {
            if (size == 0) {
                return -1;
            }
            int closest = closest(name);
            return leaves[closest].equals(name) ? closest : -1;
        }

        /** The number of names. */
        int size() {
            return size;
        }

        /** The name added {@code index}th, from {@code 0}. */
        String name(int index) {
            return leaves[index];
        }

        /**
         * The index of the name that {@code name} shares the most with (step 1 of {@link #add}): the leaf, or the
         * representative of the first node testing a position later than its length, that its own bits lead to. If
         * {@code name} is among the names, that is its index. There must be a name.
         */
        private int closest(String name) {
            int node = root;
            while (node >= 0 && at[node] <= name.length()) {
                node = side(name, node);
            }
            return node >= 0 ? sample[node] : ~node;
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

    /**
     * The members of one object read from a tree, redacted, as plain data (#402): an ordered map whose names are
     * indexed in {@link Names}, so building it, and looking up a name in it, takes no hash of a name and costs a
     * constant times the name's length plus one, amortized, whatever the other names are. A hashed map costs a log
     * factor more per name on names chosen to collide. {@link #plain} hands it out only wrapped by
     * {@link Collections#unmodifiableMap}, so callers get the same type, order, equality and errors as before;
     * {@link #append} is the only way to change it.
     *
     * <p>It serializes through a proxy (#404), {@link Members}: its names and values in order, never its own state or
     * its {@link Names} index. Reading the proxy back appends the members again, so the copy is built without a hash as
     * well, and, inside the {@link Collections#unmodifiableMap} wrapper that is serialized around it, it reads back as
     * the same type, equal and in the same order. A stream that claims to hold a {@code PlainObject} itself, or a
     * proxy whose names and values do not pair up, is refused as {@link Unreadable}.
     */
    static final class PlainObject extends AbstractMap<String, Object> implements Serializable {
        private static final long serialVersionUID = 1L;

        private final transient Names names = new Names();
        private final transient Object[] memberValues;

        /** An empty object with room for {@code capacity} members. */
        PlainObject(int capacity) {
            memberValues = new Object[capacity];
        }

        /**
         * Adds a member after the others. The names of one object are distinct once redacted, as {@link #redact}
         * checks; one that is not is unreadable, as it is there.
         */
        void append(String name, Object value) {
            int index = names.size();
            if (!names.add(name)) {
                throw new Unreadable();
            }
            memberValues[index] = value;
        }

        /** What is written in its place: its members in order. */
        @Serial
        private Object writeReplace() {
            return new Members(this);
        }

        /** It is never written as itself, so a stream that holds one was not written by {@link #writeReplace}. */
        @Serial
        private void readObject(ObjectInputStream stream) {
            throw new Unreadable();
        }

        /** The serialized form of a {@code PlainObject}: its member names and values, in the order added. */
        private static final class Members implements Serializable {
            @Serial
            private static final long serialVersionUID = 1L;

            private final String[] memberNames;
            private final Object[] values;

            Members(PlainObject object) {
                int size = object.names.size();
                memberNames = new String[size];
                for (int i = 0; i < size; i++) {
                    memberNames[i] = object.names.name(i);
                }
                values = Arrays.copyOf(object.memberValues, size);
            }

            /** The object again, its members appended in order: names that repeat are unreadable, as in append. */
            @Serial
            private Object readResolve() {
                if (memberNames == null || values == null || memberNames.length != values.length) {
                    throw new Unreadable();
                }
                PlainObject object = new PlainObject(memberNames.length);
                for (int i = 0; i < memberNames.length; i++) {
                    if (memberNames[i] == null) {
                        throw new Unreadable();
                    }
                    object.append(memberNames[i], values[i]);
                }
                return object;
            }
        }

        @Override
        public int size() {
            return names.size();
        }

        @Override
        public boolean containsKey(Object key) {
            return indexOf(key) >= 0;
        }

        @Override
        public Object get(Object key) {
            int index = indexOf(key);
            return index < 0 ? null : memberValues[index];
        }

        private int indexOf(Object key) {
            return key instanceof String name ? names.indexOf(name) : -1;
        }

        /*
         * The three views are ordered as a LinkedHashMap's are: their iterators walk the members in the order added,
         * and their spliterators say so (ORDERED, and DISTINCT for the two sets), so a stream over them, parallel or
         * not, keeps that order. Looking up a name in the key or entry view goes through the index.
         */

        @Override
        public Set<String> keySet() {
            return new Keys();
        }

        @Override
        public Collection<Object> values() {
            return new Values();
        }

        @Override
        public Set<Map.Entry<String, Object>> entrySet() {
            return new Entries();
        }

        /** The names in order, read-only. */
        private final class Keys extends AbstractSet<String> {
            @Override
            public int size() {
                return names.size();
            }

            @Override
            public boolean contains(Object name) {
                return containsKey(name);
            }

            @Override
            public Iterator<String> iterator() {
                return new KeysInOrder();
            }

            @Override
            public Spliterator<String> spliterator() {
                return Spliterators.spliterator(this, Spliterator.ORDERED | Spliterator.DISTINCT);
            }
        }

        /** The values in order, read-only. */
        private final class Values extends AbstractCollection<Object> {
            @Override
            public int size() {
                return names.size();
            }

            @Override
            public Iterator<Object> iterator() {
                return new ValuesInOrder();
            }

            @Override
            public Spliterator<Object> spliterator() {
                return Spliterators.spliterator(this, Spliterator.ORDERED);
            }
        }

        /** The members in order, read-only. */
        private final class Entries extends AbstractSet<Map.Entry<String, Object>> {
            @Override
            public int size() {
                return names.size();
            }

            @Override
            public boolean contains(Object member) {
                if (!(member instanceof Map.Entry<?, ?> entry)) {
                    return false;
                }
                int index = indexOf(entry.getKey());
                return index >= 0 && Objects.equals(memberValues[index], entry.getValue());
            }

            @Override
            public Iterator<Map.Entry<String, Object>> iterator() {
                return new EntriesInOrder();
            }

            @Override
            public Spliterator<Map.Entry<String, Object>> spliterator() {
                return Spliterators.spliterator(this, Spliterator.ORDERED | Spliterator.DISTINCT);
            }
        }

        /** Walks the members in the order they were added, giving {@link #at} of each. */
        private abstract class InOrder<T> implements Iterator<T> {
            private int next;

            @Override
            public boolean hasNext() {
                return next < names.size();
            }

            @Override
            public T next() {
                if (next >= names.size()) {
                    throw new NoSuchElementException();
                }
                return at(next++);
            }

            /** What the walk gives for the member added {@code index}th. */
            abstract T at(int index);
        }

        private final class KeysInOrder extends InOrder<String> {
            @Override
            String at(int index) {
                return names.name(index);
            }
        }

        private final class ValuesInOrder extends InOrder<Object> {
            @Override
            Object at(int index) {
                return memberValues[index];
            }
        }

        private final class EntriesInOrder extends InOrder<Map.Entry<String, Object>> {
            @Override
            Map.Entry<String, Object> at(int index) {
                return new AbstractMap.SimpleImmutableEntry<>(names.name(index), memberValues[index]);
            }
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
