package io.github.dflippojr.payerworkbench.core;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.MonthDay;
import java.time.OffsetDateTime;
import java.time.OffsetTime;
import java.time.Period;
import java.time.Year;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Copies a caller's value once into plain JDK data, the first step of {@link Redactor#redactTree(Object)} (#360's
 * snapshot-first rule, adopted by #377 stage 1). The redaction then reads only the copy, so no caller object runs its
 * own code after the copy, and none is kept.
 *
 * <p>The copy holds only {@link String}s, the final JDK scalar classes in {@link #SCALARS} (by exact class, so a
 * subclass of {@link BigDecimal} is not one), and newly built unmodifiable {@link Map}s (iteration order kept),
 * {@link List}s, {@link Set}s and {@link Optional}s of copies. A record becomes a map from each component's name to its
 * copied value, so a record with a {@code kty} component is read as a JWK; an array or any other collection becomes a
 * list; an enum becomes its {@link Enum#name() name}; a map key that is not a string or one of {@link #SCALARS} becomes
 * text as any other value does; and every other value becomes its {@link String#valueOf(Object) string form}, so it
 * cannot carry a secret through unredacted. Each caller object is copied once, by identity: one that appears in two
 * places is the same copy in both, so each of its methods (a map's entries, a record's accessors, a {@code toString})
 * runs once. A value that holds itself, nesting deeper than {@link #MAX_DEPTH}, a copy whose expanded size (every
 * value, and every character of every string, counted each time it appears) passes {@link #MAX_WEIGHT}, or any failure
 * throws; {@link Redactor#redactTree(Object)} then returns the mask. The size bound also bounds the redaction, which
 * reads the copy as a tree.
 */
final class PlainData {

    /** The deepest nesting copied. */
    static final int MAX_DEPTH = 256;

    /** The largest expanded size of a copy: values, and characters of strings, each time they appear. */
    static final long MAX_WEIGHT = 16L * 1024 * 1024;

    /** Final JDK scalar classes kept as they are: none holds caller code or caller text. */
    static final Set<Class<?>> SCALARS = Set.of(
            Integer.class, Long.class, Short.class, Byte.class, Double.class, Float.class, Boolean.class,
            Character.class, BigInteger.class, BigDecimal.class, Instant.class, LocalDate.class, LocalTime.class,
            LocalDateTime.class, OffsetDateTime.class, OffsetTime.class, ZonedDateTime.class, Duration.class,
            Period.class, Year.class, YearMonth.class, MonthDay.class, ZoneOffset.class);

    /** Each caller object copied so far, with its copy and that copy's expanded size. */
    private final Map<Object, Copied> copied = new IdentityHashMap<>();

    /** The caller objects being copied, from the root down: meeting one again means it holds itself. */
    private final Set<Object> open = Collections.newSetFromMap(new IdentityHashMap<>());

    private PlainData() {
    }

    /** A copy and its expanded size. */
    private record Copied(Object value, long weight) {
    }

    /** A plain copy of {@code value}; {@code null} stays {@code null}. */
    static Object of(Object value) {
        return new PlainData().copy(value, 0).value();
    }

    private Copied copy(Object value, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("nested too deep to redact");
        }
        if (value == null || SCALARS.contains(value.getClass())) {
            return new Copied(value, 1);
        }
        if (value instanceof String s) {
            return new Copied(s, 1L + s.length());
        }
        Copied done = copied.get(value);
        if (done != null) {
            return done;
        }
        if (!open.add(value)) {
            throw new IllegalArgumentException("a value that holds itself");
        }
        Copied result = copyNew(value, depth);
        open.remove(value);
        copied.put(value, result);
        return result;
    }

    private Copied copyNew(Object value, int depth) {
        if (value instanceof Enum<?> constant) {
            return new Copied(constant.name(), 1L + constant.name().length());
        }
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> out = new LinkedHashMap<>();
            Weight weight = new Weight();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Copied key = key(entry.getKey());
                Copied item = copy(entry.getValue(), depth + 1);
                weight.add(key.weight() + item.weight());
                out.put(key.value(), item.value());
            }
            return new Copied(Collections.unmodifiableMap(out), weight.total);
        }
        if (value instanceof Set<?> set) {
            Set<Object> out = new LinkedHashSet<>();
            Weight weight = new Weight();
            for (Object item : set) {
                Copied c = copy(item, depth + 1);
                weight.add(c.weight());
                out.add(c.value());
            }
            return new Copied(Collections.unmodifiableSet(out), weight.total);
        }
        if (value instanceof Collection<?> collection) {
            List<Object> out = new ArrayList<>();
            Weight weight = new Weight();
            for (Object item : collection) {
                Copied c = copy(item, depth + 1);
                weight.add(c.weight());
                out.add(c.value());
            }
            return new Copied(Collections.unmodifiableList(out), weight.total);
        }
        if (value.getClass().isArray()) {
            List<Object> out = new ArrayList<>();
            Weight weight = new Weight();
            for (int i = 0; i < Array.getLength(value); i++) {
                Copied c = copy(Array.get(value, i), depth + 1);
                weight.add(c.weight());
                out.add(c.value());
            }
            return new Copied(Collections.unmodifiableList(out), weight.total);
        }
        if (value instanceof Optional<?> optional) {
            if (optional.isEmpty()) {
                return new Copied(Optional.empty(), 1);
            }
            Copied c = copy(optional.get(), depth + 1);
            return new Copied(Optional.ofNullable(c.value()), new Weight().add(c.weight()).total);
        }
        if (value instanceof Record rec) {
            return record(rec, depth);
        }
        String text = String.valueOf(value);
        return new Copied(text, 1L + text.length());
    }

    /** A sum of expanded sizes, one for the value itself, that fails once it passes {@link #MAX_WEIGHT}. */
    private static final class Weight {
        private long total = 1;

        Weight add(long weight) {
            total += weight;
            if (total > MAX_WEIGHT) {
                throw new IllegalArgumentException("too large to redact");
            }
            return this;
        }
    }

    /**
     * A map key: a string or a {@link #SCALARS} value as it is, an enum's name, anything else its string form, read
     * once.
     */
    private Copied key(Object key) {
        if (key == null || key instanceof String || SCALARS.contains(key.getClass()) || key instanceof Enum<?>) {
            return copy(key, 0);
        }
        Copied done = copied.get(key);
        if (done == null) {
            String text = String.valueOf(key);
            done = new Copied(text, 1L + text.length());
            copied.put(key, done);
        }
        return done;
    }

/** A record as a map from each component's name to its copied value, in component order. */
    private Copied record(Record rec, int depth) {
        Map<Object, Object> out = new LinkedHashMap<>();
        Weight weight = new Weight();
        for (RecordComponent component : rec.getClass().getRecordComponents()) {
            Method accessor = component.getAccessor();
            accessor.trySetAccessible();
            Object value;
            try {
                value = accessor.invoke(rec);
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("cannot read a record component", e);
            }
            Copied c = copy(value, depth + 1);
            weight.add(1L + component.getName().length() + c.weight());
            out.put(component.getName(), c.value());
        }
        return new Copied(Collections.unmodifiableMap(out), weight.total);
    }
}
