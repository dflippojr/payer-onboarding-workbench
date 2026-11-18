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
 * cannot carry a secret through unredacted. Each caller method (a map's entries, a record's accessors, a
 * {@code toString}) runs once. A failure, or nesting deeper than {@link #MAX_DEPTH} (a value that holds itself), throws;
 * {@link Redactor#redactTree(Object)} then returns the mask.
 */
final class PlainData {

    /** The deepest nesting copied; a deeper value, such as a list that holds itself, fails the copy. */
    static final int MAX_DEPTH = 256;

    /** Final JDK scalar classes kept as they are: none holds caller code or caller text. */
    static final Set<Class<?>> SCALARS = Set.of(
            Integer.class, Long.class, Short.class, Byte.class, Double.class, Float.class, Boolean.class,
            Character.class, BigInteger.class, BigDecimal.class, Instant.class, LocalDate.class, LocalTime.class,
            LocalDateTime.class, OffsetDateTime.class, OffsetTime.class, ZonedDateTime.class, Duration.class,
            Period.class, Year.class, YearMonth.class, MonthDay.class, ZoneOffset.class);

    private PlainData() {
    }

    /** A plain copy of {@code value}; {@code null} stays {@code null}. */
    static Object of(Object value) {
        return copy(value, 0);
    }

    private static Object copy(Object value, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("nested too deep to redact");
        }
        if (value == null || value instanceof String || SCALARS.contains(value.getClass())) {
            return value;
        }
        if (value instanceof Enum<?> constant) {
            return constant.name();
        }
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.put(key(entry.getKey()), copy(entry.getValue(), depth + 1));
            }
            return Collections.unmodifiableMap(out);
        }
        if (value instanceof Set<?> set) {
            Set<Object> out = new LinkedHashSet<>();
            for (Object item : set) {
                out.add(copy(item, depth + 1));
            }
            return Collections.unmodifiableSet(out);
        }
        if (value instanceof Collection<?> collection) {
            List<Object> out = new ArrayList<>();
            for (Object item : collection) {
                out.add(copy(item, depth + 1));
            }
            return Collections.unmodifiableList(out);
        }
        if (value.getClass().isArray()) {
            List<Object> out = new ArrayList<>();
            for (int i = 0; i < Array.getLength(value); i++) {
                out.add(copy(Array.get(value, i), depth + 1));
            }
            return Collections.unmodifiableList(out);
        }
        if (value instanceof Optional<?> optional) {
            return optional.isEmpty() ? Optional.empty() : Optional.ofNullable(copy(optional.get(), depth + 1));
        }
        if (value instanceof Record rec) {
            return record(rec, depth);
        }
        return String.valueOf(value);
    }

    /** A map key: a string or a {@link #SCALARS} value as it is, an enum's name, anything else its string form. */
    private static Object key(Object key) {
        if (key == null || key instanceof String || SCALARS.contains(key.getClass())) {
            return key;
        }
        return key instanceof Enum<?> constant ? constant.name() : String.valueOf(key);
    }

    /** A record as a map from each component's name to its copied value, in component order. */
    private static Map<Object, Object> record(Record rec, int depth) {
        Map<Object, Object> out = new LinkedHashMap<>();
        for (RecordComponent component : rec.getClass().getRecordComponents()) {
            Method accessor = component.getAccessor();
            accessor.trySetAccessible();
            Object value;
            try {
                value = accessor.invoke(rec);
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("cannot read a record component", e);
            }
            out.put(component.getName(), copy(value, depth + 1));
        }
        return Collections.unmodifiableMap(out);
    }
}
