package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.core.AuditSink;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Opt-in durable audit journal: rolling JSON-lines segments in an owner-only directory, a versioned
 * {@code manifest.json} with SHA-256 checksums of closed segments, and time/size retention. Append only
 * inside the application; the machine owner is trusted and checksums detect accidental damage, not a
 * deliberate rewrite. Failures throw a constant-message exception and never include event content.
 */
final class AuditJournal implements AuditSink {
    static final String MANIFEST = "manifest.json";
    static final int MANIFEST_VERSION = 1;
    private static final Pattern SEGMENT_FILE = Pattern.compile("audit-(\\d{6})\\.jsonl");
    private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Duration RETENTION_CHECK = Duration.ofHours(1);

    /** Rejected setup; the message is a constant reason code, never a path or content. */
    static final class UnsafeJournalException extends IOException {
        UnsafeJournalException(String reason) {
            super(reason);
        }
    }

    record Policy(Duration retention, long segmentBytes, long totalBytes) { }

    private record Segment(String id, long bytes, long events, String firstAt, String lastAt, String sha256) { }

    private final Path dir;
    private final Policy policy;
    private final String operatorLabel;
    private final Clock clock;
    private final ObjectMapper mapper;
    private final List<Segment> closed = new ArrayList<>();
    private int nextSeq = 1;
    private FileChannel channel;
    private String activeId;
    private long activeBytes;
    private Instant lastRetentionCheck;

    private AuditJournal(Path dir, Policy policy, String operatorLabel, Clock clock, ObjectMapper mapper) {
        this.dir = dir;
        this.policy = policy;
        this.operatorLabel = operatorLabel;
        this.clock = clock;
        this.mapper = mapper;
    }

    /** Validates the location, creates it owner-only if needed, adopts what is already there. */
    static AuditJournal open(String directory, Policy policy, String operatorLabel, Clock clock,
                             ObjectMapper mapper) throws IOException {
        if (operatorLabel != null && !LABEL.matcher(operatorLabel).matches()) {
            throw new UnsafeJournalException("invalid_operator_label");
        }
        Path dir = prepareDirectory(directory);
        AuditJournal journal = new AuditJournal(dir, policy, operatorLabel, clock, mapper);
        journal.adoptExisting();
        journal.retention();
        return journal;
    }

    static Path prepareDirectory(String directory) throws IOException {
        Path dir;
        try {
            dir = Path.of(directory);
        } catch (RuntimeException e) {
            throw new UnsafeJournalException("invalid_path");
        }
        if (!dir.isAbsolute()) {
            throw new UnsafeJournalException("path_not_absolute");
        }
        dir = dir.normalize();
        if (Files.isSymbolicLink(dir)) {
            throw new UnsafeJournalException("path_is_link");
        }
        for (Path p = dir; p != null; p = p.getParent()) {
            if (Files.exists(p.resolve(".git")) || Files.exists(p.resolve("pom.xml"))) {
                throw new UnsafeJournalException("inside_checkout");
            }
        }
        boolean posix = Files.getFileStore(dir.getRoot()).supportsFileAttributeView("posix");
        if (Files.exists(dir)) {
            if (!Files.isDirectory(dir)) {
                throw new UnsafeJournalException("not_a_directory");
            }
        } else if (posix) {
            Files.createDirectories(dir.getParent());
            Files.createDirectory(dir,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(dir);
            restrictAcl(dir);
        }
        if (!ownerOnly(dir, posix)) {
            throw new UnsafeJournalException("directory_not_owner_only");
        }
        return dir;
    }

    private static void restrictAcl(Path dir) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(dir, AclFileAttributeView.class);
        if (view == null) {
            throw new UnsafeJournalException("cannot_restrict_directory");
        }
        UserPrincipal owner = view.getOwner();
        view.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                .setPermissions(Set.of(AclEntryPermission.values()))
                .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT).build()));
    }

    private static boolean ownerOnly(Path dir, boolean posix) throws IOException {
        if (posix) {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir);
            return perms.stream().allMatch(p -> p.name().startsWith("OWNER"));
        }
        AclFileAttributeView view = Files.getFileAttributeView(dir, AclFileAttributeView.class);
        if (view == null) {
            return false;
        }
        String owner = view.getOwner().getName().toUpperCase(Locale.ROOT);
        for (AclEntry entry : view.getAcl()) {
            if (entry.type() != AclEntryType.ALLOW) {
                continue;
            }
            String who = entry.principal().getName().toUpperCase(Locale.ROOT);
            boolean trusted = who.equals(owner) || who.equals("NT AUTHORITY\\SYSTEM")
                    || who.equals("BUILTIN\\ADMINISTRATORS") || who.endsWith("\\CREATOR OWNER");
            if (!trusted) {
                return false;
            }
        }
        return true;
    }

    private void adoptExisting() throws IOException {
        Path manifest = dir.resolve(MANIFEST);
        if (Files.exists(manifest)) {
            try {
                JsonNode root = mapper.readTree(Files.readAllBytes(manifest));
                if (root == null || root.path("version").asInt() != MANIFEST_VERSION) {
                    throw new IOException();
                }
                for (JsonNode s : root.path("segments")) {
                    Segment segment = new Segment(s.path("id").asText(), s.path("bytes").asLong(),
                            s.path("events").asLong(), s.path("firstAt").asText(null),
                            s.path("lastAt").asText(null), s.path("sha256").asText());
                    if (!SEGMENT_FILE.matcher(segment.id() + ".jsonl").matches()) {
                        throw new IOException();
                    }
                    closed.add(segment);
                    nextSeq = Math.max(nextSeq, seq(segment.id()) + 1);
                }
            } catch (IOException | RuntimeException e) {
                throw new UnsafeJournalException("manifest_unreadable");
            }
        }
        List<String> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                if (SEGMENT_FILE.matcher(name).matches()) {
                    files.add(name.substring(0, name.length() - ".jsonl".length()));
                    nextSeq = Math.max(nextSeq, seq(files.getLast()) + 1);
                }
            }
        }
        files.sort(null);
        boolean sealed = false;
        for (String id : files) {
            if (closed.stream().noneMatch(s -> s.id().equals(id))) {
                closed.add(seal(id));
                sealed = true;
            }
        }
        closed.sort((a, b) -> a.id().compareTo(b.id()));
        if (sealed) {
            writeManifest();
        }
    }

    private static int seq(String id) {
        return Integer.parseInt(id.substring("audit-".length()));
    }

    @Override
    public synchronized void append(AuditEvent event) {
        try {
            byte[] line = (mapper.writeValueAsString(event) + "\n").getBytes(StandardCharsets.UTF_8);
            maybeRetention();
            write(line);
        } catch (IOException | RuntimeException e) {
            abandonActive();
            throw new UncheckedIOException("Audit journal write failed", new IOException("write_failed"));
        }
    }

    private void write(byte[] line) throws IOException {
        if (channel != null && activeBytes > 0 && activeBytes + line.length > policy.segmentBytes()) {
            rotate();
        }
        if (channel == null) {
            activeId = String.format("audit-%06d", nextSeq++);
            channel = FileChannel.open(dir.resolve(activeId + ".jsonl"), StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            activeBytes = 0;
        }
        ByteBuffer buffer = ByteBuffer.wrap(line);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
        channel.force(false);
        activeBytes += line.length;
    }

    /** A failed write may leave a partial line; close the segment so the next event starts a fresh one. */
    private void abandonActive() {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // nothing more can be done
            }
            closed.add(sealQuietly(activeId));
            channel = null;
        }
    }

    private Segment sealQuietly(String id) {
        try {
            return seal(id);
        } catch (IOException e) {
            return new Segment(id, 0, 0, null, null, "unsealed");
        }
    }

    private void rotate() throws IOException {
        String id = activeId;
        channel.close();
        channel = null;
        closed.add(seal(id));
        writeManifest();
        retention();
    }

    private Segment seal(String id) throws IOException {
        byte[] bytes = Files.readAllBytes(dir.resolve(id + ".jsonl"));
        long events = 0;
        String first = null;
        String last = null;
        int start = 0;
        for (int i = 0; i <= bytes.length; i++) {
            if (i == bytes.length || bytes[i] == '\n') {
                if (i > start) {
                    try {
                        String at = mapper.readTree(bytes, start, i - start).path("occurredAt").asText(null);
                        if (at != null) {
                            events++;
                            first = first == null || at.compareTo(first) < 0 ? at : first;
                            last = last == null || at.compareTo(last) > 0 ? at : last;
                        }
                    } catch (IOException | RuntimeException ignored) {
                        // damaged line: stays in the file, is not counted
                    }
                }
                start = i + 1;
            }
        }
        try {
            return new Segment(id, bytes.length, events, first, last,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    private void writeManifest() throws IOException {
        var root = mapper.createObjectNode();
        root.put("version", MANIFEST_VERSION);
        root.put("operatorLabel", operatorLabel);
        var segments = root.putArray("segments");
        for (Segment s : closed) {
            var node = segments.addObject();
            node.put("id", s.id());
            node.put("file", s.id() + ".jsonl");
            node.put("bytes", s.bytes());
            node.put("events", s.events());
            node.put("firstAt", s.firstAt());
            node.put("lastAt", s.lastAt());
            node.put("sha256", s.sha256());
        }
        Path tmp = dir.resolve(MANIFEST + ".tmp");
        Files.write(tmp, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(root));
        Files.move(tmp, dir.resolve(MANIFEST), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
    }

    private void maybeRetention() throws IOException {
        Instant now = clock.instant();
        if (lastRetentionCheck == null || now.isAfter(lastRetentionCheck.plus(RETENTION_CHECK))) {
            retention();
        }
    }

    /** Expires whole closed segments by age, then by the total size cap, and records what it removed. */
    private void retention() throws IOException {
        Instant now = clock.instant();
        lastRetentionCheck = now;
        Instant cutoff = now.minus(policy.retention());
        List<String> expired = new ArrayList<>();
        boolean byAge = false;
        boolean bySize = false;
        for (var it = closed.iterator(); it.hasNext(); ) {
            Segment s = it.next();
            if (s.lastAt() != null && Instant.parse(s.lastAt()).isBefore(cutoff) && delete(s)) {
                it.remove();
                expired.add(s.id());
                byAge = true;
            }
        }
        while (!closed.isEmpty() && total() > policy.totalBytes()) {
            Segment s = closed.getFirst();
            if (!delete(s)) {
                break;
            }
            closed.removeFirst();
            expired.add(s.id());
            bySize = true;
        }
        if (expired.isEmpty()) {
            return;
        }
        writeManifest();
        String reason = byAge && bySize ? "age_and_size_cap" : byAge ? "age" : "size_cap";
        AuditEvent event = new AuditEvent(1, UUID.randomUUID(), now, "system", "audit-journal", "lifecycle",
                "audit.retention", "success", null, null, "audit_segments", null,
                AuditEvent.Metadata.ofLifecycle(reason, null, null, AuditEvent.Lifecycle.retention(expired)));
        write((mapper.writeValueAsString(event) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    private long total() {
        long sum = activeBytes;
        for (Segment s : closed) {
            sum += s.bytes();
        }
        return sum;
    }

    private boolean delete(Segment s) {
        try {
            Files.deleteIfExists(dir.resolve(s.id() + ".jsonl"));
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
