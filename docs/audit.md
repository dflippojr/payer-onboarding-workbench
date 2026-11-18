# Audit trail

## Audit review (offline)

Run creation, actual credential resolution, run/history reads and report rendering emit one
JSON object after the `audit ` log message marker. Each HTTP request gets a server-generated
UUID; produced runs keep their existing outbound run ID. Callers are always `anonymous`
with a null actor ID and source `http`, regardless of supplied identity/correlation headers.
`report.rendered` records server rendering, not proof of saving or publishing a report.
A HEAD request to a read route runs the same handler as GET and is audited the same way.
An HTTP 200 `run.completed` can have a diagnostic verdict of `FAIL`.

Capture the existing log destination yourself, for example after building:

```sh
java -jar workbench-app/target/workbench-app-0.1.0-SNAPSHOT.jar > synthetic-capture.log 2>&1
node scripts/audit-reader.mjs synthetic-capture.log --run <server-run-uuid>
node scripts/audit-reader.mjs synthetic-capture.log --action report.rendered --since 2026-10-08T12:00:00Z --until 2026-10-08T13:00:00Z
```

Review a checked-in synthetic fixture without starting the app:

```sh
node scripts/audit-reader.mjs scripts/fixtures/audit-synthetic.jsonl --run 00000000-0000-4000-8000-000000000067
node scripts/audit-reader.mjs scripts/fixtures/audit-synthetic.jsonl --action run.requested
node --test scripts/audit-reader.test.mjs
```

The reader accepts one named capture, ignores unrelated logs, and emits matching events
as JSON lines. A capture is read as UTF-8 unless it starts with a UTF-16 BOM (LE or BE), which is
what Windows PowerShell 5.1's `>` writes. UTF-16 without a BOM is not detected. UTC `--since`/`--until` boundaries are inclusive, including nanoseconds.
A run filter selects credential/terminal/report events; the initial request event has no
run ID yet, so correlate it using the terminal's request ID in the unfiltered capture.
Malformed audit lines produce a count on stderr and a nonzero exit without echoing contents.
The app's own gap warnings (`Audit event write failed; audit trail has a gap` and `Audit journal
unavailable; durable audit trail is not being written`) are not malformed lines. The reader counts
them on stderr as `Audit gap warnings: N` and still exits 0: the capture is complete, and the gap
is in what the app failed to write.
Review makes no server calls and writes no files. Restrict access to captures using the
OS owner's permissions; the reader provides no additional authentication.

Audit metadata is an allowlist: known catalog IDs, enums, status/reason codes, verdict,
applied override field names and logical credential IDs (opaque per-run IDs for custom
credentials). It excludes credential values, client IDs, URLs, bodies and diagnostic content.
Availability means a credential was found, not that payer authentication succeeded.
Catalogs, static assets and actuator scrapes are outside this trail.
Normal operational logs remain separate and are not audit records.

Logging is best effort. An observable sink failure preserves the API/run behavior, emits
the constant warning `Audit event write failed; audit trail has a gap`, and increments
`workbench.audit.write.failures` (Prometheus: `workbench_audit_write_failures_total`). No
side effect is retried. Missing captures or logger/OS loss can also leave evidence gaps.
Durable storage is opt-in; see the next section. Without it, the only copy is the log
you capture yourself.

### Durable audit journal (#69)

Set `workbench.audit.journal-dir` to an **absolute** directory (for example
`--workbench.audit.journal-dir=/var/lib/workbench-audit`) and every audit event is also appended
to rolling JSON-lines segments there. Stdout logging continues unchanged as the secondary sink.

| Setting | Default | Meaning |
|---|---|---|
| `workbench.audit.journal-dir` | unset (journal off) | Absolute directory outside any source checkout |
| `workbench.audit.retention` | `30d` | Closed segments whose newest event is older than this are deleted; must be positive |
| `workbench.audit.segment-bytes` | `10485760` (10 MiB) | A segment is closed before it would pass this size; must be positive and at most `1073741824` (1 GiB) |
| `workbench.audit.total-bytes` | `104857600` (100 MiB) | When all segments exceed this, the oldest closed ones are deleted first, so the size cap can shorten the 30 days; must be positive |
| `workbench.audit.operator-label` | unset | Optional `[A-Za-z0-9._-]` label written to the manifest to name the deployment |

A zero or negative `retention`, `segment-bytes` or `total-bytes` (a typo such as `-30d` or `0d`)
never turns retention into a full wipe: the journal is left **unavailable**, exactly like a rejected
location below, and no segment or the manifest is read, changed or deleted. A `segment-bytes` above
1 GiB is refused the same way. A leftover segment of any size (even 2 GiB or more) is sealed by
streaming it, so it never stops the application from starting.

- **Location and access.** The directory is created owner-only (mode `0700`, or an ACL for the
  owner on Windows). An existing directory that group/others (or other Windows principals) can access,
  a relative path, a symlink, a path inside a checkout (a `.git` or `pom.xml` above it) or an
  unreadable manifest is **rejected**: the application logs the constant warning
  `Audit journal unavailable; durable audit trail is not being written`, counts it in
  `workbench.audit.write.failures`, sets the gauge `workbench.audit.journal.protected` to `0`
  and keeps running with log-only audit. It never silently counts as a protected journal. The
  checkout check resolves symlinks and junctions to their real path, but it does not expand a Windows
  `subst` drive or a mapped drive, so a journal directory reached through one can sit inside a checkout
  without being rejected. The machine owner is trusted to point `workbench.audit.journal-dir` somewhere
  sensible: the guard refuses what it can resolve, and anything it cannot resolve is the machine owner's
  responsibility. Review access is the OS owner's file access; there is no web page, endpoint or role.
- **Files.** `audit-000001.jsonl`, `audit-000002.jsonl`, ... plus `manifest.json`, a versioned list
  of closed segments (ID, bytes, event count, first/last UTC time, SHA-256). The open segment is
  not in the manifest until it is closed by size or by the next start. Nothing in the application
  updates or deletes events except retention. Run history stays memory-only (`max-runs`) and is
  independent of the journal.
- **One writer per directory.** An exclusive OS file lock is held for the lifetime of the journal,
  before recovery or retention runs. A competing process or application context falls back to
  logging, emits the constant journal-unavailable warning, increments `workbench.audit.write.failures`
  and reports `workbench.audit.journal.protected=0`. It does not adopt or change the active writer's
  segments or manifest. The empty `.writer.lock` file stays in the directory; do not delete it while
  any writer is running. Context shutdown writes dependent cleanup events, closes the active segment
  without sealing it, then releases ownership. The next successful start seals leftover segments.
- **Retention is a recorded operation.** Expiry deletes whole closed segments and appends one
  `audit.retention` event (`system` `audit-journal`, reason `age`, `size_cap` or `age_and_size_cap`,
  and the expired segment IDs and count, never record contents). It is retention, not evidence of
  immutable storage.
- **Who.** Callers are `anonymous`; system work is `system` with a named actor. The operator label
  only labels the process in the manifest. It does not say who made a request, and no header,
  payer credential or JWT claim is ever used as an actor.
- **Failure.** If a write or a rotation fails (full disk, deleted directory) the run, the API and
  the logging sink carry on, the constant warning `Audit event write failed; audit trail has a gap`
  is logged and `workbench.audit.write.failures` is incremented. The event is lost from the
  journal; that is the documented gap. A failed write closes the segment so the next event starts
  a fresh one. No side effect is retried.
- **Review and verify (offline).**

```sh
node scripts/audit-reader.mjs /var/lib/workbench-audit --run <run-uuid>
node scripts/audit-reader.mjs /var/lib/workbench-audit --action audit.retention
node scripts/audit-reader.mjs /var/lib/workbench-audit --verify
```

  Review accepts a journal directory as well as a log capture and takes the same filters. It reads each segment
  line by line at any size; a segment that exists but cannot be read fails the review with a nonzero exit, and
  only a missing segment is skipped. `--verify`
  prints one `{"segment":...,"status":...}` line per segment: `ok`, `missing`, `checksum_mismatch`,
  `truncated`, `malformed`, `event_count_mismatch`, `unlisted`, `seal_failed`, or `unsealed`. `seal_failed` is a
  segment the manifest lists with `"sha256":null` because the app could not checksum it when closing it, even on
  the one retry it makes (journals written before that change hold `"sha256":"unsealed"` there, reported the same
  way); it cannot be verified and is a problem, but the other segments still verify and review still prints its
  events.
  `unsealed` is a segment the
  manifest does not list yet, numbered above the highest listed segment (or any segment when none is
  listed), such as the one being written or left by a crash; not a failure. `unlisted` is a segment the
  manifest does not list but that is numbered below the highest listed one: the manifest and the directory
  disagree, as after a restore or an edit, and it is a problem. It exits nonzero on any
  problem and never prints event content. Checksums detect accidental corruption, truncation and
  missing files. They do **not** stop anyone with write access from changing a segment and the
  manifest together; the machine owner is trusted, and there is no signing or WORM storage.
- **Backup and restore.** Copy the directory (stop the app or accept an unsealed last segment).
  A restored copy reads the same events with the same IDs and timestamps; nothing is rewritten.
  **Restoring an older backup rolls the trail back** to that point: events after the backup are
  gone, and there is no separate journal that survives a restore. On the next start any leftover
  segment is sealed and a new segment begins, so processes are never silently merged.
- The journal records only the allowlisted metadata above. It never holds credentials, request or
  response bodies, FHIR/financial content or reports, and it cannot attest that a report was saved
  or a site published. Synthetic marker tests cover segments, reader output and the manifest.

Restoring an older log capture rolls the visible trail back too. The machine owner is trusted;
this is not tamper-proof storage or a compliance journal.

### Fault changes and system operations

The same marker and reader also carry admin and lifecycle events (#68):

| Action | Actor / source | Meaning |
|---|---|---|
| `fault.enable`, `fault.disable`, `fault.delay_set`, `fault.clear`, `fault.change` | `anonymous` / `http` | A `POST`, `PUT` or `DELETE` to `/admin/faults[/{id}]` on a synthetic payer, with or without `X-Request-Id`. Outcome `success` or `rejected`. Metadata has the payer ID, the known fault ID (null when the ID was unknown), and `faults`: enabled fault IDs before and after, `slowResponseDelayMs` before and after, and `changed` (false for a no-op or a rejected attempt). Rejected attempts carry fixed `reasonCode`s: `unknown_fault`, `invalid_delay`, `method_not_allowed`. Read-only `GET` creates no event. |
| `fault.changed` | `unknown` / `programmatic` | `FaultSettings` was changed directly by code outside the admin endpoint and outside a run. It is never reported as an owner operation. |
| `fault.run_setup`, `fault.run_reset` | the run's actor | One snapshot when a run applies its faults and one when its `finally` clears them, with the run ID and request ID. The reset shows the state that was actually restored. A setup that could not be applied is `rejected` with `setup_failed` and changed nothing. |
| `warmup.started`, `warmup.finished` | `system` `first-run-warmup` / `job` | The background warm-up run and the app's own empty-body self-request, which is recognised by a random in-memory single-use value (never configuration, logged or returned). Any other caller, including one that sends actor, source or the internal header itself, stays `anonymous`. Warm-up still never appears in run history, metrics or replay exports. |
| `startup.configuration`, `payer.started`, `connection.seeded`, `credential.put`, `credential.removed`, `payer.stopped`, `cleanup.attempted`, `cleanup.finished`, `startup.failed` | `system` `application` / `lifecycle` | Startup seeding and shutdown cleanup. Targets are payer IDs and logical connection/credential IDs only; never generated values, JWKS or key contents, paths, URLs, environment, arguments or whole property objects. Configuration records the custom-endpoints boolean, max runs and latency/timeout durations. |

`cleanup.finished` reports what was observed: `success`, `partial` (reason `delete_failed`, with safe `attempted`, `deleted` and `failed` counts) or `failed` (`walk_failed`). It never claims a deletion that failed. Logs cannot guarantee a shutdown event after `SIGKILL`, a crash or power loss, so a missing `cleanup.finished` means the process did not stop cleanly, not that cleanup succeeded.

Standalone mocks started without Spring still emit parseable `audit ` lines for their admin changes through `System.Logger`, and an embedding application can replace the sink with `MockPayer.auditSink`. The standalone admin endpoint remains unauthenticated and cannot identify a person, so its events are `anonymous`; a TLS handshake rejected by a certificate fault happens before HTTP, so it is never an admin event. Demo and replay scripts call the API as anonymous HTTP clients; their local output-file deletion, copying and website publication are outside the server's view.
