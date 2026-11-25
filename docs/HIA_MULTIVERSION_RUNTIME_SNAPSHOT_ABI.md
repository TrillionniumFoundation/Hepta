# Private native multiversion snapshot renderer ABI (implementation in progress)

This pure HIA role formats facts captured by the native runtime while holding
its selection/lifecycle lock. It performs no observation, resource release,
registry mutation, proof or publication. The runtime owner supplies the actual
directory observation and retains all referenced generation owners until the
entire packet is captured. No source filename or arbitrary pointer is an
input to this formatter.

## Entry and result

The fixed six-word view entry is (s,sN,o,oN,w,wN) -> u64. Input and workspace,
and input and output, are disjoint owned views. All lengths are u64.
There is no aggregate 8 MiB limit. Workspace will require 65,536 plus 16 times
the larger of the generation and pending-task counts. Sorting uses two
bounded index vectors and exact decimal comparison, without narrowing public
generation, epoch, lease or attempt counts.

On success the result is the complete compact JSON byte count. On invalid
input it is UINT64_MAX, with no output writes. UINT64_MAX-1 means output
capacity insufficient; W[0] is the exact required JSON byte count.
UINT64_MAX-2 means workspace insufficient; W[8] is the required extent when
the supplied workspace is at least 16 bytes. W[16]/W[24] carry the offending
input offset/private reason on malformed input. Output is written only after
a complete measure/validation pass. No header precedes JSON.

Input header is 64 bytes:
magic HIAMVSP1 at 0; requested root kind at 8; root record extent at 16;
zero u64 words at 24 through 56. The root record immediately follows.
Kinds 1 through 7 and 12 may be top-level (generation/list records are children).

## Common record framing

Every record starts with four u64 words:
kind, flags, field count, complete record extent.
It is followed by field_count pairs (relative offset, byte length).
Fields follow that table contiguously in their listed order, with no gaps,
overlap or trailing bytes. An empty field has length zero and the same
current tail offset. All extents are checked using subtraction before any
addition or read. Child records use this same framing. A zero-length optional
record means absence; it is not a fabricated error or observation.

A list is kind 9, flags 0, with one framed child record per field.
An opaque JSON list is kind 10, flags 0, with one already validated JSON
fragment per field. Its fragments come only from fixed native producers;
this renderer does not re-admit arbitrary public JSON. Recent-events and
recent-attempts lists are limited to the original most recent 128 entries;
generation, pending, and totality lists gain no such new limit.

Text fields contain UTF-8 with WTF-8 surrogate encoding allowed. Filesystem
paths contain original fsencoded bytes and are decoded with UTF-8
surrogateescape. JSON strings use ensure_ascii escaping. Canonical decimal
fields are nonnegative ASCII digits, with no leading zero except the single
zero. They are emitted in full and compared by length then digits.

## Records

1. Full runtime snapshot: flags bit 0 closed, all other bits zero.
   Fields: profile text; selection_epoch decimal; current_generation decimal
   or empty for None; list(kind 9) of generation records; recent-events
   JSON list(kind 10); cleanup record(kind 2).
   Generations are sorted numerically by their captured generation key.
   The nested cleanup closed/state-empty flags must agree with this record.

2. Cleanup snapshot: flags bit 0 closed, bit 1 no current generation states.
   Fields: cleanup_attempts decimal; pending task list(kind 9) in original
   insertion order; recent-attempts JSON list(kind 10); directory cleanup
   record(kind 6); current directory observation(kind 5); directory pin(kind 3).
   Pending output is sorted numerically. pending_identity_releases keeps the
   original pending insertion order, then the directory entry when required.
   Completion booleans are computed from closed/state-empty, the actual pin
   and task flags, pending count, and actual observation status.

3. Path pin: flags low four bits are the actual retirement query flags;
   bit 4 selects native-decoder error field order (0 is reference order).
   Fields: filesystem path bytes; exact 4608-byte retirement state capture;
   optional acquisition error; optional close error; optional policy error;
   optional quarantined_open_result JSON object; optional
   foreign_open_result_slot JSON object. The last two are already captured
   native diagnostic JSON, present only with a policy error.
   The original 13 pin fields and conditional quarantine/last-attested fields
   are retained. State words and actual flags keep their original meanings.

4. Retirement task: flags low four actual query flags, bit 4 native order.
   Fields: generation decimal; cause text; artifact filesystem path;
   exact 4608-byte state capture; pin record; disk_attempts decimal;
   optional library error; optional fd error; optional disk-before observation;
   optional disk error; optional quarantined_foreign_resources JSON object;
   recorded inode (zero bytes for None or two u64 words).
   Policy diagnostic fields use the same pin's captured policy error.
   All native/disk timestamps come from the captured state. Counts never use
   the state's bounded generation/disk-attempt fields in place of captured
   full public decimal values.

5. Observation: flags low three bits status index (pending, absent,
   owned_present, replaced, unbound, recreated_after_release, error);
   bit 4 native error field order.
   Fields: filesystem path; observed_ns decimal; actual inode (0 or 16 bytes);
   optional error record. The inode is retained even when a later fstat failed.

6. Directory cleanup: flags low three bits status (0 not_attempted,
   1 already_absent, 3 refused_unowned_or_unobservable, 4 removed, 5 error);
   bit 4 native error field order.
   Fields: filesystem path; attempted_ns decimal; before observation;
   after observation; optional pin; optional error.
   Status 0 requires all fields empty and produces the original singleton
   status object. Every other status carries actual before/after facts.

7. Captured ordinary error: flags 0.
   Fields: exact exception type text; errno decimal or empty for None;
   exact exception message text. Message is truncated to the original first
   1024 Unicode characters during formatting. This is for actual captured
   native non-errno branches, not caller-supplied replacement exceptions.

8. Generation: flags bit 0 retired.
   Fields: verified GenerationInfo JSON object without its HIAMVIR2 header;
   generation decimal; active_leases decimal; path pin; totality-evidence
   JSON list. The generation key must agree with the producer's first
   generation field. The original info key order is preserved, followed by
   active_leases, retired, artifact_identity_pin and totality_evidence.

12. Native OS error: flags bit 0 filename present.
    Fields: errno canonical decimal; filesystem filename bytes.
    The renderer supplies the original errno subclass, Linux strerror text,
    Python filename repr and the same first-1024-character message truncation.
    Unknown errno uses the original Unknown error plus decimal value.
    Raw syscall/loader error capture remains the provider's responsibility.

Optional errors in records 3 through 6 are kind 7 or 12, or a kind-11
opaque verified error JSON object. Kind 11 has flags 0 and exactly one
already validated JSON field. Fixed native producer provenance for each
optional error/diagnostic fragment must be documented by the capturing owner;
missing evidence must not be filled with invented false/empty fields.

This ABI is a private formatting interface, not an external admission API.
Qualification and native construction remain pending until separately recorded.

## Final native construction and capture details

The complete callable flat is produced by multiversion_runtime_snapshot_packer.hepta from HIAMVSPK (32-byte header: magic, policy-flat length, zero, zero) and the actual policy flat. Its 175-byte mechanical prefix checks distinct views and translates the private u32 policy status/full W0 length to the public u64 ABI above. The policy compiler profile remains unchanged.

For a fenced state, the first 512 bytes of the 4608-byte state field are the actual last-attested header saved by its owner; never copy a damaged current header. The following path storage comes from the retained capture. Actual query flags, including zero after fencing, must be retained. This is diagnostic data and never grants release authority.

Kind 7 errno permits a signed canonical decimal integer or an empty field for null. Kind 12 takes the actual errno (positive for a failed Linux syscall; raw negative syscall returns are normalized by their effect owner). Its full filename bytes are the actual original filename, not a new path resolution. Loader errors without errno use kind 7 with the captured dlerror message. All messages use the original first 1024 Unicode characters.
