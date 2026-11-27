# Native metadata groups: source checkpoint

This is an independent Runtime component checkpoint. The complete Runtime,
complete cold source admission, release, installed Worker and pending index
remain unqualified by this checkpoint. The current public regression and
parallel public controls are still being completed.

## Public operation and custody

Archive and usage workers now create one nonblocking, close-on-exec Unix
SEQPACKET reply pair per request. One endpoint accompanies an atomic metadata
frame on the existing audit socket through SCM_RIGHTS. The daemon owns the
received endpoint until the actual observation ends; a caller timeout or
cancellation cannot release that custody or deliver to a reused slot.

Metadata queries no longer acquire the legacy byte-one complete-exchange
mutex. Ordinary admissions, completions and history retain their existing
protocol and mutex. The daemon's durable store mutex and existing per-worker
byte 64+slot lease are unchanged.

The daemon accepts exactly one Unix SEQPACKET descriptor with matching
SO_PEERCRED worker/uid and the original slot lease. recvmsg installs descriptors
with MSG_CMSG_CLOEXEC. Truncated bodies, truncated ancillary data, multiple
rights/messages and wrong socket kinds are rejected, with every installed
visible descriptor closed. Zero-byte data from a live peer is distinct from
EOF. Failed recvmsg results retain their full signed ssize_t representation.

## Explicit internal ABI

* Metadata input/output uses version 2 and HIARQY02/HIARQO02 or
  HIAUSQ02/HIAUSO02. Legacy version 1 remains an explicit separate protocol.
* Offsets 272/280 carry the original monotonic entry time. Offsets 256/264 keep
  the original absolute deadline. Reserved bytes 288..511 remain zero.
* Audit composition is HIARAU04 with 19 roles: the new batch role is index 17,
  followed by JSON at index 18. The old composition is not relabeled compatible.
* The only new native source path is
  examples/hia_bootstrap/mcp_request_audit_batch.hepta.
* The syscall adapter adds the existing bounded relocation action needed for
  native msghdr/iovec pointer construction. Policy remains in emitted HIA.

## Fixed observation rules

Each same-kind group contains at most eight already received, validated
members. Archive collection ends two milliseconds after the first original
entry; usage collection ends one millisecond after it. A later member never
extends that cutoff. The earliest original member deadline controls the
whole observation, and each public request keeps its original three-second
budget.

Small and unknown stores remain singletons. A large-store hint is established
only by a complete successful observation of more than 16,384 originals.
Hints never substitute for a new observation. Each member has its own owner,
cursor, limit, projection state, response bytes, slot and generation.
A local cursor/projection refusal stays local. A common original, namespace,
watch, poison or deadline failure discards all staged successes. Rendering
precedes the final original/namespace fence and publication follows cleanup.
The ninth or a later caller cannot reuse a completed result.

## Evidence retained in this checkpoint

The exact ae1c7ea593da45f7299c692a2acd44605c35be09 Rust audit/archive source
and all 26 original included test files were built and executed on Linux with
the unchanged locked graph: 447 passed, zero failed, ignored or filtered.
The source project packet and complete stdout/stderr/receipt are retained in
tests/fixtures/hia_metadata_batch_original. This is the original baseline,
not a count of native passes.

Four pinned native seed roots construct the new audit component, service and
HTTP bundles. Their construction receipts bind source and product hashes.
The current audit product is 1,906,450 bytes, SHA256
4fe29ef2e8685f0938a21b726d096d443ddb80c4a9bd72fd3ee070f74f671634.

Sixty actual native continuation checks pass after two independently retained
negative controls: swallowed recvmsg failure and a shared-custody refusal
incorrectly reaching the common response channel. The current source fixes
both. Real process controls additionally exercise complete 16,385-original
observations, eight private owner/cursor projections, all three persisted
states, mutation/refusal, cancellation and original deadline custody.

The prior real-process run and an intermediate observer failure remain
explicitly separate. The intermediate assertion incorrectly expected the
internal unknown record state on a live public page; the original Rust test
a_completion_after_membership_freeze_is_seen_by_the_fresh_group_observation
explicitly requires accepted. Only that observer assertion was corrected.

The first full original archive public regression exceeded an observer-only
240-second orchestration timeout during its retained fixture run. Its 13
completed original comparisons and complete partial output remain saved.
That timeout is not a changed three-second query budget or a successful
public qualification. The unchanged original method is being continued with
sufficient fixture orchestration time.

## Remaining work

Finish the expanded same-product real-process controls, full original public
archive/usage comparisons and actual concurrent stdio/HTTP calls. Integrate
the source through the canonical branch before regenerating the shared source
authority, Worker/release identities and complete final-chain evidence.

The original disposable pending index and original-content reader batches
are separate remaining implementation work: MAX_PENDING 8192, small flush
watermark 4096, large-store watermark/read-only tail 128, worker chunk 256 and
original read batch 32 remain the required source semantics. This metadata
group change does not claim those subsystems are implemented.
