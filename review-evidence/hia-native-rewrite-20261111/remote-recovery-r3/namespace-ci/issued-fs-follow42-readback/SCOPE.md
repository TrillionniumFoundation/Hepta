# FOLLOW42 exact original recorded frontier

This is a new, unexecuted, read-only stdlib program. It does not import project
code or execute a HIA generator, compiler, VM, native image or fixed ELF.

The official artifact download must use artifact 13932591885 from run
43192344684. HIA_NAMESPACE_FOLLOW42_DIR may point to either the direct extracted
artifact or a wrapper directory: the reader finds exactly one matching inner
archive and member index by full byte count and SHA256. GitHub's outer ZIP
digest is a declaration, not a claim that the extracted-directory reader has
recomputed the outer ZIP digest or CRC.

Before semantic parsing, it copies the complete pinned archive and index and
reads them back. It verifies all 4,272 original regular members, 323,619,640
raw bytes, exact modes and SHA256, additionally computing each Git blob ID.
Every original member is preserved, including full summaries, canonical
.hiaasm sources, images, builder/compiler receipts, requests, returns,
workspaces, syscall traces, VM ledgers and all other source/evidence files.

It parses actual trace framing and existing gzip ledger prefixes only. Each
complete ledger record is matched to the original trace offset and checked
against complete recorded input, pre-output, pre-workspace, return,
post-output and post-workspace bytes where the native post-record exists.
This verifies recorded bytes; it does not rerun a VM or infer an unrecorded
result. All first/last complete records and their full binary buffers are
preserved through a SHA256 CAS. Any incomplete gzip suffix is reported with
its exact length and digest and retained in full. Original trace headers
for every step are preserved in a separate full index.

The readable result distinguishes actual carrier process termination from
completed six-role replay, displays the original unittest stderr, original
partial summary keys, existing returned-VM records, and actual native records
without a stored VM line. Gzip and Python buffering can hide records that
completed but were not flushed. Therefore the first unrecorded trace entry is
only a candidate; neither the in-flight instruction nor the time allocation
nor a performance root cause is inferred.

All original JSON/u64 bytes remain unchanged. Only the console projection
represents integers as explicitly declared decimal strings. It is emitted as
one complete JSON smaller than 900,000 bytes; otherwise the reader fails with
an explicit bound report while preserving the whole untruncated JSON file.
A second archive and index are fully read back, including failure paths.
Input archive/index and reader-source checks run independently in finally.

The original failed target is never restarted. Its 900-second aggregate,
per-process 90 CPU / 180 wall / 1 GiB, 42 physical groups, 33 packer controls,
and 84 old-VM / new-VM / native comparisons are not changed. The reader itself
uses 90 CPU / 180 wall / 1 GiB / zero core and requires an external
timeout --signal=TERM --kill-after=5s 180s under pipefail. It needs CPython
3.12.14 and no third-party packages or common.prepare.

Status at handoff: zero AST checks, zero reader executions, zero HIA/B3/VM/
native entries. This is not a successful target qualification or ordinary
Store closure.
