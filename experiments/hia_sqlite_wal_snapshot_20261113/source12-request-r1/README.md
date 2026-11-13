# WAL committed snapshot and page locator

Status: source authored; generation, VM, C, native and tests have not run.

This module advances the AgentStore persistence replacement at the byte/pager
boundary. The existing WAL byte kernel verified one header or frame. The new HIA
core scans the chain, saves the latest complete commit and locates the newest
version of a requested page within that fixed committed prefix.

## Production-facing interface

The explicitly qualified image exposes a scanner and a locator. A caller supplies
the captured WAL length and base-database page geometry, then satisfies the exact
header/frame requests. A finished scan returns an immutable snapshot; a locator
copies its 256-byte continuation and replays only its committed prefix.

The returned location is one of: missing (above the snapshot database size),
base database, or page data in a particular WAL frame. The WAL result also gives
the selected frame's checksum state before and after decoding so a future pager
can bind its final page read. The core stores no entire WAL, whole database or
unbounded page index. Replay is linear per page lookup; that is an explicit initial
algorithm cost, not a claim of a production-speed index.

Pseudo integration, with the external lock and exact I/O supplied by the pager:

    scan = image.scanner(wal_bytes=captured_size,
                         base_page_size=db_header.page_size,
                         base_page_count=db_header.page_count)
    while scan.request is not None:
        request = scan.request
        scan.provide(read_exact_bound_wal(request.offset, request.size))
    snapshot = scan.finish()

    lookup = image.locator(snapshot, page_number)
    while lookup.request is not None:
        request = lookup.request
        lookup.provide(read_exact_same_wal(request.offset, request.size))
    location = lookup.finish()
    # Keep the same external reader protection for the final page read.

No such I/O or lock adapter is implemented in this draft. In particular, a short
read is an error: provide() requires the exact request size and permanently
closes the session on failure. It cannot convert an I/O error into a benign tail.

## Commit and snapshot rules

The two retained official walIndexRecover bodies are exactly equal. They update
mxFrame, nPage and the saved committed checksum only after a valid frame with a
nonzero dbsize. This draft follows that rule. A valid zero-dbsize tail can advance
the scan's working checksum and valid-frame count, but cannot become visible.

An invalid header format/checksum yields a recorded ignored-WAL result; an
unsupported version after a valid checksum is a refusal. A corrupt frame ends
the recovery prefix; the scanner never searches later bytes for a new chain.
A partial final frame is excluded according to the captured extent.

A locator compares all eight header fields, rechecks frame salts and rolling
checksums, and must reach the saved end-mark index, byte end, dbsize and checksum.
A changed prefix is refused. Valid frames appended after the snapshot are not
requested. Pages above a truncating commit's database size are missing even if
an earlier frame for that page remains in the file.

The state is 256 bytes, every reply 128 bytes, and the largest packet is one
65560-byte SQLite frame plus a 16-byte command. WAL length uses SQLite's existing
signed 64-bit file-offset domain; there is no additional whole-WAL size policy
limit. Page numbers and dbsize retain the unsigned 32-bit format domain. Any
additional pager-level maximum page count must be admitted separately.

## Preserved algorithms and sources

The checksum_region, word and control_word functions are complete byte-for-byte
copies of the retained WAL HIA author's source. Header and frame admission use
the same order and checksum regions. Official complete wal.c files for SQLite
3.46.0 and 3.53.2, their exact recovery/page-finding functions, and the original
HIA author/bridge/ABI/source tests are retained under reference/.

Historical WAL finite-native evidence is 7ffcb9375481a29ccffb69b6fdc681be247d539d.
It covers the old checksum/header/frame byte kernel only. It supplies source
provenance; it does not qualify this scanner, a fixed snapshot, locking, recovery
I/O or SQL.

## Source-only request

The twelve new source methods preserve the original nine HIA structural caps.
Independent expected bytes use closed-form Fibonacci checksum weights and a
finite Python reference that first parses frames and then selects the last
commit; it never calls the HIA checksum or snapshot implementation.

The fixed VM denominator is 608 returned calls, with the exact per-method
derivation in EXPECTED-VM-COUNTS.json. Complete frame bodies in this first source
request use 512-byte pages. Larger sizes through 65536 exercise header and
packet/offset boundaries; they are not represented as full-page VM execution.
A later separately frozen finite-native request must cover every actual page
size with full frame/lookup buffers.

control/source12.py and clean_exec.py adapt the already used Record Source12
runner. The original 369 process owner, 180-second qualification/3-second cleanup,
effect-deny guard, exact twelve IDs, complete before/after source reads, and
closed-before-child-read rule remain. Changes are operation identity, test
module, evidence schema and the new complete mutable-state buffer reader.
The support source remains the already bound 1686-file 0504 source library used
by that runner; the new algorithm files are an isolated overlay. This does not
claim that a current matching-cold native image exists.

## Open production work

Reader/recovery/write locks, descriptor identity and generation stability,
checkpoint/backfill and WAL reset, shared WAL-index synchronization, database
header/page-size compatibility, page I/O, page mutation, durable commit/fsync,
SQL/query semantics and the AgentStore shared transaction adapter are still
external. Checksums and salts provide format/chain checks, not synchronization
or cryptographic identity. A read-lock-zero/backfill decision belongs to the
external pager; this byte scanner does not substitute for sqlite3WalBeginRead.

The default service still constructs its current AgentStore. This draft changes
no default, old test, old timeout, product workflow, or installed behavior.
