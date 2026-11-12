# Native immutable commit coordinator — authoring contract

This document defines the next implementation after the record codec and paged
view components. It is not a successful execution report. The complete ten
tables, 31 relational operations, 51 existing call sites, five storage classes
and frozen transaction/journal decisions remain the interface. No ordinary
worker selects this draft and no legacy SQLite file is retired by it.

## Persistent representation and admitted predecessors

`DATA` contains the complete raw `HIANLR01` record stream. `CURRENT` is exactly
32 bytes: the digest of an immutable head object in `HEADS`. An object is named
by its 64 lowercase digest digits; its complete canonical bytes are 128 bytes:

| Byte offset | Content |
| --- | --- |
| 0 | `HIANHD01` |
| 8 | u64 format version 1 |
| 16 | 32-byte namespace identity |
| 48 | 32-byte predecessor head digest |
| 80 | u64 predecessor committed prefix |
| 88 | u64 new committed prefix |
| 96 | 32-byte digest of the exact appended stream's canonical page chain |

The head object's name is its native SHA-256 over all 128 bytes. Genesis has
zero predecessor digest, both prefixes zero and zero append chain. It is
constructed by HIA from an actually issued namespace identity. Later commits
have a strictly increasing prefix and the digest of the exact predecessor head.
There is no persistent u64 commit-count ceiling: identity is content-linked.
Checked descriptor/call counters are process-local transport generations.

The append chain uses exact 4,096-byte pages, except for the final nonempty
short page. Starting from 32 zero bytes, each step is native
`SHA256(previousChain || littleEndianU64(pageLength) || SHA256(pageBytes))`.
Every hash input is bounded independently of the namespace/history size. This
internal record-store checksum does not replace an artifact's existing raw
SHA-256, change artifact names, or add a namespace/value byte quota. Head hash,
page hash and chain hash reuse the existing HIA SHA schedule/round algebra.

A commit starts from a private native-issued base-head/view lease, an actual
writer-lock lease, and a captured pending-spool lease. The pending lease binds
the complete native record-codec validation, actual descriptor, captured
prefix, generation and canonical page-chain digest. Preparing rereads and
hashes those exact bytes while copying them. It refuses if the final digest
differs. A matching integer handle or caller-provided digest is not proof of
an arbitrary external spool. The fixed surrounding coordinator must bind the
actual completed predecessor calls; a test stand-in is not production custody.

Opening an existing namespace also needs actual head/object hash and native
history/data validation. A head header alone does not authenticate its DATA
prefix. The commit component does not silently substitute a short header read
for that full admitted predecessor. Migration must preserve raw TEXT/BLOB,
rowids and the complete `sqlite_sequence` cell, including its original integer
conversion, and fence old writers before native selection.

## Original transaction boundaries

The existing transaction owner still issues action 6 prepare, action 7 data
sync, action 8 head publication, action 9 root sync, and explicit scope
retirement/unlock. They remain separately acknowledged operations:

1. Under the actual writer lock, read the actual current pointer and compare
   it with the admitted base head. A stale base fails before changing DATA.
2. Check the actual DATA descriptor and extent. A shorter committed prefix is
   corruption. An uncommitted tail may be truncated only back to the current
   committed prefix under this same lock; an older committed prefix is never
   discarded by an old view or by scope retirement.
3. Copy the captured spool through bounded reads and writes. HIA retains the
   exact offset, page length and partial-write progress; an executor never
   chooses a new source, retries a semantic operation, or reports inferred
   success. Positive short I/O issues only the remaining range.
4. Validate the complete page chain and construct the new head in HIA. Create
   its immutable named object with exclusive creation. If it already exists,
   HIA must read and compare its exact bytes; existence alone is not success.
5. On action 7, perform actual DATA, head-file and HEADS-directory fsyncs.
   Prepared bytes and durable bytes are different states.
6. On action 8, create and write an owned temporary CURRENT file, fsync it,
   reread the actual base pointer under the same lock, and atomically rename
   the temporary pointer. The HIA-issued path and complete operation identity
   are fixed for each step. A new publisher cannot overwrite an unowned temp.
7. On action 9, perform the actual root-directory fsync. Only then is the
   durable publication stage reported. A later close/unlock failure cannot
   turn an already published commit into an uncommitted one.

A zero-change COMMIT takes the existing discard/retire/unlock route; it does
not call prepare or manufacture an empty new head. Results transferred out of
the transaction remain independently owned. Read-only calls get fresh view
and row generations even if no persistent head changed.

Unknown acknowledgements permanently refuse their owner. They do not license
a new action identity or replay. A syscall error that can leave publication
indeterminate, including the rename/EIO boundary, cannot be advertised as a
known unchanged pre-publication failure. Native recovery inspects the actual
current pointer in another admitted session. Temporary descriptor cleanup is
mechanical resource retirement; it is not a rollback or a commit decision.
Linux close/EINTR cannot be retried as though the same descriptor lease were
still live. Each phase has an explicit error/ownership rule.

## Mechanical executor and framing boundary

The intended executor is a fixed syscall/descriptor transport. HIA chooses
open-at paths/flags, exact read/write offsets and extents, fsync targets,
rename operands, close/unlink ownership and every continuation. The executor
returns actual kernel results with the issued session/call/action identity;
it does not parse heads or rows, calculate domain hashes, classify transaction
state, generate a successful lease on demand, or select the next syscall.

There is no subprocess reuse, forged native image, hosted SQL fallback or
ordinary-worker selector in the component fixtures. A temporary Python
mechanical fixture, if used during development, must be labelled as such and
must dispatch the actual native images and actual syscalls. It cannot count as
the final fixed native executor or as completed legacy migration.

## Required real-file and process controls

Validation must retain exact HIA input/output/workspace bytes in compressed
paged ledgers and original syscall outcomes. It must cover stale base heads,
partial I/O, errno and unknown ACKs, actual file replacement/truncation,
all data/head/root fsync boundaries, rename-before-ACK process death, and
cross-session/sequence/generation refusal. Two real processes must contend on
the actual lock and publish against the head they observe after acquisition;
an always-successful lock callback is not that test.

Concurrent readers keep their original immutable prefix while later writers
append. Once a writer dies, another admitted native session must distinguish
old/current/new pointer states and preserve every committed prefix. This still
does not fence a pre-existing SQLite writer: the managed-worker drain and
durable old-open guard remain a separate mandatory migration gate. An unknown
old writer or missing original evidence keeps migration on HOLD.

## Private state revision record

The first actual B3 image completed one complete positive file transaction,
including real partial-read/write controls and every durability stage. Before
broader controls, three explicit private-workspace probes showed that changing
only the publication marker, admitted DATA lease, or initial spool cursor could
still issue the first CURRENT read. The original image, complete frames and
positive result are retained. These were private state consistency probes; no
ordinary external input or filesystem mutation was used for the counterexample.

Revision 2 retains an immutable copy of the issued binding words and checks
the publication marker against the exact phase/stage. It also binds a fresh
idle stage to zero processed bytes/no owned handles and a completed idle stage
to the complete pending prefix and checksum. It does not claim that duplicate
private fields authenticate an arbitrary externally supplied full workspace.
No error policy, transaction boundary, file range, wait/compile budget or public
relational API is reduced by this change. Actual revision-2 execution remains
a separate result from the revision-1 positive case and original fault probes.
