# Native SQLite snapshot components

These flat HIA components reconstruct a committed view from an offline database and
WAL pair, locate a row in an immutable SQLite table B-tree, and describe its
physical record. No component opens a file, starts a transaction, or uses
SQLite, libc, or Python at runtime. Snapshot consistency and database/WAL
pairing remain the caller's responsibility. Do not pass a live database or WAL,
an inconsistent copy, or a rollback database requiring hot-journal recovery.
The components do not replace the Agent Store.

## Build

Use a complete HIA source checkout and the flat compiler from its matching
source-only cold replay. These build commands are not Agent wheel entry points.

```sh
python -B -m tools.build_hia_json_preflight --candidate sqlite-wal-snapshot \
  --compiler "$compiler" --cold-report "$cold_report" --output "$wal_output"
python -B -m tools.build_hia_json_preflight --candidate sqlite-rowid-lookup \
  --compiler "$compiler" --cold-report "$cold_report" --output "$rowid_output"
python -B -m tools.build_hia_json_preflight --candidate sqlite-record-layout \
  --compiler "$compiler" --cold-report "$cold_report" --output "$record_output"
```

Each output is a flat Linux x86-64 image and a manifest. The hosted build driver
and independent VM are not runtime dependencies of the images.

For private Agent migration, use the same command with
`sqlite-agent-row-import`, `sqlite-agent-import-batch`,
`sqlite-agent-cost-sequence`, `sqlite-agent-artifact-catalog`,
or `sqlite-agent-catalog`.

### Standalone retained-migration components

```sh
python -B -m tools.build_hia_sqlite_components --compiler "$compiler" \
  --cold-report "$cold_report" --output "$component_output"
```

The output contains eight standalone Linux x86-64 programs (`hia-sqlite-*`),
each linked with one unchanged HIA image. They run without a runtime FFI,
interpreter, dynamic loader or subprocess. Start a separate process for each
component and each independent scratch lifetime. A request consists of
`HIASCC01`, three unsigned 64-bit little-endian lengths (input, output,
scratch), and exactly the input bytes. The response is `HIASCR01`, the
zero-extended HIA return code, the two output and scratch lengths, then those
two complete byte regions. Both buffers start zeroed; only scratch retains
its bytes, and its length cannot change during a session. In particular, send
all three catalog phases to the same component process. Drain the response to
each request before sending another. An empty frame boundary on stdin closes
the process normally; partial or out-of-profile frames exit 64 without
executing that frame. A transport I/O failure exits 74, separately from HIA
decision codes. This transport accepts up to 256 MiB input and 64 MiB each
output and scratch; the individual HIA image still applies its own limits.

These programs expose the component ABI only. The caller must still hold the
same Pager snapshot across components, stage all references and bytes, and
handle migration and activation as a whole.

## Flat-image ABI

The flat images use the existing `(readbuf, mutbuf, mutbuf) -> u32` HIA entry ABI.
The input, output, and scratch buffers must not overlap. Offsets within the
component wire formats are bytes; integer fields are little endian.

| | Rowid lookup | Record layout |
| --- | --- | --- |
| Input | 8-byte root page, 8-byte signed rowid, then the database bytes | Raw record payload |
| Minimum scratch | 64 bytes | 16 bytes |
| Successful output | `HIAROW01`, payload length, SQLite text-encoding code, leaf page, then payload | `HIASREC1`, column count, consumed bytes, header length, then one 32-byte descriptor per column |

Each tag is eight bytes, and all fields after it are unsigned 64-bit values,
except for the signed rowid in the input. Each column descriptor contains the
serial type, byte offset from the start of the record, byte length, and scalar
bits. The decoder preserves signed integer bits, IEEE binary64 bits (including
NaNs), and raw text and reserved serial types; it does not perform SQL
affinity, collation, or Unicode conversion.

Return codes are `0` success, `1` invalid input, `2` insufficient output, and
`3` insufficient scratch. Rowid lookup additionally returns `4` for a missing
row and `5` for an unsupported database format or B-tree kind. Errors leave
the output untouched; the scratch buffer is private and may change. B-tree
checks cover the visited table path and selected record, not the integrity of
an entire database or index.

### Rowid lookup over retained pages

The rowid image also accepts bounded, demand-supplied pages from one active
WAL read transaction. Instead of the complete database, pass the following:

1. A 4-byte root page, the literal four bytes `HSP1`, and the signed 8-byte
   rowid.
2. The complete page 1 as returned by the Pager, without changing its WAL
   journal-format bytes.
3. Two 8-byte values: the logical snapshot page count reported by the Pager
   and the number of additional resident pages.
4. Each resident page's 8-byte page number followed by its complete bytes.
   Page numbers must be strictly increasing, exclude page 1, and be within the
   logical snapshot. There must be no trailing bytes.

Reserve at least 72 scratch bytes for this form. Status `6` means another page
is needed. The required page number is the little-endian 8-byte value at
scratch offset 64. There is no output on that status. Obtain the page from the
same active Pager, add it to the resident set in sorted order, and retry. A
success uses the same `HIAROW01` output as the offline form. The lookup
rechecks the path from the root on each retry; it never follows a different
transaction, reads a page itself, or requests a page outside the admitted
geometry. The caller owns transaction identity and must discard these bytes at
END; the image cannot establish that separately supplied pages come from the
same transaction.

### Enumerating table pages and rowids

Use the same retained-page wire with tag `HSP2`, the page number in place
of the root, and eight zero bytes in place of the rowid. The output tag is
`HIABTW01`, followed by the page kind, entry count, and page number (all
8-byte unsigned words). For interior table pages (kind 5), the entries are
8-byte child page numbers in table order, including the rightmost child.
For leaf table pages (kind 13), they are 8-byte signed rowids in table order.
An empty leaf returns count zero.

The component validates the selected page's cell geometry and keys before
writing the result. It does not enumerate or read overflow pages for this
operation. Status `6` asks for the selected page if it is not resident.
Page 1 is the root of SQLite's schema table.
An index or a WITHOUT ROWID table is not a rowid table and is not supported.

The `sqlite-table-walk` component can own traversal instead of leaving page
selection and row ordering to the caller. Use one process per table, passing
the same 24-byte retained snapshot identity in every request. All requests
start with `HIASTW01`, an eight-byte phase and the snapshot identity:

- Phase 1 appends the logical page count and table root as 8-byte words.
- Phase 2 appends the exact `HIABTW01` header and entries for the page that
  the previous reply requested. Trailing zero transport capacity is not input.

A successful reply is `HIASWA01`, the completed page (zero for phase 1),
the next page (zero only at completion), a rowid count, and those signed
rowids. HIA visits children in B-tree order, tracks visited pages, rejects
out-of-range or duplicate children/cycles, and requires signed, strictly
increasing rowids across leaves. Short output (2) or scratch (3) does not
advance the walk. An invalid frame, wrong snapshot/page or ended walk returns
1; impossible tree order or reuse returns 4 and invalidates the walk. No
failure writes output. Scratch is private, including an 80-byte header,
`floor(page_count / 8) + 1` bitmap bytes, and eight bytes per pending child.
If the caller's scratch budget cannot hold the frontier the walk refuses
instead of dropping pages. The Pager must remain the source of page bytes
and lock custody; an identity attached by the transport is not proof of data
provenance. Completing a table walk is not migration activation.

### Admitting an Agent schema before migrating its rows

`sqlite-agent-catalog` discovers the typed roots for the exact original UTF-8
Agent schema. Keep one zero-filled 1024-byte scratch buffer for all phases
of one SQLite snapshot. Every request starts with the eight-byte tag
`HIASCAT1` and an eight-byte phase. For phase 1, append the retained logical
page count and the SQLite encoding code. For phase 2, append the positive
physical rowid, the fixed descriptor size (192 bytes), the `HIASREC1`
descriptor, and the raw record. Feed all rows of the retained page 1 table
in increasing rowid order, including its original automatic indexes. Do
not mix snapshots; the Pager owns that binding.

Phase 3 is just the tag and phase. A complete catalog returns `HIASCOK1`,
version 1, count 11, then the eleven root page numbers as eight-byte words:
the ten Agent tables in the order below, followed by `sqlite_sequence`.
Malformed frames return `1`, short output `2`, short scratch `3`, an
incomplete or duplicate catalog `4`, and unsupported encoding or schema
`5`. No error publishes roots, and phase 3 cannot be repeated after
success. The program checks exact column declarations, keys, constraints,
and automatic indexes, allowing whitespace and ASCII keyword spelling
case variation in the SQL. It does not migrate custom schemas, additional
DDL, other SQLite encodings, or open native Store state.

### Projecting a SQLite row to the private HIA Store format

`sqlite-agent-row-import` produces one typed stored row for the ten known
Agent table numbers (artifacts, profiles, contexts, requests, costs, cursors,
slots, versions, leases and execution budgets, in that order). Its source is
the eight-byte tag `HIASQI01`, table number, signed physical rowid, encoding
code, layout byte count, the exact `HIASREC1` descriptor bytes, then the raw
record. All header numbers are eight bytes. The layout must come from the
record decoder for that exact record; neither input supplies table or
transaction authority.

On status `0`, the output is a private Store `HIAROW01` version 1 record, not
the lookup output described above. After the tag, version, table and number
of columns, each column has three 8-byte words: storage kind (NULL 0, INTEGER
1, REAL 2, TEXT 3, BLOB 4), output-relative offset, and byte count. The cost
sequence alias comes from the physical rowid, because its SQLite record
column is NULL. Actual integers and binary64 values retain their exact bits.
Status `1` is malformed input, `2` is insufficient output, and `5` is
unsupported text encoding (this bridge accepts UTF-8 only). The output is
untouched on an error; this component needs no scratch.

This is only a row projection. It does not apply constraints, migrate
`sqlite_sequence`, publish durable data, move artifacts, or change which
Store the Agent uses. The receiving Store must still validate the row and
apply its complete transaction protocol.

### Packing projected rows for a private transaction

`sqlite-agent-import-batch` packages already projected rows for the private
Store transaction producer. Its input has the tag `HIASQB01`, version 1, a
nonzero transaction ID and a nonzero row count. Each frame holds the table
number, signed physical rowid, row byte count, and exact `HIAROW01` bytes.
Header and frame integers occupy eight bytes each. Supply rows in ascending
(table number, signed rowid) order, without duplicates.

On status `0`, the output is a `HIATXB01` version 1 proposal: the transaction
ID and row count are followed by a contiguous directory of (table, signed
rowid, absolute offset, row byte count) and the row bytes. The extent is
the input size plus eight bytes per row. The program checks frame bounds,
matching row tags, versions and tables before writing anything. It leaves the
output unchanged on malformed input (status `1`) or insufficient capacity
(status `2`); no scratch is needed. The receiving producer still performs
full typed-row and cost alias validation. A proposal is not a commit, and
this interface does not preserve a deleted cost high-water by itself.

### Preserving a deleted cost sequence during staged migration

`sqlite-agent-cost-sequence` accepts `HIASQH01`, version 1, a nonzero
transaction ID, the highest nonnegative live cost rowid (zero if absent),
and the original UTF-8 SQLite record bytes for the `costs` row of
`sqlite_sequence`. The first four fields each occupy eight bytes. The
sequence must be a nonnegative SQLite integer. Both the live-row maximum
and the sequence record must come from the same retained snapshot; this
component does not obtain or authenticate that snapshot.

An ahead-of-live sequence is represented by one 656-byte `HIAWAL01`
transaction: BEGIN, canonical cost PUT, DELETE of the same key, and COMMIT.
There is no surviving row, but committed cost history retains the sequence
even if it is the signed maximum. The transaction has four native SHA-256
seals. This is staging for a new private migration namespace, not an
authorization to update an existing or publicly opened Store. The native
writer must still admit, append, and publish against the selected anchor.
No writes occur in the caller's output on status `1` (malformed),
`2` (output too small), `3` (scratch smaller than 4096), or `4` (the
sequence is not ahead; no transaction is needed). Success is status `0`.

### Artifact byte inventory for staged migration

`sqlite-agent-artifact-catalog` takes the exact `HIATXB01` proposal and
returns `HIAFID01`, version 1 and artifact row count, followed by one
lowercase 64-byte content digest per artifact row in physical rowid order.
Version and count each occupy eight bytes. Two rows may legitimately name
the same content. A valid proposal without artifact rows returns count zero.
The image validates the directory extent and ordering, and reads only the
typed digest within each bounded artifact row; other values remain the
transaction producer's responsibility. Malformed records (status `1`) or
short output (status `2`) leave the output untouched. Scratch is not needed.

An inventory alone neither reads nor authorizes files. Actual migration
must still verify the content bytes against the digest and stage them under
the private destination's artifact ownership before exposing any migrated
references.

## Committed WAL view

The WAL component takes an 8-byte size of the base database, the corresponding
nonempty main database in WAL format, and then the complete captured WAL. An
empty WAL denotes the already checkpointed base. The component checks the WAL
header and rolling frame checksums in either checksum byte order, and selects
through the last valid commit. Frames after that commit do not affect the view.
It applies the last committed version of each page and respects the committed
database size. The fixed scratch header is 64 bytes, followed by one byte for
each page in the committed view beyond the physical base.

On success, the output begins with the eight-byte tag `HIASNAP1` and five
unsigned 64-bit fields: page size, view byte length, count of validated frames,
one-based index of the last committed frame (zero for none), and the reason the
valid prefix ended. Reason codes are `0` complete, `1` incomplete final frame,
`2` salt mismatch, `3` invalid page number, and `4` frame checksum mismatch.
Inspect that reason before deciding how to handle a damaged capture. The view
starts at byte 48; only its first-page journal format bytes are normalized to
rollback format for in-memory consumers such as rowid lookup. Neither source
file is written or claimed safe to restore without further integrity checks.

Return codes `0` through `3` have the meanings above. The WAL component also
returns `4` for an invalid nonempty WAL header and `5` for an unsupported WAL
version. Errors leave the output untouched.

## Read-only retained Pager

The retained Pager is separately built and selected. Unlike the offline WAL
component, it acquires an actual SQLite-compatible read transaction and
retains its file/lock ownership until END. It does not open an Agent database
by default, implement SQL or write transactions, or replace the Agent Store.

```sh
python -B -m tools.build_hia_sqlite_pager \
  --compiler "$compiler" --cold-report "$cold_report" --output "$pager_output"
```

The hosted build uses the cold HIA compiler, a fixed three-file assembler
adapter, and the HIA ELF linker. The resulting `hia-sqlite-pager` is a Linux
x86-64 executable with no interpreter, libc, child program, or host SQL engine.
The command/reply transport uses stdin/stdout. In direct mode, start it
with a source directory and database basename, and continuously drain
stderr as a binary audit pipe. The adapter opens the selected directory
without following a symlink at its endpoint. SQLite files and locks are
still opened only through the HIA Pager policy.

The original one-argument mode takes a database basename and an inherited
directory capability on fd 3 with the lossless audit pipe on fd 4.
Neither mode opens a different source after an error.

The retained operation is a separate copy from the ordinary page output.
Client event 6 reads and retains the selected page, 7 reads a checked span of
that copy by nonce and pin, and 8 releases the copy without releasing the read
transaction. END and cleanup invalidate the copy. Replies for event 7 carry
the exact requested offset/count and a separate payload of that length.

For migration, BEGIN may set its little-endian word at byte 72 to `1`.
This asks the HIA owner to acquire SQLite's exclusive WAL writer lock
before reading the first published WAL-index header, and hold it through
the retained read. A busy writer causes a refusal rather than an
unprotected snapshot. Ordinary BEGIN keeps this word zero and still
permits concurrent writers. The lock is released by END or cleanup and
does not modify the source database or WAL. This is a migration prerequisite,
not an activation mechanism: a caller must still hold the source boundary
through migration and prevent the old service from accepting writes after
cutover.

With byte 72 set to `2`, BEGIN reads a clean, checkpointed WAL-mode main
database with **no** `-wal`, `-shm` or `-journal` sidecar. The Pager opens
the ordinary database read/write only to obtain SQLite's exclusive database
byte-range lock; it does not write any database bytes. It checks the held and
named file identity under that lock, requires every sidecar to be absent
(including symlinks), and validates page size/count against the actual file and
its version-valid page-count header. It rechecks the identity, extent,
timestamps and all three sidecars at END before releasing the lock. Retained
page tokens and spans bind to this database identity and require the exclusive
lock; WAL-mode tokens continue to bind to their captured WAL header and lock.
This mode never starts WAL or
recovery, creates a sidecar, or falls back to another source/mode. The caller
must select the migration profile matching the source.

## Committing a proposal to a staged HIA Store

The source-bound Agent batch commit executable stages a transaction from an
admitted `HIATXB01` proposal, emits the sealed `HIAWAL01` records, and runs the
native writer to append the records and publish the next immutable anchor.
The producer, stager, writer, and executable packer are all HIA. The
Linux x86-64 adapter transports fixed descriptor operations to the kernel;
the resulting ELF needs no interpreter, libc, hosted SQL, or child process.

```sh
python -B -m tools.build_hia_agent_batch_commit \
  --compiler "$compiler" --cold-report "$cold_report" --output "$writer_output"
```

To commit a first batch to a freshly initialized private Store, invoke
`hia-agent-batch-commit STORE_DIRECTORY`. Supply one little-endian unsigned
64-bit proposal length, the exact `HIATXB01` bytes, and EOF on stdin. The
length must be between 32 and 1,000,000,032 bytes. The executable opens the
initial anchor and the named Store files, seals the proposal in a private
memfd, and creates the unnamed anchor stage itself. No extra descriptors are
passed by the caller. A stale initial anchor or a busy writer lock is refused
by the native writer; this argument form is not for appending later batches.

To append the native cost-sequence records after the initial batch, invoke
`hia-agent-batch-commit STORE_DIRECTORY GENERATION`. Supply the selected
anchor generation as exactly 16 lowercase hexadecimal digits (for example
`0000000000000001`), and send the same length framing with the exact
`HIAWAL01` records in place of a proposal. The limit for the records is
1,000,000,000 bytes. The executable seals the record bytes and invokes the
same native writer, which requires the named anchor to still be current.
The caller must take the records from the same retained migration snapshot.

The no-argument descriptor form remains available. Supply the selected
128-byte `HIAWAK01` anchor on stdin (followed by EOF). The caller supplies the open WAL data
file on fd 3, selected anchor file on fd 4, Store directory on fd 5,
WAL lock on fd 6, namespace identity file on fd 7, and an unnamed new
anchor file in the Store directory on fd 10. Fd 12 holds the read-only-mode
(`0400`) proposal memfd with all four seals; fd 9 must be unoccupied.
The HIA stager creates and seals its own transaction file on that slot.
A nonzero exit or missing receipt is not permission to repeat a possibly
durable write; first reopen the Store and verify the selected anchor.

This primitive is selected explicitly for private migration. The executable
does not initialize a destination, select a source snapshot, move artifact
bytes, switch the Agent's active Store, or replace the existing SQL path.

The no-argument sealed-record entry can also be built with `--kind sealed`.
It uses the same HIA writer as the batch entry,
with the same stdin and descriptors 3 through 7 and 10. Fd 9 instead
carries the HIA-generated `HIAWAL01` transaction in a `0400` memfd with
all four seals; there is no proposal or fd 12. Reopen the staged Store and
select its current anchor before switching from the batch entry to this
entry. Both refuse to overwrite an existing anchor.

## Reading and updating the staged Agent Store

The persistent Agent Store transaction root and its four authenticated
modules build from checked-in HIA sources. The bootstrap requires the
source-bound cold compiler. Its fixed word filter admits the exact compiled
bytes and relocation frame for each unit before copying or patching any
output. The build plan records the admitted input and output digests; it is
not a runtime extension mechanism. The HIA packers build all four modules
and place the loader, transaction owner, module manifest, and JSON hub in
the final ELF. The builder independently checks the emitted layout against
the assembled descriptor adapter.

```sh
python -B -m tools.build_hia_agent_store \
  --compiler "$compiler" --cold-report "$cold_report" --output "$store_output"
```

This is the Linux x86-64 native Store transaction protocol, not the public
Agent service. Launch it directly with the staged Store's parent directory,
one namespace basename, the build's module directory, and optionally the
read-only artifact directory:

```sh
"$store_output/hia-agent-store" "$parent" "$basename" \
  "$store_output/module-root" "$artifact_directory"
```

This mode needs no descriptor setup by a host process. It checks private
descriptor slots before opening paths, refuses symlink endpoints and
admits the same module and namespace identities as descriptor mode.
The module directory may be the private build stage (`0700`) or an
immutable installed release (`0500`). The latter may contain the executable,
initializer and the four authenticated module files in the same directory:
pass that directory as the module root. Other permission bits are refused;
the installer does not select the writable Store's state directory.
The original no-argument descriptor mode still reads the initial namespace
header from stdin. In direct mode, stdin starts with `HIATCM01` commands
and stdout emits native acknowledgements and result frames. Use streamed
bindings (kind 27, target operation in the offset word) followed immediately
by that command's exact typed payload. No borrowed parameter fd is needed.
Commit or rollback ends the current transaction; use NEXT before sending
more operations. A lost commit receipt is not safe to replay.

The native engine owns overlay reads, typed updates, indexed lookups, and
commit or rollback for the original Store operations. An optional artifact
capability allows already migrated content to be reopened and checked.

### Selecting the Store for the existing Agent worker

For validation on a separate state root, initialize a `store` namespace inside
that root and keep its existing immutable artifacts in `artifacts`. Pass the
installed release directory and the executable SHA-256 pins to the existing
worker, along with its ordinary request envelope:

```sh
python -m hepta.hia_agent_worker --state-root "$staged_state" --request-json-stdin \
  --native-store-release "$installed_release" \
  --expected-native-store-sha256 "$store_executable_sha256" \
  --expected-native-artifact-sha256 "$artifact_executable_sha256" \
  --expected-native-capture-sha256 "$capture_executable_sha256" < request.json
```

All three executables are pinned and sealed before launch; HIA authenticates
the four Store modules against the Store executable. The installed capture
application admits and reads permitted input paths. The installed artifact
application hashes, publishes and verifies complete artifact byte streams.
The worker transports the existing typed operations to the same Store
process. It does not open SQLite, fall
back on refusal, or replay an unacknowledged commit. A native state root is
not eligible for the legacy worker, and the worker refuses to select the
native backend on a root containing a legacy journal or its sidecars.

This selection changes persistence, capture and artifact byte effects, not
the implementation of the remaining tool methods or public MCP routing.
Selected HIA candidate and execution-budget policies use the same native
transaction session and lock. They cannot borrow an active caller
transaction. The default backend and migration cutover are unchanged.

The Store reader checks complete WAL frames and index nodes even when it
processes several contiguous bytes at once. Its bounded private memo keeps
recent digests within the Store process. Before using a cached digest, HIA
compares every SHA-256 state and block byte (or the exact index node bytes).
A miss always recomputes the digest; the memo does not change persisted
bytes, anchor selection, locking, or the checks on admitted rows.

## Initializing a fresh native Store

Build the standalone initializer with `python -B -m
tools.build_hia_agent_batch_commit --kind initialize` and the same compiler,
cold report, and output options as the batch writer. Run
`hia-agent-store-init <owned-parent> <new-basename>` to initialize a
fresh Store under a caller-selected private parent. The HIA policy owns
namespace naming, real kernel entropy admission, modes, the initial
`HIAWAK01` anchor, sync ordering and no-replace publication. The assembly
adapter passes only fixed effects to Linux; no external programs or SQL
are used to initialize state. The initializer does not move data or select
the result as the Agent's active Store.
