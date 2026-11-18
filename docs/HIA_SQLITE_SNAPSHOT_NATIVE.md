# Native SQLite snapshot components

These HIA components reconstruct a committed view from an offline database and
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

## Flat-image ABI

All three use the existing `(readbuf, mutbuf, mutbuf) -> u32` HIA entry ABI.
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
Traverse interior entries from a known root; keep a visited set to reject
cycles and repeated pages. Page 1 is the root of SQLite's schema table.
An index or a WITHOUT ROWID table is not a rowid table and is not supported.

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
It takes one database basename and an inherited directory capability on fd 3.
Its cmd/reply transport uses stdin/stdout and requires a drained lossless
audit pipe on fd 4. There is no pathname fallback.

The retained operation is a separate copy from the ordinary page output.
Client event 6 reads and retains the selected page, 7 reads a checked span of
that copy by nonce and pin, and 8 releases the copy without releasing the read
transaction. END and cleanup invalidate the copy. Replies for event 7 carry
the exact requested offset/count and a separate payload of that length.
