# Native SQLite snapshot components

These HIA components reconstruct a committed view from an offline database and
WAL pair, locate a row in an immutable SQLite table B-tree, and describe its
physical record. No component opens a file, starts a transaction, or uses
SQLite, libc, or Python at runtime. Snapshot consistency and database/WAL
pairing remain the caller's responsibility. Do not pass a live database or WAL,
an inconsistent copy, or a rollback database requiring hot-journal recovery.
The components do not replace the Agent Store.

## Build

Use the flat compiler from a matching source-only cold replay of this checkout:

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
