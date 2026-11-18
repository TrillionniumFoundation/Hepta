# Native SQLite snapshot components

These HIA components locate a row in an immutable SQLite table B-tree and
describe its physical SQLite record. Neither component opens a file, starts a
transaction, or uses SQLite, libc, or Python at runtime. The caller must provide
a stable, consistent, rollback-format snapshot. Do not pass a live database
file, a database requiring journal recovery, or an unmerged WAL database.
Neither component replaces the Agent Store.

## Build

Use the flat compiler from a matching source-only cold replay of this checkout:

```sh
python -B -m tools.build_hia_json_preflight --candidate sqlite-rowid-lookup \
  --compiler "$compiler" --cold-report "$cold_report" --output "$rowid_output"
python -B -m tools.build_hia_json_preflight --candidate sqlite-record-layout \
  --compiler "$compiler" --cold-report "$cold_report" --output "$record_output"
```

Each output is a flat Linux x86-64 image and a manifest. The hosted build driver
and independent VM are not runtime dependencies of the images.

## Flat-image ABI

Both inputs use the existing `(readbuf, mutbuf, mutbuf) -> u32` HIA entry ABI.
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
