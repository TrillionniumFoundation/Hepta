# HIA ten-family catalogue root, private author R1

## Implementation boundary

This author supplies seventeen typed HIA author functions, a development generator
using the retained HIA SHA implementation, and an independent Python byte-format
oracle. The static typed check passed. Generation, Core verification, native
compilation, VM/Native controls and filesystem publication have not run.

The catalogue contains all ten current Store table families in the exact order
defined by the retained hia_agent_store.py DDL: artifacts, profiles, contexts,
requests, costs, cursors, slots, versions, leases and execution_budgets. A
transition constructs one complete new root. Unchanged records retain every
byte; all selected changed records share one generation increment and checksum.

This component does not implement row operations, uniqueness, indexes, a complete
page graph, durability, locks, recovery, migrations or request replay history.
In particular, a supplied nonempty table digest/count is only encoded metadata.
It is never proof that its pages exist, that its count is true, or that a request,
slot, version and budget mutation is authorized. A later HIA transaction owner
must establish the complete durable graph and row semantics before giving this
root to the separate commit-head continuation. No public Store admission or
default backend change is made by this author.

## Exact catalogue bytes

The root is exactly 576 bytes, with u64 values encoded little endian.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | HIACAT01 |
| 8 | 8 | Format version 1 |
| 16 | 16 | Nonzero Store UUID |
| 32 | 8 | Catalogue generation |
| 40 | 8 | Exact table count 10 |
| 48 | 16 | Reserved zeros |
| 64 | 480 | Ten records of 48 bytes, in table-ID order 1 through 10 |
| 544 | 32 | HIA SHA-256 of the complete preceding 544 bytes |

Each record contains its table ID (8 bytes), logical row count (8 bytes), and
32-byte table-root digest. No table may be omitted, duplicated or reordered.
Every digest must be nonzero. A zero count requires the exact digest of the
canonical empty page for this Store UUID and this table ID. Nonempty graph
membership and counts require the separate graph owner; this codec does not
pretend to validate them from their digests.

The empty page is exactly 64 bytes: HIATBL01 at 0, version 1 at 8, table ID at 16,
zero row count at 24, Store UUID at 32, and sixteen zero bytes at 48. Its digest
is HIA SHA-256 of all 64 bytes. Different Store UUIDs and table IDs therefore
have separate canonical empty-page byte strings. These pages still need actual
durable publication by the file owner; computing a hash publishes nothing.

## Three-buffer entry and request

The entry is catalog_root(readbuf source, mutbuf output, mutbuf workspace).
The workspace extent is exactly 2048 bytes and output is at least 1152 bytes.
All three physical owners must be distinct and admitted. The workspace is
cleared after the full request header/shape checks. This is a stateless codec;
a partially written failed frame conveys no authority or reusable transaction.

The 128-byte header begins with HIACRQ01. It contains operation at 8, expected
generation at 16, changed-table bit mask at 24, nonzero Store UUID at 32, selected
table ID at 48, and seventy-two reserved zero bytes beginning at 56.

| Operation | Source extent | Payload and successful result |
|---:|---:|---|
| 0 | 704 | Full catalogue after the header; verify UUID/generation/all records/hash and return those exact 576 catalogue bytes |
| 1 | 1104 | Full old catalogue plus ten fixed 40-byte updates; construct one next-generation catalogue and return 576 bytes |
| 2 | 128 | Construct the complete empty generation-zero catalogue and return 576 bytes |
| 3 | 128 | Selected table ID 1 through 10; return its 64-byte empty page followed by its 32-byte digest |

Only operation 1 accepts a nonzero change mask, restricted to bits 0 through 9.
Each selected update is a u64 count followed by its 32-byte root digest. It must
differ from the old pair. Every unselected 40-byte update must be all zero;
ignored extra proposal data is rejected. Selected zero-count proposals must
match the canonical empty page. Generation exhaustion refuses before adding
one. The Store UUID and exact ten-table record order remain unchanged.

Only operation 3 accepts a nonzero selected-table field. Operations 2 and 3
require generation zero. Trailing, truncated, malformed-header and wrong-sized
inputs are refused. The source-header generation must equal the actual old
catalogue generation for operations 0 and 1.

Bad request ABI returns 4294967293; bad catalogue/hash returns 4294967292; invalid
transition or exhausted generation returns 4294967291. Successful extents are
576 or 96. Those extents describe the returned logical value, not the full
modified scratch extent. Every future observation must preserve all source,
output and workspace bytes and physical canaries, including rejected calls.

## SHA ownership and retained source

The five retained SHA functions, compression constants, round algebra and padding
are reused through a complete reversible author projection. The mutable input is
an admitted workspace subrange of exactly 544 or 64 bytes. All hash scratch and
the digest at offset 1088 live in the distinct output owner. The catalogue and
the empty-page scratch occupy nonoverlapping workspace ranges 0..575 and
576..639. The last digest is copied into the catalogue only after hashing; final
output bytes are copied after all checksum work. No Python hash decides a
production result. Python hashlib appears only in the independent oracle and
development provenance.

The generator and typed author checker retain complete preimages from the
commit-head author. AUTHOR-INVERSE.json lists every literal projection and
proves the complete original bytes and AST are recovered. The actual op8
source tree remains 3210 files with tree 7f694b80c7ab76eb9d62402aeea4c331503ddc16.
Neither that source nor any original fixture or budget was modified.

## Next actual gates

The explicit control plan retains two separate generation owners and a complete
check, each with fresh complete source/runtime guards and original 180+3 timing.
Actual Core verification, a 20-second/10-CPU/1-MiB compilation envelope, and
10-million-step/8-MiB/depth-128 VM controls must follow. Future controls must
compare actual outputs to the independent oracle, every full before/after
buffer and original limits; no fabricated Native result or expected checksum
may fill a missing observation.

Original Store/namespace/request/slot/budget tests remain unchanged and are not
qualified by the new codec tests. The complete durable graph, ten-family row
semantics, joint request transaction, current cold production installation and
legacy retirement remain open.
