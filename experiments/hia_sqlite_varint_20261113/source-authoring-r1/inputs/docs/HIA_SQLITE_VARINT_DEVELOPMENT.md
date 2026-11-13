# SQLite varint HIA development component

This isolated candidate implements the complete `sqlite3GetVarint` and
`sqlite3PutVarint` byte algorithms over every unsigned 64-bit bit pattern.
It includes the behavior of `putVarint64`, the original writer's helper.
It has not yet been generated into HIA assembly, run in the Core VM, compiled
to native code, or installed into SQLite. The authoring source and the bridge
are concrete code; this document is not an execution result.

## Current persistence boundary

The base is pure v92 commit `0504beb11c0dae875d8590660c42488b7bc634fb`, tree
`596ab07e8813e4811a8dca51800cd51eb397aeb2`. The selected files were read in full
and matched the current physical source inventory. This task does not claim
to have reread the other repository bodies absent from that physical source.

`hepta/hia_agent_store.py` still opens the database with `sqlite3.connect`,
selects WAL and FULL synchronization, creates the tables, and executes SQL.
Its transaction context still owns BEGIN, ROLLBACK and COMMIT through SQLite.
The selected Agent journal and store-authority HIA components already choose
request/record actions, but their adapters explicitly retain the SQLite and
filesystem owners. Reimplementing those existing policy choices would not
replace the storage algorithms underneath them.

The repository's `tests/fixtures/sqlite_fixed_codec` contains complete original
four-byte `sqlite3Get4byte` and `sqlite3Put4byte` fixtures. Their scope is two
functions per version. This new component adds a different, complete pair of
format primitives; it does not replace or remove those original fixtures.

The pure-u64 durable queue is another remaining hosted path. In particular,
`DurableOwnedQueue._validate` performs ordered request deduplication and joins
the admitted, committed and attempt ledgers; `_store` still owns descriptor
write progress, fsync, replacement and failure poisoning in Python. Those
operations are outside this candidate and retain all original tests.

## Exact original functions

The retained official SQLite source versions are 3.46.0 and 3.53.2. Each
`src/util.c` was fetched through its immutable official mirror commit, with its
`manifest.uuid` checked against the existing repository's upstream SOURCE_ID.
The exact contiguous selected region is 3,897 bytes in each version and is
byte-identical across the two. It contains the two public functions, their
one complete helper, original masks, assertions and comments. The full
`util.c` originals remain beside the extraction record, so the selected region
can be independently reconstructed. No preprocessor branch was silently cut.

The selected original source is public domain. The authored oracle adapter
only supplies the original integer typedefs, `assert`, the noinline macro and
two exported forwarding functions. It contains no replacement varint logic.
The originals will be compiled separately for native comparison; they are not
linked into the HIA payload.

SQLite's format definition is at <https://sqlite.org/fileformat2.html>.
The first eight varint bytes each contribute seven payload bits. If none
terminates the value, the ninth byte contributes all eight bits. Reads accept
nonminimal representations. The writer emits the original shortest form,
including nine bytes for values of at least `2^56`. Negative SQLite rowids use
their two's-complement u64 bit patterns; SQL value coercion is not moved here.

## Executable algorithm and ABI

`tools/generate_hia_sqlite_varint.py` contains the executable HIA authoring
notation. The normal repository authoring aid produces a v8 Core document and
`sqlite_varint.hiaasm`. It is not imported by a native codec call.

The single entry takes the existing three-span/six-actual-argument native ABI.
The control span is a 16-byte little-endian `HIASVR01` command with operation
1 (decode) or 2 (encode). It is checked and never changed. Decode accepts up to
nine input bytes and an eight-byte output. Encode accepts one eight-byte u64
and an output capacity from zero through nine. Successful returns are the
original consumed/written counts, 1 through 9. The exact fields and refusal
codes are in `hepta/hia_sqlite_varint_abi.json`.

The decoder accumulates at most eight seven-bit payloads, then shifts the
56-bit prefix by eight for the ninth byte. Every shift is within the u64
domain. It checks available length before every read and does not reject a
nonminimal value. The encoder calculates the required length before any
output write. The nine-byte branch preserves the original order, writing the
last byte first and then the preceding bytes backwards. The other branches
write forward. No returned tail byte is changed.

The raw SQLite C API assumes a valid pointer/allocation and has no bounded
truncation/capacity refusal. The new slice ABI makes those failures explicit
before output mutation. These safety refusals are an extension outside the
original valid-allocation domain; they are not alleged original SQLite error
codes. This candidate does not assert equivalence for invalid raw pointers,
overlapping mutable spans, races, volatile stores or signals between C stores.

`hepta/hia_sqlite_varint_native.py` only prepares spans, invokes the admitted
image, checks complete input/control/canary and output-tail custody, and
materializes the u64/byte result. It does not scan continuation bits or compute
the encoded length. No fallback to the original codec exists in this bridge.
There is no default selector, SQLite monkey patch, SQL engine replacement,
database open, file write, or network access in this component.

## Source controls and planned native qualification

Eight new source control IDs are fixed in `test_hia_sqlite_varint_source.py`.
They cover all nine lengths and every u64 power boundary; nonminimal reads;
all 256 possible ninth bytes with three complete prefixes; all incomplete
continuation-only prefixes; every encode capacity; bad protocol envelopes;
exact bridge types, offsets, exception identity and buffer custody; the full
original source regions and retained existing test IDs. Source execution must
record expected, loaded and executed IDs and every actual VM buffer.

The source request must preserve the original 180-second owner and separate
three-second cleanup, refuse compiler/native/network use, and retain failure
originals. The generated program must fit the unchanged full source limits:
1 MiB, 16,384 lines, 8,192 operations, 1,536 blocks and 128 functions; 256 blocks
and 2,048 SSA values per function; 16 parameters/arguments and three results.

A separate future native request must bind an actual compiler's complete
source/image/receipt capsule, use the original compile wall/CPU/output caps,
compile both full original C regions separately, and compare the actual HIA
results and all buffer tails. It must include all source-case families plus
the full two-byte input population and independent original C results. The
original C decoder must never be called on an incomplete allocation: its test
input will have a complete valid encoding or an initialized nine-byte region.
No source or native result currently exists for this new component.

## What remains open

Neither this byte primitive nor an eventual successful finite comparison will
close SQLite query execution, record serial types, B-tree balancing, page
allocation, locks, WAL, rollback journals, transaction durability, concurrent
writers, crash recovery, or actual AgentStore integration. Python allocation,
buffer materialization and executable-mapping custody also remain explicit
foreign owners. Future integration must actually replace a selected storage
call site and run its unchanged transaction/restart/error controls; composing
or testing the codec alone cannot claim that work complete.
