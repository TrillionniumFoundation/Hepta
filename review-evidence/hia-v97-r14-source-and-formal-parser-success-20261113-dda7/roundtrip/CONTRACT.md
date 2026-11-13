# Bounded canonical reuse and assembly reparse

This independent development component restores a syntax document from the
existing formatter's output. It does not authorize Core execution, replace
the public assembly parser, or supply whole CLI qualification.

## Existing canonical serializer

`examples/hia_bootstrap/core_json_bytes.hepta` remains byte identical to the
fixed base. Its native entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. The input
is the actual JSON wire. The private workspace starts with eight little-endian
u64 words: `HIACJQ01`, the integer digit limit, and six zero words. The limit is
zero or at least 640. The existing image owns complete UTF-8 admission before
syntax, duplicate decoded keys, Core node/depth budgets, integer policy,
Unicode-key sorting, compact separators, UTF-8 escaping, and `-0` to `0`.

The reference is the unchanged `_decode` path, whose canonical output uses
`json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False,
allow_nan=False).encode('utf-8')` after original structure admission. Its
accepted scalar domain contains integers, strings, booleans and null, not
floating JSON numbers. No Unicode normalization is introduced. Empty exports
and all other arrays/objects remain part of the document.

The public serializer supports a larger allocation profile. This development
scope uses only calls whose actual input/output/workspace are each at most
1 MiB. Its existing `canonical_buffer_sizes` remains the admission rule; a
large syntactically accepted reparse result is not automatically within that
canonical scratch profile. No 8 MiB qualification is claimed here.

## New assembly reparse entry

New files are `tools/generate_hia_assembly_reparse.py` and
`examples/hia_bootstrap/assembly_reparse.hepta`. The ordinary borrowed-buffer
entry is `f0(readbuf assembly, mutbuf output, mutbuf workspace) -> u32`.

Each supplied extent must be at most 1 MiB. Workspace must be at least 103328
bytes. Its initial contents do not confer authority; the entry initializes
all parser control words and uses counts to guard private name records. The
output capacity is supplied by the caller. Successful return is the positive
JSON byte count; output bytes beyond it are unspecified but remain in bounds.
The input is read-only. There is no borrowed value or host object in the result.

The accepted internal grammar uses exact LF, the formatter's spaces, explicit
ASCII identifiers (up to 128 bytes), v6/v7/v8 headers, function and block
headers, four terminator forms, typed operation outputs, strict JSON attrs,
optional empty/nonempty exports, and v8 `return_loans`. Comments, blank lines,
CRLF, alternate whitespace and general public import syntax are outside this
internal grammar. Duplicate functions and blocks are refused; ordinary Core
semantic checking remains responsible for types, SSA, effects and loans.

Original syntax bounds remain 256 functions, 4096 blocks, 16384 operations,
256 list items, 16384 lines and bytes per line, 2048 attribute nodes and depth
16. The attribute scanner is the original HIA JSON preflight with source
offsets and two nonoverlapping private scratch regions relocated into one
workspace parameter. Its branch decisions are not replaced by a Python graph.

| Return | Meaning |
| --- | --- |
| `1..1048576` | Length of the produced syntax JSON |
| `0xffffffff` | Internal grammar or attribute syntax/Unicode refusal |
| `0xfffffffe` | Explicit syntax budget refusal |
| `0xfffffffd` | Supplied buffer or internal scratch ABI refusal |
| `0xfffffffc` | Duplicate name or decoded attribute key |
| `0xfffffffb` | Output capacity exhausted |

Errors may leave a partial JSON prefix and private workspace changes. A caller
must discard those results. This ABI does not promise original Python exception
objects, traceback identity, messages, or no-write-on-error behavior.

## Independent controls

The frozen raw records contain 104 logical native controls, 132 actual returned
native calls, two original-20-second compilations and eight full-buffer VM
comparisons. The VM limit stays 10 million steps; the largest observation used
286841 steps. All groups use the original 180-second owner plus 3-second cleanup.
Every native observer retains full source/output/workspace bytes and canaries.
The child reports no imported product modules. Original oracle calls occur in
the test process before or after the independent machine call.

The first native group recorded 54 successful observations and then failed at
an incorrectly authored reference fixture (`stop` was not an original trap
code). The successor found a second fixture error: entry parameters must equal
the function signature. Both failures, the original authoring `widen` error,
all source snapshots and their logs remain intact. The later 37-case group
continues only previously unexecuted rows; the 13 boundary cases and eight VM
pairs are separate groups. No prior failed group is relabeled PASS.

The controls include independent canonical scalars and Unicode/escaping,
integer limits, invalid UTF-8 ordering, duplicate keys, exact v6/v7/v8 and
empty exports, all terminator forms, returned-loan metadata, typed underscore
names, complete nested attribute values, truncations, duplicate assembly
components, changed attrs, short buffers, exact 2048/2049 node and 16/17 depth
boundaries, 256/257 parameter and function counts, 4096/4097 blocks, and
16384/16385 line bytes. Large syntax cases do not claim a larger canonical arena.

## Remaining composition

The development harness compares native reparse output after the existing
canonical image with the independent original reference. The current file
renderer has not yet captured or called this new component. Its resident
dispatch, preservation of the original JSON/canonical bytes, final machine
byte comparison, cold/portable source binding and complete production route
are separate work. `VerifiedProgram` is not constructed or granted by this ABI.
