# HIA JSON value-arena candidate

**Whole-stack rewrite remains OPEN.** This candidate replaces JSON payload
syntax and value-tree decoding within its declared profile. It does not replace
the Python Core checker, canonical encoder, module system, runtime, service,
package manager, build tools, arbitrary-precision integer library or installer.
Default decoding is still the independent Python reference. No service or
release lock is changed by building the candidate.

## Implementation and wire contract

`examples/hia_bootstrap/json_decode.hiaasm` is ordinary verified HIA Core source.
Its 15 functions implement the preflight grammar/Unicode/duplicate-key checks,
then construct a preorder arena with container ownership, ordered sibling links,
decoded UTF-8 string/key bytes and exact signed-integer source slices. The small
authoring generator reuses the preflight algorithm, adding a private actual-node
count output; it does not run as a parser in the generated native image.

The native public entry receives immutable source bytes, a mutable arena and a
disjoint private workspace. Limits are 8 MiB source, 1..1,048,576 nodes and
root-at-depth-zero limits 0..128, matching the existing preflight profile.
Empty containers at the boundary retain existing semantics. Keys do not count
as value nodes. Fractional/exponent/nonfinite JSON numbers and isolated UTF-16
surrogates are refused, as in the existing HIA input subset.

The arena has a 64-byte little-endian header (magic, count, data start/end,
used bytes, input size, version 1, reserved zero). Each 56-byte node holds seven
u64 fields: tag, parent, next sibling, content start, content length, key start,
key length. Tags 0..6 are null, false, true, integer, string, array, object.
The absent-index sentinel is u64::MAX. Strings/keys refer to arena byte ranges;
integers refer to their unchanged input lexemes; containers refer to the first
child index and immediate-child count. Offsets are not foreign pointers.

The entry returns used bytes or u32 codes: `ffffffff` syntax/Unicode,
`fffffffe` budget, `fffffffd` profile/scratch and `fffffffc` duplicate key.
The host allocates bounded private buffers; the native first pass checks actual
node/depth budgets before constructing the graph, and checks total arena capacity.
The existing 1 MiB compiler capacities and cold deadlines are unchanged.

`hepta/hia_json_decode_native.py` validates the immutable arena's ranges and
single-parent tree before translating it to foreign Python objects. It uses
UTF-8 decoding and integer conversion, not a Python JSON tokenizer/parser.
Integer and object-pair hooks retain source-order, children-before-parent calls,
including exact `-0` lexemes. This bridge and trusted image loading remain Python;
there is no claim that producing foreign Python objects is HIA selfhosting.

## Explicit build and selection

Use the repository's task Python and an actual completed, matching cold receipt:

```sh
python -B -m tools.build_hia_json_decode \
  --compiler /path/to/B3.image.bin \
  --cold-report /path/to/cold.json \
  --output /new/private/directory
HEPTA_HIA_JSON_DECODE_MANIFEST=/new/private/directory/manifest.json \
  python -B -m hepta hia --help
```

The manifest binds HIA source, native image and compiler SHA-256. It selects
trusted local executable code, not a sandbox or submitted-payload code source.
An invalid selected artifact fails closed. Inputs outside the native profile
retain the prior reference API. Unsupported-profile fallback is not a native
qualification. Building never activates a production backend.

The selected route serves the existing Core and Agent JSON APIs and bounded
queue journal, state wire, full-cost, paired-replay and Rust byte-DAG inputs.
Canonical encoding and other internal/report JSON operations remain Python.
Finite VM/native/random/boundary observations are not an all-input correctness
or worst-case-cost proof, cross-platform qualification or whole-stack closure.
