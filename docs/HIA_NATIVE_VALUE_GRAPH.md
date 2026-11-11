# Native complete-value transport

`hepta/hia_native_value_graph.py` decodes complete values selected by HIA.
It contains no instruction, type, ownership, dispatch or export policy.
`tools/hia_native_value_graph.py` supplies ordinary HIA writers. Its existing
`BODY` remains unchanged; `EXTERNAL_BODY` explicitly opts a new owner into
external references, preserving checked source and images of existing owners.

## Encodings

Ordinary typed-tree tags 0–7 retain their existing representation. Output tag
8 references one complete original input node. Tag 9 concatenates complete
original input arrays. Input bytes cannot themselves contain references.
Tag 10 references one private external pool ID; tag 11 concatenates arrays at
private external pool IDs. These are u64 identities and array references,
not executable callbacks or opcode-specific construction plans. HIA selects
the complete dictionaries, arrays, keys and positions.

`decode_native_graph(encoded, original, external=())` accepts an exact list or
tuple of held entries, or a `NativeValuePool`. A prepared pool's `add(value)`
validates the representation and returns its zero-based ID. `get(id)` returns
the held value. Prepared pools are append-only; IDs never change or expire.
A raw list/tuple pool validates each referenced entry on every decode. The
pool boundary is private and cannot be selected by source programs.

## Identity and stable custody

JSON entries contain exact `dict`, `list`, `str`, `bool`, `int`, finite `float`
or `None` values. Dictionary keys are exact strings. An exact outer tuple is
also admitted as an immutable array snapshot; nested tuples are refused.
A tag-10 reference to a JSON dict/list/scalar reuses that held object identity.
A tag-10 reference to an outer tuple produces a new outer list, retaining every
child identity. Tag-11 concatenation accepts list or tuple arrays and always
produces a new outer list in the native-selected order. No operation deep
copies complete Core arrays or invents a semantic placeholder.

The private controller must not mutate pooled JSON containers after insertion.
When an operation owner will append to an existing list, the controller first
pools `tuple(existing_list)` or another stable outer snapshot. For a dictionary
which will later be assigned, it takes an outer dictionary snapshot. Shared
nested values must already be complete and stable. Mutation of returned
shared values during a pool's lifetime violates this private custody contract;
prepared pools intentionally do not rescan every prior large result on every
continuation. A raw pool performs a fresh representation check when referenced.

Validation rejects cycles, excessive depth, non-string keys, nonfinite floats
and opaque/subclassed host objects. It follows shared containers once per
insertion and checks their effective depth at each reused path. The output
cannot refer back to itself: original bytes and held external values exist
before decoding, and neither contains a native output reference. Native
output headers, extents, tags, counts and reference IDs are checked separately.
External nesting is checked with the output container depth, so references
cannot conceal excessive depth.

## Bounds

Every byte arena retains the 8,388,608-node and depth-128 representation limits.
Newly materialized logical elements have a per-decode bound of 134,217,728.
Ordinary output containers, source-node decoding, source-array concatenation,
outer tuple materialization and external-array concatenation are charged.
An external reference to an already allocated JSON object does not charge all
of its existing children again. The pool retains complete output already
created by another owner, or raw input already admitted by an existing owner;
it does not bypass that owner's limits or semantic verification.

This accounting is deliberately not a whole-program aggregate quota. Multiple
calls can reuse a wide callee and have combined argument arrays approaching
the public source-node count times 512. Repeatedly charging held child arrays
would introduce an earlier refusal absent from the original program. Only the
new outer structure is allocated by concatenation. This does not authorize an
unbounded public language or make the private bridge a sandbox for arbitrary
machine code. Each semantic owner supplies its own source-bound capacity proof.

## Controls

Tests cover exact scalar kinds, Unicode and signed zero, malformed headers,
source offsets, opaque values, cycles, nested shared containers, effective
depth, tuple snapshot stability, mixed-list concatenation and retained child
identity. A reduced-quota control proves that complete held values are not
recharged while newly allocated arrays are still bounded. Independent HIA VM
execution checks the external writers' exact bytes against the representation.
Existing original-reference/concatenation tests, including 8,193 repeats of a
512-element array, continue to pass. Existing checked call/primitive source is
unchanged after adding the opt-in writers. These are representation controls;
whole-profile cold qualification belongs to the profile using the new source.
