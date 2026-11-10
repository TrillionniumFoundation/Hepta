# HIA canonical JSON wire candidate

**Whole-stack rewrite remains OPEN.** The 22-function HIA library in
`examples/hia_bootstrap/json_canonical.hiaasm` decodes bounded JSON wire into
its own arena, sorts object children with iterative linked-list merge sort,
and writes canonical UTF-8 JSON. Native payload execution does not call a host
JSON parser or encoder. The authoring generator, loader, allocator, foreign
Python-object bridge, semantic Core verifier and production runtime remain
Python. No backend is selected by default and no production service is changed.

## Profile and behavior

- Source is at most 8 MiB; value-node budget is 1..1,048,576 and root-at-zero
  depth budget is 0..128. Keys are not counted as value nodes. Empty containers
  at the depth boundary retain the existing input semantics.
- Accepted values are null, booleans, signed decimal integers, Unicode strings,
  arrays and objects. Fractional/exponent numbers, malformed UTF-8, isolated
  surrogates and duplicate decoded keys are rejected.
- Keys sort by Unicode scalar value (equivalently lexicographic UTF-8 for
  well-formed scalars). Strings use literal UTF-8 with JSON quote, backslash and
  control escaping, matching the existing `ensure_ascii=False` canonical wire.
  Whitespace is removed; integer lexemes are preserved except `-0` becomes `0`.
- Integer processing in this wire library is lexical. A 10,000-digit integer
  can be canonicalized without constructing a host big integer. APIs that
  materialize Python integers still apply their existing host conversion limit;
  this is not blanket equivalence with unrestricted Python `json.loads`.

The public entry uses immutable input and disjoint private output/workspace
buffers. It reuses the native value arena but never exports foreign pointers.
Canonical output cannot exceed accepted input length: key order preserves size,
whitespace and escape normalization only shrink it, and `-0` shrinks to `0`.
Scratch has the arena's independently bounded node and string/key capacity.
Return codes are `ffffffff` syntax/Unicode, `fffffffe` node/depth budget,
`fffffffd` scratch/profile and `fffffffc` duplicate decoded key; otherwise the
return value is the canonical byte count. Compiler limits and deadlines remain
unchanged. Finite differential tests are not a worst-case runtime-cost proof.

## Explicit build and integration

```sh
python -B -m tools.build_hia_json_canonical \
  --compiler /path/to/B3.image.bin \
  --cold-report /path/to/completed-cold.json \
  --output /new/private/canonical-directory
```

The build requires a completed, matching source-only cold compiler receipt.
Its local manifest binds source, compiler and native image SHA-256. Set
`HEPTA_HIA_JSON_CANONICAL_MANIFEST` to this manifest to select wire
canonicalization in the existing Core input path. Selecting the separate
`HEPTA_HIA_JSON_DECODE_MANIFEST` as well moves input decoding and internal
detached snapshots/`VerifiedProgram.as_dict()` to the HIA value decoder.
Structural and semantic checks are still performed by the existing verifier.
Caller-owned dictionaries retain the existing bounded snapshot and host object
serialization. Structured elaboration and other report serializers are not
rewritten by this route. Outside-profile fallback is not native qualification.

The manifest selects trusted local executable code, not a sandbox or a
payload-controlled backend. A selected invalid artifact fails closed. All
three JSON candidates share a loader which rejects duplicate manifest fields
and rechecks source identity even after a warm cache; cached executable mappings
remain immutable. These checks do not establish full compiler refinement,
cross-platform support, clean-machine installation or whole-stack closure.
