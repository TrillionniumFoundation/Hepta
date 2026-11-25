# Native NDU evaluator leaf

## Frozen component

The native leaf implements the pinned NDU evaluation algorithm in HIA. The
one-shot Linux x86_64 executable is 685,362 bytes and has SHA-256
7dbe3f18f329be0124ba1af55bad4358654262e1b0503a7745b56b9f3b76057e.

This checkpoint covers the evaluator leaf, its JSON diagnostics, framed
transport, and native construction. The rank caller, fresh translation proofs,
background lifecycle, final repository aggregation, and production MCP
registration have separate gates. This document does not mark those gates
complete and does not activate a service.

The reference is the original Rust bridge at upstream commit
d3c2d760eca5065fc966820379c35c6e8d56e855. Its fresh, locked build has SHA-256
e72c74f3e226ff9412ee8143077d4d0b93292e0645c4b0c5e2c50ddd2f3aabf2.
The reference is used for independent qualification and is not a runtime
dependency of the native leaf.

## Observable contract

Input retains schema hepta.hia.ndu-request.v1. Object and positional-struct
array forms, original field/error precedence, exact signed Q32.32 values,
u64 generation, original stable IDs, support digests, hard/resource rejection,
Pareto ties, explicit abstention, and advisory-only authority are preserved.

The native success identity is explicit:

| Field | Native value |
| --- | --- |
| schema | hepta.hia.ndu-native-response.v1 |
| entry_point | hepta.hia.ndu_evaluator.v1 |
| reference_entry_point | codex_hepta_ndu::evaluate_candidates_with_policy |
| upstream_commit | d3c2d760eca5065fc966820379c35c6e8d56e855 |

The request, evaluation-v2, evaluation-policy, and utility-profile SHA-256
values match the original algorithm. No digest is replaced with a digest of
a native convenience serialization. Success JSON is sorted and compact with
the original trailing newline. Errors retain the original one-shot or stream
error schema. No response grants program-safety proof or global optimality.

The standalone entry has no arguments for one-shot evaluation. Framed mode
uses exactly --stream-v1 SESSION_HEX MAX_REQUESTS. The session is 64 lowercase
hexadecimal bytes and the allowance is 1 through 256. Each response is freshly
evaluated. The native hello uses schema
hepta.hia.ndu-native-stream-hello.v1 and the same native/reference entry fields
above. Session accounting charges actual native input and output frame bytes,
including the explicitly longer native identity.

## Distinct capacities

| Boundary | Limit |
| --- | ---: |
| Standalone request / framed JSON input | 1 MiB |
| Standalone pure output view | 8 MiB |
| Standalone evaluator workspace | 24 MiB |
| Framed response JSON | 1 MiB |
| Framed session, actual combined input/output wire bytes | 8 MiB |
| Framed request count | 256 |
| Rank caller executable read | 128 MiB |
| Rank caller build-receipt read | 4 MiB |
| Rank caller stdout | 1 MiB |
| Rank caller stderr | 1 MiB |
| Rank pump overflow detection | 1 MiB + 1 byte per stream |

The 8 MiB standalone output view is necessary for the original error domain.
An exact 1 MiB request with a wrongly typed DEL-filled string produced
7,339,189 bytes of stderr, identical to the original Rust executable. It does
not increase the rank caller's independent 1 MiB stdout/stderr limits.

## Native construction

HIA_NATIVE_NDU_EVALUATOR_RECIPE.json specifies the source and wire recipe.
Compile transport, evaluator, number, debug, and packer HIA sources with the
qualified hia-source-build compile entry. Its compiler image is
813,129 bytes / 494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af.

Wrap the packer flat with the existing HIA filter packer:

- HIAFLT01 followed by one little-endian u64 flat length, then the packer flat.
- Run the resulting hia-ndu-evaluator-pack native ELF.
- Its input is HIANDP01, four little-endian u64 lengths at offsets 8, 16, 24,
  and 32, a zero u64 at 40, then transport/evaluator/number/debug flats in
  that order.
- Each flat is between 16 bytes and 1 MiB. Input is at most 4,194,352 bytes.
  The output capacity is 8 MiB.

Two actual source-to-image constructions, each consisting of seven native
execs, produced the exact qualified image. Traces contain no Python, Rust,
assembler, or host-linker child. Python QA launches and byte-compares these
native steps; it supplies no evaluator, parser, numerical, or linking behavior.

The checked-in HIA packer emits the complete ELF. The readable assembly files
only implement fixed Linux syscall and six-word view translation. They contain
no NDU ranking, number formatting, Unicode classification, JSON, or digest
policy. The development authors may use as/objcopy to regenerate their
mechanical literals; the runtime recipe executes checked-in HIA without them.

HIA_NATIVE_NDU_EVALUATOR_BUILD.json is the frozen build receipt template.
Publishing that template is authorized by the recipe only after actual source
hash checks and actual output hash equality. It is not evidence for a different
source tree or an arbitrary executable. The receipt contains an eleven-file
relative source closure, module pins, compiler identity, recipe and independent
qualification pins, and a canonical build-inputs digest. It makes no claim to
have executed Rust or to have preserved fictitious Rust build flags.

## Pure ABI

The evaluator uses the existing six-u64 borrowed-view ABI:

    (input_pointer, input_length,
     output_pointer, output_capacity,
     workspace_pointer, workspace_capacity) -> u32

The input limit is 1 MiB; the standalone transport reads at most one extra byte
to distinguish oversize input. Output capacity is at least 8 MiB; workspace is
at least 24 MiB. A normal return gives the output byte count. Bit 31 indicates
an error payload. Private continuation returns 0xfffffff8 and 0xfffffff7 select
the number and Unicode-debug HIA roles through the fixed mechanical join;
these values are not exposed as standalone response bytes.

The number role reconstructs the original default serde_json conversion,
including binary64 rounding, underflow, overflow positions, and shortest zmij
formatting, using HIA integer operations. The Unicode debug role uses an
explicit static property table. Every valid Unicode scalar was independently
compared with the pinned Rust formatting behavior; this is a language-property
table, not cached request or evaluation output.

The transport policy uses a 128-byte action view and a 48 MiB private
workspace. It owns argument checking, request/response extent validation,
partial reads and writes, frame sequence/session matching, cumulative byte
accounting, error truncation, and process exit decisions. The assembly adapter
executes only the requested syscall or fixed evaluator callback.

## Qualification

The exact reports, file pins, and original oracle source/build provenance are
in HIA_NATIVE_NDU_EVALUATOR_QUALIFICATION.json:

| Actual gate | Result |
| --- | ---: |
| Complete original request-domain differential | 167 / 167 |
| Raw JSON, invalid UTF-8, escapes, types, duplicate and positional fields | 2,970 / 2,970 |
| Default-serde number bits, formatting and range/error positions | 3,689 / 3,689 |
| Every valid Unicode scalar, complete output bytes | 1,112,064 / 1,112,064 |
| Standalone arguments and framed protocol | 65 / 65 |
| Maximum request/error, fragmented pipes, fresh 256 requests, session boundary | 66 / 66 |
| Native packer positive/negative cases | 26 / 26 |
| Packer direct ABI capacities, input/output canaries, workspace preservation | 24 / 24 |
| Full native source rebuild | 2 identical images |

Earlier failed tests remain saved. In particular, the first session-boundary
fixture incorrectly obtained request digests from unpadded input. The corrected
fixture asks the original Rust oracle to evaluate each exact padded request;
it does not replace or relax the boundary assertion.

Qualification covers the specified Linux stdio protocol and its admitted
request/error domains. Kernel startup, invalid-UTF8 process argv panics, and
Rust-specific panic/backtrace text are not asserted to be an identical language
runtime. The production rank caller independently bounds, owns and rejects
unsuccessful evaluator processes.
