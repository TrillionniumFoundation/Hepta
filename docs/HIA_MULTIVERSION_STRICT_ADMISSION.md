# Captured strict multiversion admission

This component adds fresh raw admission for the multiversion runtime. It
executes the shared original JSON, structural budget, integer conversion and
historical nominal-v2 checks before the captured native normalizer. It then
freshly verifies the actual normalized Core, computes the three identities,
checks the existing scalar profile, and emits the existing sorted scalar ABI.

The old HIAMVNQ1 normalization profile and its source remain unchanged.
The new source supports both profiles; only HIAMVNQ2 takes the strict path.
This is a component qualification. Complete public typed program construction,
original dependency exception mapping, and the final release are separate gates.

## Fixed six-word interface

The export is hia_mv_prepare_admission. Its arguments are input pointer and
extent, output pointer and extent, and an exclusive workspace pointer and
extent. Workspace is at least 256 MiB. Output is at least 320 bytes; a complete
successful result can require two 8 MiB canonical spans plus its ABI and header.
An output of 16 MiB plus 16384 bytes covers the original bounded result.

The input consists of the following 128-byte header followed by the actual raw
program bytes. All unspecified words are zero.

| Offset | HIAMVNQ1 | HIAMVNQ2 |
| --- | --- | --- |
| 0 | HIAMVNQ1 | HIAMVNQ2 |
| 8 | Profile: 0 syntactically total, 1 proved-total profile | Same |
| 16 | Captured normalizer descriptor, at least 3 | Same |
| 24 | Nonzero absolute transport deadline | Zero |
| 32 | Zero or aligned actual cancellation word | Zero |
| 40 | Exact following raw extent, at most 8 MiB | Exact following raw extent |
| 48 | Zero | Captured integer conversion policy |
| 56–127 | Zero | Zero |

The integer policy is 0, or 640 through INT_MAX, and comes from the fixed
composition's captured configuration. It is the same policy used by the
whole typed verifier, checked freezer and shared raw leaf. It is not a public
request flag which can bypass validation. Values are checked at every relevant
component boundary. A new-profile input over 8 MiB returns the original byte
budget error before copying or decoding those bytes. The old profile still
rejects such a private frame.

The new profile requires strict UTF-8, as original verify_program does.
BOM, UTF-16 and UTF-32 byte input therefore receive the original format error.
Floating JSON numbers, duplicate keys, depth and node budgets retain the shared
original order. Only after complete syntax and structural preflight does the
captured integer policy run. Historical nominal-v2 with a decoded top-level
types key is then rejected with its original version-collision diagnostic,
including escaped schema and key spellings.

The captured normalizer's role 1 and diagnostic role 4 run under qualified
HIAMVPS2. Original public verification has no added wall-clock deadline.
Every child remains owned, every output is fully captured, and every child is
reaped before return. This does not change the per-proof validation timeout or
conditional publication's original prepare-budget check. The old profile
retains its original deadline, cancellation and refusal behavior.

## Reply and ownership

The existing 320-byte HIAMVNP1 reply, canonical spans and scalar ABI layout are
unchanged. Return code and reply status agree. A successful reply binds the raw
request, original canonical program, primitive canonical Core and actual ABI
hashes, and preserves the original sorted export metadata.

New shared-preflight failures have status 1 and no returned descriptors:

| Detail | Original exception |
| --- | --- |
| 201 | HIAProgramRejected: E_HIA_LIMIT: program exceeds byte budget |
| 202 | HIAProgramRejected: E_HIA_FORMAT: invalid/deep UTF-8 JSON |
| 203 | HIAProgramRejected: E_HIA_LIMIT: program exceeds structural budget before JSON allocation |
| 205 | HIAProgramRejected: E_HIA_VERSION_COLLISION: historical nominal v2 requires import_legacy_composite_v2; the primitive v2 namespace cannot infer a producer profile |

These are structured private details for the enclosing original-exception
adapter; the component does not pretend to have completed that adapter.
Other invalid-program diagnostics remain the actual sealed normalizer
diagnostic stream. The receiver closes each returned descriptor exactly once.
The ordinary profile rejection details remain unchanged. Private bad frames,
short header/workspace and invalid captured policy fail without output writes.

## Native construction and actual qualification

The new HIA packer consumes HIAMVNK2, a role count of 10, ten exact role extents,
and the ten actual flats. It emits the ordinary closed shared-object input for
the existing native linker. The fixed readable assembly bridge only dispatches
six-word calls, raw syscalls and the legacy aligned cancellation read. The
production packer contains its exact bytes and requires no assembler or linker
host process. Development assembly extraction is compared byte for byte.

The exact qualified shared image is 1602320 bytes, SHA-256
160d1879bf0c112c4182daa67154a0d76ec4bcb572b8b5d7fdb9593a907f54be.
The new admission policy is 105197 bytes / 7a701eb9a012915fa314bdee8fe0aafd52a92973bfc2206b08c6e955493b2177.
The shared raw policy is the qualified 105747-byte 8be1fcf009600914ef0dad9f76fe8be89668e5aebdaa0dfbe0f2641044c725cd.
The process policy is the qualified 179101-byte 4a99d033921f93314ac8c8c4519d019f10e1d2255c79034c0002b263eeb5368b.

Actual gates cover:

- 157 original-profile cases, including every existing scalar type and
  signature, actual built probe programs, byte limits, diagnostics, private
  guards, cancellation, deadline and payload capacity.
- 151 new-profile cases: 124 fresh original verify/profile comparisons plus
  27 private controls. These include exact byte limits, UTF encodings,
  structural budgets, decoded version collisions, and captured integer policies
  0, 640, 4300 and INT_MAX with 5000-digit inputs and mixed-error precedence.
- 48 native pack and actual lifetime controls. Forty check all ten role extents,
  malformed frames and short-output atomicity. Eight check real waiting,
  child reaping and descriptor custody. A test-only delayed native executable
  proves that the old deadline still expires while the new verification path
  waits and completes; it does not substitute for the actual normalizer in
  semantic qualification.

The machine record preserves complete reports, exact source provenance and
all component pins. Reused role source hashes are checked against the original
qualified source record before this qualification is frozen.
