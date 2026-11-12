# Explicit whole primitive Core admission candidate

`core_admission.hepta` admits a complete raw primitive Core JSON document,
schemas v1–v8. It embeds declaration, SSA, CFG and public-export checks, then
checks every function body: all 50 opcode contracts, exact scalar literals,
callee signatures/effects, owner consumption, borrow permissions and parent
suspension, edge graph renaming, branch/loop predecessor agreement, and returned
loans bound to original function formals. No reduced compiler profile is used:
the existing 8 MiB / 262,144 nodes / depth 64 / 1,024 functions / 4,096 blocks
per function remain the admission ceilings.

The generator produces ordinary HIA, compiled by the native compiler. Python
authoring is not runtime policy execution and is still a build dependency.

`HEPTA_HIA_CORE_ADMISSION_MANIFEST` selects an immutable source/image-bound
candidate. Selected refusal, missing images or source drift never invoke the
old declarations or body checker. The hosted default is unchanged. The
incremental API uses whole native admission when selected; it reports that all
bodies were checked instead of claiming that host-cached bodies were reused.

The strict `tools.build_hia_core_admission` requires the completed cold report
to match the current complete source manifest and compiler generation hashes.
An older compiler used in development is not exact-source qualification.

The selector is unselected only when its environment variable is absent. An explicitly present empty value is rejected before image loading or entry into the hosted reference. Remove the variable to use the unselected reference path; an empty assignment does not disable selection.

## Current private ABI and complete primitive policy diagnostics

The manifest schema is `hepta.hia.core-admission-native.v4`. The original
three-buffer entry and complete state allocation plus 576-byte tail remain
unchanged. The two existing value families keep their private version-1
512-byte payload. The body-policy family 16 and declaration family 17 use private version 2 and a
complete UTF-8 payload in the original state prefix, only after every policy
frame has returned. The shared constant pool and payload do not overlap the
retained tail or separate decoded arena.

HIA selects each message at the original refusal edge. It publishes complete
opcode/contract, callee, owner/loan, return, CFG and effect messages, including
arbitrarily long admitted opcode strings and full callee return-type lists.
The adapter only validates and reads the already-published header and payload.
All original source, JSON, arity, node, block, image and memory limits remain.

All 66 declaration message programs preserve the original complete messages
and first-refusal order, including invalid names without truncating their input
domain and admitted duplicate-name insertion. JSON diagnostic presentation,
composite elaboration, legacy nominal-v2 namespace handling, exact Python
snapshots and VerifiedProgram custody retain their existing boundaries. This component does not claim
complete `verify_program` equivalence. The precise two frame variants, safe
state-reuse point, capacity proof and unchanged ordinary Agent envelope
are specified in
[HIA_CORE_ADMISSION_DIAGNOSTICS.md](HIA_CORE_ADMISSION_DIAGNOSTICS.md).

## Remaining boundaries and claims

Host strict decoding, bounded caller snapshots, canonical JSON transport,
composite normalization, `VerifiedProgram` custody, incremental cache metadata,
scratch allocation and executable loading remain dependencies. Runtime, code
generation, linking, Agent persistence, build/install and applicable-platform
acceptance are separate whole-product requirements. This candidate is not a
formal all-input refinement proof, sandbox, default migration or native-only
release. No legacy production implementation is retired by this change.

Independent ordinary-Core VM witnesses run before native compilation. Raw
native witnesses and differential checks cover malformed input, ownership,
loans, full declaration profiles and selected no-fallback behavior. The actual
Core/composite suites must additionally pass with old declaration/body policy
calls forbidden, followed by matching-source cold and whole-repository gates.

## Accepted-path interface still to transfer

The public `verify_program` path still runs `_decode`, including bounded exact
Python snapshots, strict JSON admission and canonical transport, before the
selected Core image. Composite elaboration and the nominal-v2 namespace guard
also precede selection. On success the current selector mechanically creates
function/block maps; `verify_program` does not use those maps and constructs
`VerifiedProgram(raw)`. That redundant materialization can be removed in a
later isolated change, but doing so does not transfer the preceding decode
owner. The present receipt contains status, diagnostic family and native
message bytes, not canonical/structured bytes, a digest, foreign signatures
or an execution plan. A direct bytes-to-canonical-to-Core chain and its
complete error/order/custody contract remain separate work.
