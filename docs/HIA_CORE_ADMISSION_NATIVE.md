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

## Complete native diagnostics

Every primitive semantic refusal carries the original English text, including
function, block and value identifiers, instruction signature rules, and complete
callee return-type lists. HIA owns the text constants and constructs the UTF-8
message. The bridge validates the private trailer, decodes those bytes, and
raises the existing `HIAProgramRejected`; it never runs a Python checker to
reconstruct an error. The public `status(bytes) -> int` codes remain unchanged.

An edge's entire renamed capability graph is checked before comparing any
predecessor state. This preserves the original first-refusal order when one
resource disagrees with a prior predecessor and another lacks a required
owner or parent.

The message region reserves the raw input byte count plus its bounded node
count and 4,096 bytes. Every copied name or opcode is already present in the
input; a Python-style type list adds at most one space per node. The resulting
maximum private state is 65,450,176 bytes, below the existing standalone
64 MiB allocation. Input limits, compiler limits, CLI mappings, native child
limits and independent-VM limits are unchanged.

The adapter transports one invocation's message through an input-bound
`ContextVar` while keeping the existing public `status` observation boundary.
Its token is restored in `finally`; nested or concurrent admissions cannot
reuse another call's message. A status returned without the corresponding
native observation is refused. Tests cover overlap, re-entry, exceptions,
wrong-input observations, malformed trailers and invalid output UTF-8.

The selector is unselected only when its environment variable is absent. An explicitly present empty value is rejected before image loading or entry into the hosted reference. Remove the variable to use the unselected reference path; an empty assignment does not disable selection.

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
