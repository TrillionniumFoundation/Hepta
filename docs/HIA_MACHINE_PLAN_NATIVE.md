# Native HIA machine-plan validation and register witnesses

The selected owner in `examples/hia_bootstrap/machine_plan.hiaasm` implements
the finite block-layout v1 and machine-plan v2/v3/v4 admission rules and the
closed-block scalar register witness. It is connected to the ordinary public
`validate_plan` and `register_assignment_witness` entrypoints through the explicit
`HEPTA_HIA_MACHINE_PLAN_MANIFEST` selection. A selected failure never calls a
retained plan implementation.

This is one native responsibility in the retained product. It does not replace
the complete backend, the Python object ABI, or the ordinary Core verifier.

## Responsibilities

HIA owns the schema and exact field sets, Core identity comparison, complete
block/function permutations, scratch-register bijection, finite instruction
choices, alignment and scalar-select admission. It determines every normal
exact-string function/SSA membership decision, scalar/leaf eligibility,
definition and last-use position, inclusive interval collision, first-refusal
order and witness ordering. A dead definition still occupies its write point.
Block parameters and terminator uses retain their ordinary lifetime rules.
Collisions are checked before observing mappings for a later block.

Function and block permutations use merge sorting. A sorted SSA index and binary
search avoid input-dependent hash collision costs inside HIA. Register witnesses
are ordered by original block order and value spelling; interference is checked
by block, admitted register order, first position and value spelling. The v4
caller-clobbered registers retain the exact finite leaf opcode/signature gate.

The host bridge transports the already verified immutable Core, retains the
original bounded plain-JSON plan capture, and materializes HIA-selected results.
It does not compute liveness, classify opcodes, choose accepted schemas or call
either retained semantic owner. The source-order public witness hook is still
called with the detached plan. A context-local captured image keeps that hook
on the same selected owner even if caller code changes the environment.

## Foreign object observations

The standalone witness API accepts a Python truth-conversion object for its
leaf-register flag. Such a callback can mutate an otherwise exact input
dictionary. HIA therefore drives observation stages instead of assuming that
the first map read is a snapshot of all later reads:

1. Check every initial outer function name, then perform the first truth
   conversion.
2. For each observed mapping, check its complete exact-kind/register gate before
   looking up its function in the retained immutable Core object dictionary.
3. Observe fresh leaf-register membership and execute HIA leaf/SSA gates. HIA
   requests generic dictionary membership/lookup only when a foreign key needs
   Python hash/equality semantics. Exact Core identifiers use its own SSA index.
4. In block/value order, observe membership and both original dictionary reads
   separately. An opaque handle preserves the first observed register object;
   the second lookup supplies the native-selected register bucket. HIA checks
   each block's complete interference before advancing to the next block.
5. Observe callee-register membership, materialize HIA-selected intervals,
   insert the result under the original foreign function key, and only then
   perform the second truth conversion. The optional result update performs
   the original dictionary lookup again.

These callbacks are mechanical foreign object operations. They retain actual
`KeyError`, `TypeError`, user hash/equality/truth conversion and dictionary
mutation behavior at the original boundaries. The adapter does not replace a
native refusal with hosted validation. Private buffers are per invocation;
reentrant or concurrent calls share only immutable executable code.

## Custody and execution limits

The local manifest schema is `hepta.hia.machine-plan-native.v1`. It binds the
package-owned HIA source, immutable native image and compiler image digests.
Every selection rereads the manifest and current source, including a warm code
cache. The emitting backend's implementation hash additionally binds the new
bridge/transport code and selected source/image identity; it rechecks that
identity before publishing an artifact.

The native entry uses the existing three-buffer Linux x86-64 LP64 ABI. It has
private request/state words, bounded typed transport and checked output offsets.
The state buffer grows from actual captured plan/Core transport sizes. Four
merge arrays plus 64-byte rows consume 96 bytes per SSA definition, below the
reserved multiple of the actual immutable Core transport. Plan permutations
reserve 24 bytes per member. No smaller block, function, node or byte allowance
is silently imposed on the existing verified Core profile.

The adapter's Core custody precondition remains an already verified immutable
Core. Bounded JSON capture, foreign Python operations, source/manifest custody,
object materialization, static `code_options`/`preservation_checks`, machine
encoding, linking and publication still have retained host responsibilities.
The native image is locally selected trusted executable code, not a sandbox or
an all-input refinement proof.

## Build and qualification

`python -B -m tools.build_hia_machine_plan --compiler <image> --cold-report
<report> --output <new-directory>` uses the shared complete current-source cold
gate. The machine-plan source must be in that complete contract. An old compiler
with identical image bytes does not authorize changed source, and unqualified
input creates no artifact directory.

`tests.test_hia_machine_plan_native` checks independent ordinary Core VM
execution, source reproduction, exact retained-oracle custody, refusal priority,
foreign mutation order, immutable plan/owner capture, warm source admission and
backend identity. Native tests require an explicit
`HEPTA_HIA_MACHINE_PLAN_COLD_REPORT` or a distinctly named
`HEPTA_HIA_MACHINE_PLAN_DEVELOPMENT_MANIFEST`; the two cannot override each other.

`tools/qualify_hia_machine_plan_native_callers.py` runs the unchanged original
machine-plan, scalar-register, leaf-register and Agent machine-choice suites.
Both retained plan owners are forbidden. The report records loaded and executed
test IDs, every unittest anomaly, actual native entry counts, source/manifest
readbacks and native image identity. Cold qualification permits no exclusions.
Development observations are explicitly labelled and cannot qualify a release.

The original draft's foreign-flag counterexamples and an initial test-fixture
failure are preserved separately from corrected executions. Full product
replacement, default activation and retirement of retained implementations are
not implied by the selected component or its development tests.
