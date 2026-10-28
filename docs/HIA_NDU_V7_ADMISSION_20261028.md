# NDU primitive v7 admission

The NDU candidate adapter admits primitive v7 for the existing `byte-swap.v1`
and `checked-unsigned-reduction.v1` contracts. `full-view-fill-loop.v1` still
admits only v1–v6. This closes the adapter's version gap for the two already
supported public rules; it does not extend the matchers or introduce a chain
optimization.

## Identity and semantic boundaries

`make_plan` and `prepare_candidate` enforce the selected rule's explicit version
profile. Every baseline, reproduced result and supplied candidate is parsed and
fully reverified. A manually constructed `VerifiedProgram` is not authority.
The check covers every function, including functions other than the selected
scalar entry. Composite inputs are refused even if elaboration would produce
the exact candidate bytes. A caller can explicitly elaborate a separate
primitive input, but that does not transfer the original composite's identity
or prove its elaborator.

`observe_semantics` also reverifies the complete candidate object before
extracting canonical bytes from the public `PreparedCandidate` dataclass.
Matching canonical Core digests do not establish the original input profile:
a valid composite identity and inconsistent forged structured metadata are
both refused, even when the candidate's executable bytes are unchanged.

The plan wire schema remains `hepta.hia.ndu-plan.v1`: `baseline_sha256` already
includes the Core schema bytes. The exact registered rewrite determines the
candidate bytes. Validation, native artifact and NDU evidence digests retain
their existing bindings. Cross-version plans and candidates cannot be replayed,
and the qualifier refuses a native artifact receipt bound to another Core
before it invokes NDU.

V7 input remains v7. Earlier, necessary upgrades still work: byte-swap changes
v1–v3 to v4 when matched, and fill-loop changes v1 to v2. Declining to admit v7
fill is separate from those valid upgrades.

## Finite controls

`tests/test_hia_ndu_v7.py` contains thirteen test methods. Its authored control
program allocates a buffer and chain node, obtains a head read loan, passes that
loan through the internal checked-reduction loop, reads the payload and drops
the resources. The external ABI is `(usize, usize, usize, usize) -> u8`; a
separate exact `(u32, u32, u32, u32) -> u32` wrapper supports bounded native
correctness observation. It is a compiler control, not an upstream application
or a performance workload.

Three positive and five negative inputs produce sixteen baseline/candidate VM
observation pairs under normal execution and first-allocation refusal. They
compare returned values, trap codes and complete resource ledgers; successful
normal rows create/drop one node, perform two allocations/frees and balance
both loans. Two additional pairs inject refusal at the node allocation and
check that its head-bounds trap still precedes an arithmetic overflow. These
are finite, overlapping observations, not eighteen independent test methods.

Other controls preserve v7 swap/reduction identity and old valid upgrades,
refuse v7 fill, reject equivalent-but-composite candidate exchange and semantic
observation, reject forged structured metadata before observation, recheck an
invalid unused chain function and forged receipt, reject dropping a chain with
an active loan, enforce scalar public entry, and refuse extra candidate resource
events. A valid loop with extra chain events stays unchanged. Replayed v6
artifact identities are rejected with synthetic measurement records before any
evaluator invocation; those negative records are not measured performance.

Run the finite admission/resource controls from the repository root:

```sh
python3 -m unittest -v tests.test_hia_ndu_v7
```

No timing instrument or performance experiment is invoked by that module.
Actual native and pinned-NDU controls, when separately run and retained, must
identify their source, artifacts, finite inputs and evidence bindings. A policy
control using an explicitly infeasible candidate can exercise real NDU abstain
without claiming that its cost inputs were measured or that a candidate gained
performance.

## Remaining limits

The independent Lean arithmetic model remains separate from the matcher, Core
resource verifier and LLVM backend. This adapter change adds no formal theorem.
Instruction-budget equivalence, host interruption and host allocation-failure
equivalence retain each registered rule's existing exclusions. Language-level
allocation refusal and resource event order are still observable and checked.

The native/interpreter version dispatchers, static heap bounds and instruction
budget analyzers retain their own version profiles. Admitting a v7 candidate
does not admit it to those consumers. No general recursive data type, external
state migration, new optimizer, whole-language safety, global optimum or
industrial gain is established here. Historical NDU timing attempts remain
bound to their original source and are not rerun by this extension.
