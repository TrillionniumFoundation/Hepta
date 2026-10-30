# Returned byte calls compose with local Views in the existing v8 route

## Frozen source and exact scope

The final local candidate is `0d077885cc4be0b8ee96a012d7d6d2e51d1d2ace`, tree
`88478a74708cf63edf7f9304c0b4ceb820b04d01`, following local candidate
`31736998decf7fe952617fd219130ee3a5048a9e`. Its public source base is
`b121c9b4a57a8a58e53360d1d67387d953348f57`. That base includes the two independent
CI fixture corrections; their source and earlier observations are not relabeled
as part of this implementation. Source publication and a later public-head
execution, when available, require separate mappings and observations.

Production changes are confined to `hepta/hia_program_source.py`. The other
nine paths contain the example, nine regression methods, existing safety and
critical/workflow registrations, and documentation. There is no new language
schema, source option, route, checker, evaluator, Machine or native backend.
Python remains the production admission authority and optimization remains
`no_change`.

## Actual rejected composition and implementation

The unchanged source checker requires an explicit outer borrow in a stored
reference field: `View {data: read shared(read data), tag: 7}`. Four such source
programs passed source checking and the existing ResourceIR verification on
pristine public `e0b9012a249167b5bc5b0f3bd243899344621080`. Its HIA source adapter
then rejected all four at `borrow and assignment places must be local records
or fields`. The actual source, ResourceIR documents and errors are retained in
`explicit-e0-preconditions/`. This establishes a concrete boundary between
already legal source/resource semantics and the old executable-source adapter.

The initial four probes omitted that outer `read` or `mut`, following a
historical negative fixture. Those programs failed source checking with
`E_BORROW_MODE`; they were not legal counterexamples to the HIA adapter. Their
original results remain in `pristine-e0-preconditions/`. The corrected probes
have separate source hashes and observations. The initial syntax error was
not repaired by weakening the source checker.

The existing explicit `core_schema=hepta.hia.program.v8` route now accepts a
stored call result with these limits:

- Each local View record has one `[u8]` reference field and up to four scalar
  labels, admitted by the existing source checker and ResourceIR rules.
- The called helper returns a borrowed `[u8]` slice and has exactly one borrowed
  byte-slice or byte-buffer formal. Formal, result and stored field have the
  same `read` or `mut` permission. Other formals are ordinary scalar values.
- The actual origin is a direct named byte owner, borrowed parameter or field
  of an available ordinary owner record. A nested returned-call argument,
  local-View origin, aggregate borrowed formal or permission conversion is
  outside this increment.
- View parameters, View returns, nested View records, multiple stored loans,
  named lifetime escape, and a standalone stored returned slice remain refused.
  Default v1 still refuses the new returned-call construction. Readless or
  mutless stored fields remain source-checker errors.

The adapter selects its existing v8 `call()` implementation. That implementation
already produces the argument parent loan and returned child loan. The new
work preserves the parent value through View construction, local binding,
shared Copy and exclusive move. `_State.prune` retains the transitive
`borrow_parents` dependencies, so the existing block builder includes the
hidden capability in ordinary CFG interfaces. Edges also require the same
producer parent binding. This is producer bookkeeping; the primitive Core
verifier independently checks the emitted capabilities and edges.

Shared copies alias the same obligation. An inner copy cannot end a parent or
child still held by an outer copy. The final lexical alias ends the child
before its argument parent. Exclusive View moves invalidate the old binding,
and explicit `drop(move view)` releases both capabilities in that order.
Exclusive scope exit and early return do not invent a destructor. The example
contains both valid early-return and normal-return paths that explicitly drop
the exclusive View before the caller accesses and drops the owner.

## Actual frozen qualification

`final0d-focused9/` is the mandatory new nine-method execution on the final clean
candidate. Every selected ID starts, succeeds and stops exactly once; there
are no failures, errors, skips, expected failures or unexpected successes.

| Observation | Actual retained scope |
| --- | --- |
| New methods | 9: five source/Core semantics methods, two Rust Machine methods, two LLVM methods |
| Source refusal controls | 18 actual rejected source programs |
| Primitive refusal controls | Five corruptions of actual emitted Core, refused by Python and by five separate raw Rust invocations |
| Rust/Python differential | 86 actual Rust invocations, each compared with Python values/status/steps and complete resource ledger |
| Direct LLVM | 33 actual calls through five source-selected scalar exports |
| Native allocator | Two actual observer processes: normal allocation and injected second-allocation failure |
| Source identity | 1,457 materialized tracked files bound to their raw Git blobs and modes before/after, within the 7,699-file Git tree |

The 86 Rust observations are a finite repeated corpus, not 86 distinct
programs or independent tasks: 33 normal requests, two injected allocation
failures, two heap policies, one completed mutable-loop observation, and all
47 step limits for that loop, plus one accepted balanced shared-parent reborrow
neighbour. Stopped ledgers preserve live owners and loans;
they do not claim automatic cleanup after a budget stop.

The LLVM allocator observer calls `failure_case(7)`. Its normal result is `50`,
with two allocation attempts, two allocations/frees, no live bytes and peak
requested payload 10 bytes. Injecting failure at attempt two returns `41`,
with one allocation/free, no live bytes and peak requested payload 3 bytes.
This is one actual failure index and one normal control, not general allocator
fault coverage. Native loan events are not exposed as a separate ledger;
full loan-ledger equality is measured between the Python and Rust Machines.
Neither requested payload nor this observer is RSS or allocator-overhead proof.

The retained shared object and object bytes match the original compilation
receipts. The observer source, executable, link command and actual process
stdout/stderr are retained. `bounded-compiler-processes.json` additionally
retains six original bounded Clang invocations, with actual argv, time,
stdout/stderr, and the two temporary LLVM inputs and outputs copied during
their original invocations. The external collector observes the unchanged
bounded runner, preserves its arguments/results/exceptions, and adds no
compiler executions. Backend compilation receipts retain their honest
`native_compiled_not_executed` status; the separate call/process rows establish
actual execution. The earlier 317 run used the uninstrumented backend API and
retained IR hashes/flags/artifact receipts rather than its temporary LLVM
files or bounded compiler stdout/stderr. Its later deterministic matching IR
in `matching-core-llvm-inputs/` is labeled as reconstruction without additional
compilation or execution; it is not substituted for the final original inputs.

`final0d-legacy87/` is the final required existing-source and registration
regression run: 87/87 pass, with no nonordinary outcome. It covers general
source lowering, direct local Views, partial field restoration, unit enums,
public exports, existing returned-loan field origins, the shared route, safety
protocol, and integrated workflow. This is a selected regression gate, not a
full-project or full-349-method execution. Its 1,457 materialized files include
three additional original protocol JSON files needed by registry imports.

The earlier `frozen317-legacy87/` attempt retains its 84 successes and three
missing-protocol import errors. `sparse-protocol-materialization.json` records
restoration of those three files from the same frozen Git commit, with exact
blob IDs, bytes, SHA256 and modes. No source implementation changed, and the
317 nine-method run was not repeated for this environment correction.
`frozen317-legacy87-complete/` retains the successful 87-method rerun on that
earlier candidate. Final 0d nine- and 87-method results are fresh observations.

## Negative-control correction before publication

The original 317 nine-method suite passed as written, but reviewing its raw
refusal messages exposed an imprecise causal assertion: its shared-parent
reborrow fixture introduced an additional child without ending it. Both
implementations refused the missing CFG loan transfer, which did not show
that a shared reborrow itself was forbidden.

`317-reborrow-control-audit/` retains three subsequent actual Rust invocations
and Python/source/ResourceIR controls. The original unended shared child
refuses at the CFG boundary. A balanced shared reborrow is accepted and
actually returns 8 with three loans started/ended. A reborrow of an exclusive
parent while its mutable child remains live is refused even when the proposed
new child has a matching end: Python reports `E_HIA_LOAN: conflicting live
borrow`; Rust reports `E_HIA_LOAN: overlapping incompatible loans`.

The final candidate corrects that fixture and checks those specific conflict
reasons; it also retains the balanced shared positive neighbour. The only
production-file change from 317 is neutralizing one comment about a parent
capability. Its production AST is identical while its raw source-file bytes
differ. Documentation likewise limits frozen-parent language to exclusive
parents. `317-negative-control-correction/` retains the exact comparison and
the superseded metadata drafts. Original observations are not rewritten, and
neither a source implementation defect nor a backend defect is inferred from
this test-quality correction.

## Machine and tool identities

The new source normalizes to the existing primitive v8 and uses the retained
Rust executable from the earlier public `e0b9012` build:

`core-rust-public-validation/field-origins-native/rust/hia-core-shadow`

It is 4,204,464 bytes, SHA256
`090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`.
Original build/process provenance is retained separately in
`core-rust-public-validation/rust-crate/process.json` and its earlier
field-origin observation record. This task did not rebuild the unchanged Rust
crate. New final Core inputs and executions are bound to candidate 0d077885, while
the reused executable keeps its original build lineage. Reuse does not confer
Rust production authority.

Clang is the restored Ubuntu LLVM 20.1.2 executable, SHA256
`b15e7640bf3082f36ef14321711706b265df3058721e3c2caef3a4b83895d07d`.
The actual host is Linux x86-64 with the current Debian host runtime, not the
older Ubuntu host. Native evidence is limited to that scalar C ABI target.
No physical-device, threaded-callback, foreign-lifetime or cross-target
qualification is inherited from it.

## Registration, reproduction and remaining obligations

`final-safety-union-receipt.json` proves that every original 340 selector remains
exactly once, all original guarantees and other 35 capabilities are unchanged,
and nine methods were added to the existing `source_lowering` capability.
The 349-selector union still has 36 capabilities. The canonical reviewed
contract hash is
`7da611f24e957ab113d987bbfb1d812db3234ca1be27cc61a8e743d0c89e4f99`.
The eight universal claims remain false. Registration and successful dynamic
resolution of 349 methods are distinct from executing all 349.

With actual Cargo/Rust and Clang available, the new corpus is reproducible via:

```sh
python -m unittest -v tests.test_hia_source_returned_local_views
python -m hepta hia lower examples/hia_program/source_returned_local_views.hepta \
  --core-schema hepta.hia.program.v8 --module source_returned_local_views -o core.json
python -m hepta hia run core.json --function shared_case --arguments '[3,19,0]'
```

The last command should return 57. The test harness may reuse an explicitly
selected Rust executable only when `HIA_RETURNED_VIEW_RUST_BIN` and
`HIA_RETURNED_VIEW_RUST_SHA256` agree. This is a test harness option, not a
production source or admission flag. `collect_returned_views.py` and
`run_frozen_validation.py` retain the exact focused invocation, original raw
test outcomes and scoped source/tool identities; their actual used bytes are
archived beside each process receipt.

The four legal preconditions, dirty-e0 development results, each frozen candidate
results, and any later public or peer observations retain their own identities.
The development corpus had 31 normal native calls and 83 Rust observations;
the two additional exclusive-return cases account for 317's 33 and 85 counts.
The balanced shared positive neighbour adds one Rust/Python comparison to the
final 86 count without adding an LLVM invocation. Byte-matching reconstruction of the subsequently edited
development fixture/test files is explicitly labeled and checked against its
original before/after hashes; no observations were reconstructed.

This closes one finite source-to-existing-v8 composition gap. It does not close
P0's complete historical-route unification, P1's general memory/provenance,
recursive ADTs, arbitrary partial initialization, escaping lifetimes or
asynchronous cleanup, P2's production-authority switch, or any broad P3–P7
criterion. The original 27 strict blocker criteria are untouched.

## Independent review

The frozen independent review in `peer/` reports PASS for this finite slice,
with no blocking implementation defect. Its original positive controls run on
317: three independently authored source families with two flags each, giving
six Python executions, six raw Rust processes and six LLVM calls from one
compiled module. They cover a nonfirst borrowed formal, two independent
returned shared Views of one owner, and an outer Copy retained while an inner
copy changes a label across a loop. Two additional checked/ResourceIR-admitted
source negatives establish the extra nominal-value-formal and permission-change
boundaries. Those executions are not relabeled as 0d or a future public head.

The peer then independently checked the three-file 317-to-0d delta, identical
production AST versus changed comment bytes, the owner's original/final
observations, exact selector union, and the corrected shared/exclusive control
premises. Its initial low-level LLVM API misuse occurred before compilation;
completion reused the six original Rust outcomes and ran only the outstanding
LLVM phase. Read-only postprocessing mistakes and their original traces are
also retained, with no source/native-defect inference. The peer archive is
4,014,666 bytes, SHA256
`369485771f6a211a599fb76422764545c582745d59382f952f6a18e713f20542`;
all 67 members and gzip CRC passed its original readback. The main package
retains all owner originals referenced by the peer's input manifest.
