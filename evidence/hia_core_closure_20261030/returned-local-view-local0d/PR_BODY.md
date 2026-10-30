## Why

The source checker and existing ResourceIR already accept a local byte View
whose stored field explicitly borrows a returned-call result, such as
`View {data: read shared(read data), tag: 7}`. The executable-source adapter
rejected these checked programs because its borrow-place path accepted only
named locals and fields. Simply removing the stored-loan guard would lose the
hidden argument parent when local temporaries are pruned or passed through CFG
edges, leaving copy/move/scope cleanup obligations incomplete.

## Change and behavior

The existing explicit primitive-v8 source route now selects its existing
returned-loan call implementation for this finite constructor form. A helper
has one direct byte borrowed formal, matching read/mut permissions, a borrowed
byte-slice return and otherwise scalar value arguments. The lowerer retains
the hidden parent through local binding, shared copies, exclusive moves and
CFG interfaces; the final lexical alias or explicit exclusive drop ends child
before parent. Edge validation preserves parent bindings. The unchanged source
checker, ResourceIR and primitive verifier each remain in the admission path.

Default v1, missing outer read/mut, nested returned-call/View origins, multiple
borrowed formals, aggregate borrowed origins, permission changes, View
parameters/returns and escaping stored lifetimes remain rejected. There is no
new source flag, Core schema, route, Machine or backend. Public exports remain
the source-selected scalar wrappers.

The existing source_lowering safety capability retains all original 340
selectors and guarantees, adds nine methods, and updates its reviewed hash.
The resulting union is 349 selectors in the same 36 capabilities; registration
is not a claim that all 349 executed on this candidate.

## Validation

Final local frozen commit: `0d077885cc4be0b8ee96a012d7d6d2e51d1d2ace`.
Tree: `88478a74708cf63edf7f9304c0b4ceb820b04d01`.
Public source base: `b121c9b4a57a8a58e53360d1d67387d953348f57`, including the
two previously reviewed CI-fixture fixes. Local 317 remains a separate earlier
observation; final 0d includes a precise negative-control correction.

- Four actual pristine-e0 legal source/ResourceIR preconditions rejected by the
  old HIA adapter are retained. Initial readless source-checker errors remain
  separate from those legal controls.
- New nine-method gate: 9/9, zero nonordinary outcomes; 86 actual Rust/Python
  complete-ledger comparisons, 18 source refusals, five emitted-Core corruptions
  refused by both Python and five raw Rust invocations, 33 actual direct LLVM
  scalar calls, and two allocator-observer executions.
- Reviewing the original 317 negative fixture showed that an unended shared
  reborrow was refused for missing CFG cleanup, not exclusivity. A separate
  three-process control confirmed a balanced shared reborrow is legal and a
  balanced reborrow of an exclusive parent with a live mutable child is not.
  Final tests retain the accepted neighbour and assert the specific actual
  exclusivity errors. Production AST is unchanged from 317; a corrected
  comment changes source bytes. No original observations are relabeled.
- Existing source/route/registration regression gate: 87/87, zero nonordinary
  outcomes. Its earlier 84-pass/3-missing-protocol sparse-checkout attempt and
  exact-Git protocol materialization are retained; no source fix was needed.
- Source and selected tools are unchanged before/after. The unchanged Rust
  Machine is reused by exact hash with its original public-e0 build lineage;
  this is not a new Rust crate build or authority qualification.
- Original final bounded compiler commands/stdout/stderr/times and temporary
  LLVM inputs/outputs are retained; actual native calls remain separate from
  honest compile-only backend receipts.
- All ten changed UTF-8 files and modes are exported. Applying the full-index
  patch to the public parent reconstructs the exact candidate tree.

Independent review reports PASS, with six original Rust and six LLVM controls
on 317 plus read-only review of the final 0d delta and actual 0d owner results.
Those peer executions retain their original 317 identity. A later public-head
execution must retain its own source identity and outcomes.

## Limits

Native observations are finite Linux x86-64 scalar C calls. The allocator
observer measures requested payload, not process RSS. VM stops retain actual
live ledgers; native trap unwinding, async cancellation, arbitrary stored
lifetimes, general provenance and full-language/backend refinement remain
unproved. Python production authority, no_change optimization policy, all eight
universal-false claims and all 27 broad blocker criteria remain unchanged.
