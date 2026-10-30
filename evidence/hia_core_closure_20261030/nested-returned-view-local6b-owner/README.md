# Nested returned origins in local Views: frozen local candidate

This directory retains an actual finite P0 source-adapter increment. It does not
close a strict P0–P7 obligation. Python remains the production Core authority,
the optimization policy remains `no_change`, and no general provenance,
escaping lifetime, cancellation, ABI or refinement claim is added.

## Exact source and implementation

The frozen local commit is `6b83eae0aef1cfbc9654510b55f5c35ed0bd55d5`, tree
`0cac7421225a2f8bba1de07c08011d79410b8cdc`, based directly on public
`a6cfb7e00a1c08276d27459bdcc5628aa7622079`. These are local-candidate executions;
they are not relabelled as executions of a later public or combined commit.

There are ten source files in the diff. `hepta/hia_program_source.py` is the only
production implementation file changed. Every stored-field origin call must
have one same-permission byte borrowed formal, return from that formal, and
have only scalar value parameters elsewhere. The origin argument can be
another call satisfying the same rules. Its terminal place remains a named
byte owner, incoming borrowed byte parameter, or ordinary owner-record field.
Local-View origins, borrowed aggregate formals, multiple borrowed formals,
permission conversions and escaping View storage retain their refusals.

The adapter recursively validates the actual call chain and prepares arguments
in source order before invoking the existing `call()` implementation. It uses
the existing `borrow_parents`, flat loan lists, CFG capabilities and lexical or
explicit cleanup. The original checker, ResourceIR verifier, primitive Core,
Rust Machine and LLVM backend were not changed. No public flag, schema,
primitive instruction or execution route was added.

`source-export/manifest.json` binds all ten exact UTF-8 Git blobs, sizes, modes,
SHA-256 values and exported files. `source-export/source.patch` is 54,634 bytes,
SHA-256 `e054ee398e1a3058529da5f702665bef6868f6b5de0ce4f69529b97eee1b7d89`.
`export_candidate.py` independently applied it to the public a6 parent in a
separate temporary index and reconstructed the exact frozen tree.

## Actual red probes and development

`parent-a6cf-red/` contains four original source programs. Each passed the
unchanged source checker and fresh ResourceIR verification on clean a6. Each
failed the original HIA adapter with its direct-named-origin restriction.
The cases cover a shared Copy/branch, a mutable move/drop loop, a nonfirst
borrowed formal over an ordinary owner field, and explicit mutable cleanup on
early and normal returns. The probe scripts and their original hashes remain.

`development1/` contains the initial dirty implementation's four accepted Core
programs and nine Python executions. Its source snapshot was taken after the
run; it explicitly makes no before/after source-binding claim. `development2/`
retains an actual eleven-method development run with one failure and one error:
the test omitted scalar `stamp` from the existing source export selection, and
incorrectly assumed that reborrowing a stored View field passed ResourceIR.
The expectations were corrected without changing source/Core admission.
`development3/` retains the targeted two-method rerun. None of these dirty
observations is counted as frozen execution evidence.

## Frozen new ten methods

`frozen6b-new10/summary.json` is the original successful collector result:

- 10 distinct selected methods, each with one ordinary success, no skips,
  errors, failures, expected failures or unexpected successes.
- 103 actual Rust/Python full-ledger comparisons: 43 returned and 60 stopped by
  evaluator budget. The selected mutable-loop execution completes in 59 steps,
  and each step limit through that completion was actually compared.
- Six actual invalid emitted Core documents submitted separately to raw Rust;
  all were refused. Six corresponding Python Core refusals are retained.
- 35 actual direct-LLVM scalar calls and six actual native allocator-observer
  processes, with original outputs and generated native files retained.
- Fourteen source refusals, four allocation-order Python reports and six
  original bounded compiler-runner records, including temporary LLVM inputs.

The argument-order fixture allocates the root owner first, then a scalar prefix,
then its nested mutable origin, then a scalar suffix. Its successful result is
15. Failing allocation attempt 2, 3 or 4 yields 113, 61 or 109. Those distinct
results were observed through Python, Rust and the native allocator wrapper.
All six successful native observer invocations reported balanced allocations
and frees and zero live requested payload. Logical payload is not RSS.

The six Core mutations target a root or middle ancestor ended before its
descendants, live-borrowed owner release, a balanced shared reborrow from an
exclusive middle ancestor with a live mutable child, an omitted middle end,
and swapped intermediate ancestors on one CFG edge. The exact expected
primitive diagnostic is checked. A balanced additional shared reborrow remains
an accepted neighbour; it is not misclassified as an exclusivity violation.

The collector reuses the previously built Rust binary with SHA-256
`090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`.
It did not rebuild the crate or attribute earlier build cost to this source.
Actual Clang/Python/Rust file identities, process arguments, stdout/stderr and
source/tool/producer before-and-after identities are retained.

## Existing regression attempts remain separate

`frozen6b-regressions92/` is an original **failed** batch: 92 methods ran,
89 had ordinary successes, and three safety-protocol methods raised
`FileNotFoundError`. The sparse worktree was missing three already tracked
experiment protocol JSON files needed by dynamic import. The failed report is
retained unchanged and is not turned into a passing batch.

`sparse-protocol-inputs-restored.json` records exactly those three files, 8,846
bytes, materialized from this same frozen Git tree and checked against their
original blob identities and modes. There was no source change.
`frozen6b-protocol3-retry/` reran only those three failed methods and recorded
three ordinary successes. The aggregate is therefore 105 method attempts,
102 distinct method IDs with an ordinary success: the new ten plus the old 92.
It is not a 102-method single-run report, and it is not a full 359-method run.

The new-ten and first regression batches bound all 1,456 materialized files.
The retry bound 1,459 after restoring the three protocol inputs. The full Git
tree contains 7,701 files; absent sparse paths are not claimed as runtime input
coverage. Every materialized file's actual raw Git blob, SHA-256 and executable
mode matched the frozen tree before and after its batch.

`single-call-core-stability.json` compares the two original single-call Core
programs and all five existing invalid emitted programs against the actual
public-a6 raw records. They are identical after the adapter change. This is a
compilation/readback check, not a replay or relabelling of the old native/Rust
observations. The five old Python semantic methods did run in the 92 batch.

## Selection, roles and remaining claims

`contract-union.json` recomputes the exact 349 + 10 = 359 selector union in the
same 36 capabilities. All original selectors remain, and the other 35
capabilities and global trust/unproved-claim values are unchanged. The existing
source capability explicitly updates only the bounded nested-origin scope and
its corresponding exclusion. The reviewed canonical contract SHA-256 is
`44c138659e8472a58db069c035d066feaaa5877680dc550b784802fe40ac9e76`.
Registration and selector resolution are not execution of that full matrix.

The owner authored the adapter, tests, collector and this summary. A separate
`evidence_resume` peer reviews the implementation and original records and may
run narrowly different controls; its review is a separate artifact. This
owner summary is not an independent review. The root publisher controls any
later public or combined source and records its own identity separately.

The complete set of 27 strict P0–P7 obligations remains open. This increment
removes one source-composition rejection already expressible by the existing
Core; it does not unify all historical execution entrances or prove arbitrary
recursive layouts, lifetime escape, asynchronous cleanup, full Rust authority,
general interoperation, universal migration, agent efficiency, physical device
performance, language soundness or backend refinement.
