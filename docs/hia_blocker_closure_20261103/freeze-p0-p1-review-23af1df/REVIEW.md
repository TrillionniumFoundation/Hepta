# Recovery freeze code review and next P0/P1 proof increment

## Identity and review scope

- Final integrated source: `23af1df3eed65230137aa54ab8b10eac3520abd3`.
- Final source tree: `1a6c0c6801e8c4be5117018b8052d289f6546e99`.
- Independently reviewed freeze implementation commit: `c77f38f69d923ade03e3a5958604f8858ef07fae`, parent `1629a03dc76c5360550da40a6fc6fcbd80425128`.
- Review date: 2026-11-03 UTC. Reviewer role: safety_implementation, separate from the freeze implementation author.
- Method: read-only inspection of complete recovery adapter and tests, inherited v4 register/save/validate call chain, production capability checker, formal models, and witness exporters. No model request, native benchmark, source edit, or new test execution was performed for this review. The integrator separately reported 6 recovery plus 20 original protocol tests passing; this report does not relabel those executions as an independent rerun.
- The final recovery `run_study.py` and `test_recovery.py` are byte-identical to the reviewed commit. Between 1629 and 23af, only those two files and the recovery README changed. Original v4 files did not change.
- Ledger authority: [Issue 471](https://github.com/TrillionniumFoundation/Hepta/issues/471), read on the review date; issue state remains OPEN / DENY_ALL. This report is not a release grant.

The companion `review-identities.json` records source SHA-256 identities and the exact issue body identity.

## Freeze fix: no blocking defect found in the reviewed publication scope

The previous adapter called the inherited `register()`, which already wrote `REGISTRATION.json` through a create-only writer, and then attempted to save enriched metadata at the same path. The second write was correctly refused. The fix intercepts the inherited registration's single publication and enriches it before serialization.

| Path | Observed implementation and consequence |
| --- | --- |
| Successful publication | Add campaign/source/tree/protocol/preparation metadata, fully serialize with canonical JSON, create candidate with `xb`, write, flush, fsync, close, then create the final name with `os.link`. The final path never exposes a partially written registration. |
| Existing final | Early refusal. No existing registration is overwritten. |
| Final created after the early existence check | `os.link` refuses the occupied final path and preserves the concurrent owner's bytes. |
| Serialization failure | Occurs before candidate creation. No registration final is published. Earlier create-only fixture evidence remains. |
| Candidate already exists, write failure, or fsync failure | Exception propagates before linking a final path. A failed candidate may remain as diagnostic evidence. |
| Link failure | No final created by this invocation; a candidate remains. An already-existing final is preserved. |
| Writer restoration | `finally` restores the prior `evaluator.save` on normal completion and exceptional exits from `register()`. |
| Admission | Validation reads `REGISTRATION.json`, never the candidate. Generation additionally requires an independent review bound to the final registration hash and exact source. |

The regression fixture uses the real inherited `register()` and `save()` call path while substituting local, explicitly non-model preparation evidence. It covers successful complete metadata publication, existing registration refusal, serialization failure, link failure, and final-path competition. It is not a real-model productivity observation.

**Precise boundary:** the fix gives create-only atomic publication of one complete registration file. If linking succeeds and candidate cleanup subsequently fails, a complete final can remain while the command raises. The final still needs independent review before generation. This is not an all-files transaction, a concurrent-thread-safe registry service, or a directory power-loss durability proof. No such wider claim is needed for the reviewed single-process freeze path.

Primary code: [recovery adapter](https://github.com/TrillionniumFoundation/Hepta/blob/23af1df3eed65230137aa54ab8b10eac3520abd3/experiments/hia_agent_local_recovery_20261103/run_study.py), [recovery controls](https://github.com/TrillionniumFoundation/Hepta/blob/23af1df3eed65230137aa54ab8b10eac3520abd3/experiments/hia_agent_local_recovery_20261103/test_recovery.py), and unchanged [v4 register/validator](https://github.com/TrillionniumFoundation/Hepta/blob/23af1df3eed65230137aa54ab8b10eac3520abd3/experiments/hia_agent_assembly_v4_20261030/run_study.py).

## P0/P1: what the existing proof does and does not establish

The selected capability lifecycle/borrow model proves closure, rank/acyclicity, name uniqueness, borrow compatibility, and parent-view suspension for its admitted instruction steps and transfers. Its abstract finite Trace is not restricted to a fixed length. This is substantive scoped proof; the remaining problem is connecting all relevant production transitions to that Trace with continuous states.

The recorded borrow proof run includes 1,100 Lean kernel dependency checks, 16 proof negative controls, and 4 actual checker rejection controls. These are existing executions, not rerun by this review. They do not establish whole-language memory safety or a full checker refinement theorem.

The production checker already propagates capability states through a CFG, validates actual-to-formal resource remaps, and requires exact incoming capability dictionaries to agree at joins and backedges. The gap described here is in the exported formal correspondence, not an assertion that those production guards are missing.

| Concrete obligation still open | Existing location and limitation |
| --- | --- |
| Derive legal release premises from reachable checker states | `formal/HiaCapabilityLifecycle.lean` defines `Unreferenced`; selected end/drop steps require it. Actual `_BlockCheck` guards use local-view childlessness or an owner's same-root scan. A stronger reachable-state invariant is needed to derive the model premise from these guards. |
| Preserve typed, rooted state from function entry | `hepta/hia_program.py` constructs resource entries and updates capabilities across allocation, borrowing, ending, dropping, moves, chain transfers, calls, and returns. The existing formal slice does not prove that complete production transition inventory preserves the required kind/env and root/parent relationships. |
| Continuous instruction correspondence | `tools/verify_hia_capability_lifecycle.py` and `tools/verify_hia_capability_borrow.py` encode each observed row with its own namespace and independently establish its before-state facts. They do not yet require one instruction's after-state to equal the next instruction's before-state. |
| Complete CFG walk correspondence | Transfer witnesses exist separately in `tools/verify_hia_capabilities.py`. A combined certificate must bind each block exit/edge projection/renaming to the actual destination entry, cover branch and backedge cases, and account for every instruction in the selected profile. The current report explicitly leaves `whole_cfg_execution_trace_exported` false. |
| Runtime/refinement obligations beyond capability graphs | Source execution, heap contents/aliasing/provenance, trap and all completion outcomes, foreign contracts, compiler/LLVM machine semantics, and native resource budgets need their own checked correspondence and evidence. They cannot follow merely from capability graph preservation. |

### Concrete countermodel to an insufficient abstract invariant

Consider the following internal capability graph:

| Name | Kind | Root | Parent |
| --- | --- | --- | --- |
| r | owner | r | none |
| c | owner | r | r |
| d | read view | r | c |

It can satisfy uniqueness, closure, a decreasing parent rank, parent/root agreement, and the assertion that each referenced root is a legal owner. Nevertheless, a same-root scan for `owner_free(c)` finds no other capability with root `c`, while `d.parent = c`; deleting `c` would violate `Unreferenced`.

**This is a counterexample to an insufficient proposed proof premise, not a demonstrated production checker bug.** No accepted program or reachable production state producing this nested owner was found. Production owner-creating rules inspected here create self-rooted owners; the extra invariant must state that fact for every owner, not just for nodes that happen to be referenced as roots.

### Most useful next deliverable

Implement a selected-profile CFG capability certificate and the reachable-state lemmas it needs:

1. Name a `Rooted`/typed invariant explicitly: every owner is self-rooted with no parent; external entry views are legal roots; local views have a parent and inherit its root; capability kinds agree with the live resource environment; names are unique and referenced roots/parents exist.
2. Prove entry establishment and preservation under the selected allocation/borrow/end/drop/access steps and admitted projection/renaming transfers. Derive local `Childless -> Unreferenced` and owner-free-scan `-> Unreferenced` from that invariant, rather than adding the desired after-state property as a premise. Returned external roots additionally need a finite path-to-root argument.
3. Export one function-wide namespace and exact adjacent capability/environment states. Bind block entry, every selected operation, terminator, edge transfer, and destination entry; reject omitted or disconnected observations.
4. Prove that any finite walk through such a checked CFG certificate produces the existing abstract Trace. A finite certificate may support loops without claiming that the runtime terminates.

Expected implementation scope: additive Lean lemmas or one companion formal file, a joint observer/exporter or narrowly factored existing exporters, and focused fixtures/regressions, approximately 5–7 files. This is an implementation-scope estimate, not an elapsed-time promise. Calls, moves, chain transfers, return variants, or other transitions not included in the first selected profile must be explicitly refused by that certificate or left outside its declared theorem; they must not be silently skipped.

Meaningful rejecting controls should target disconnected adjacent states that each look valid in isolation, a dropped/reordered operation, an edge attached to the wrong destination/incoming state, a backedge/join mismatch, and the malformed nested-owner countermodel above. Positive controls should include an actual multi-block path, shared siblings, mutable reborrowing with parent suspension, end/restoration, and nontrivial edge renaming. These controls serve specific correspondence obligations rather than a target test count.

Until that work and the wider semantic/runtime obligations are separately established, whole-checker/source/heap/LLVM/FFI refinement, whole-language safety, all-seven closure, and production activation remain unproved or false as currently declared.
