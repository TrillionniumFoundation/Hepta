# HIA v5 + Agent impact: source-level convergence checkpoint

Integration inputs (exact Git commits):
- Native v5 range-copy PR #191: c36243d1c2bc42f9c3ac81f1d4044c847b5d72d2
- Verified v3 read-only Agent impact PR #190: f7cc496a6878eec4dfa79132adaa1e6c7688986b
- Common unchanged producer parent: PR #186 b763482c1c2832796dafcb61efcb91296c4ff494

All four donor changes are new files or byte-identical to the common ancestor
on the v5 recipient branch before integration. The donor's exact Git blobs
are used without rewriting the core verifier, LLVM backend, Agent mutation
protocol or CLI.

Result: existing HIA v5 typed Owner/Loan range copy and v3 Agent advisory
patch-impact analysis coexist. A new cross-branch regression checks the
unchanged v5 program, source-identity-bound patch, complete candidate
verification, only intended local copy data update, interface preservation,
native qualification nonclaim and read-only CLI no-publication behavior.

Reproduce in complete exact-source checkout:

```sh
python -m unittest tests.test_hia_v5_agent_convergence \
  tests.test_hia_offset_copy_v5 tests.test_hia_patch_impact \
  tests.test_hia_swap_opt tests.test_hia_program -v
```

Pure Git object/blob ancestry comparison is not native execution qualification.
Standalone handwritten-LLVM copy controls and earlier Agent mock tests remain
separately scoped evidence. Exact merged SHA still requires real in-repo
unit, native, model, CPU/RSS and hardware runs.

`whole_project_blockers_closed=false`.
