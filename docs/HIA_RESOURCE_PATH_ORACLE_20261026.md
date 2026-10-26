# HIA finite operational Resource IR path oracle — P1 increment

The one canonical Resource IR verifier in `hepta.resource_ir` remains the sole
ownership transition authority. The new `hepta.hia_resource_trace` is a
test-only bounded path replay of its already-verified CFG; it invokes the
*same* internal typed transfer operations instead of implementing a second
ownership checker. It is **not** a second compiler, a source authorization
gate, a numeric interpreter, or a machine-memory model.

## Supported finite profile

- Existing Resource IR v3/v4/v5 with exactly qualified, claim-false receipts,
  no external assumptions, selected non-generic local function with Unit
  return, and no owned input parameters.
- `acquire(buffer)`, `move`, `drop`, `borrow`, `end_borrow`, `use`
  with `jump`, `branch` and normal `return`.
- Caller supplies the 0-based successor number of each branch occurrence.
  Actual Boolean expression values **are not evaluated**; branch choices do
  not prove that a source/native execution will take the same route.
- Finite operation and branch budgets. Refuse fallible allocator outcomes,
  view/aggregate/call/FFI instructions, switch/exceptions, stale receipts,
  unconsumed choices and invalid loops. A fuel exhaustion is not a runtime trap
  or proof of nontermination.
- Output includes graph identity, chosen path, active-owned/loan snapshots,
  transition counts and a canonical witness hash. The hash is an integrity
  hint, **not source authenticity**.

## Reproduction

```sh
python -m unittest tests.test_hia_resource_trace -v
python -m unittest tests.test_resource_ir tests.test_owned_drop_sites -v
```

The 5 local tests executed with a **test stub for the missing full repository
Resource IR module** and verify the wrapper/trace protocol only. The actual
repository tests and native HIA LLVM differential have not been run against
this combined commit; neither is claimed as passed.

P1 full executable numeric+Owner/Loan/Drop/Memory SSA is still OPEN. P2
native LLVM still does not consume a single verified executable Owned HIA
Core; this trace oracle does not qualify it. No silent claim upgrade.
`whole_project_blockers_closed=false`.
