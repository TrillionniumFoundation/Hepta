## Why

Nominal partial-record typestates currently normalize to primitive v7, while
parameter-bound returned loans require primitive v8. A caller can borrow an
initialized buffer field of a partial record, but cannot pass that view to a
helper that returns a checked child view through the same nominal program.
The two existing profiles therefore reject a useful composition even though
the primitive v8 checker and Machine already support its executable behavior.

## Change and resulting behavior

Add the explicit `hepta.hia.composite.v4` frontend profile. The existing nominal
elaborator preserves partial states, owner tokens, calls and CFG structure,
then maps a function's nominal `return_loans` annotations to primitive v8.
Only a primitive borrowed result can name an original primitive borrowed
formal with sufficient permission. A nominal nonloan result contributes null
entries for all of its flattened leaves, including private partial-state
tokens. The ordinary primitive checker independently validates the generated
origin and owner/parent/child relationships.

This permits the checked sequence: retain a partial record in the caller,
borrow its initialized buffer field, call an internal returned-view helper,
use and end the child, end the parent, then take and restore the field. A
separate fixture returns an unrelated partial state before a borrowed result,
exercising annotation expansion and a primitive borrowed formal after expanded
nominal formals.

Composite v1/v2/v3 retain their original normalization targets and refusal
contracts. Aggregate stored-loan results, loan-containing partial layouts,
uninitialized field access, incomplete finish, wrong origins and moving a
borrowed owner remain rejected. Public exports still derive only from the
original scalar signatures. The raw Rust route still receives normalized
primitive Core; direct LLVM keeps the scalar public C ABI.

The safety matrix retains its previous 103 methods and adds 13, for 116 unique
selected methods. The registry snapshot and independent reviewed digest are
updated together, and integrated critical coverage requires the new module.
The full 116-method matrix is a selected obligation; it is not claimed as
executed by the focused component receipt below.

## Validation

Freshly executed public component: `99cf106586509b08bb2b9890ed29cf042336d69e`, parent `adbe4a1168a84d0696749ef54f933994b5dc554c`.
Exact source tree: `c2afb20ce0eb14ff3a7750ff123d8f9bfa8842e2`.
The separately retained local component is `e21d672eb1bc588e248f72b0217b922671a869a5`; its reports keep that identity.

- Focused qualifier: **13/13 methods**, zero failures, errors, skips, expected
  failures or unexpected successes. It retained **153 actual Rust comparisons**,
  **4 raw Rust refusals**, and **31 actual native calls** with source, tools and
  Rust binary stable before and after.
- Legacy composite/partial/returned-loan/source-route regression selection:
  **98/98 methods**, zero failures or skips, exact source unchanged.
- Real Rust uses the existing Machine with the bound-v4 invocation protocol.
  Cases include read/mutable forwarding, child creation, CFG renaming,
  recursion, expanded nominal return slots, every actual step boundary in two
  recursive fixtures, allocation failure, heap limits and depth limits.
- Real LLVM20 execution covers nine modules with private helpers and scalar
  exports. Normal native calls retain payload sizes 1, 7 and 19. The separate
  allocator observer executes its declared one-byte fixture under success and
  injected failure, with balanced physical allocation/free and byte counters.

The first development allocator assertion used a seven-byte payload with the
existing observer, whose documented classifier recognizes only one-byte
payloads and 24-byte chain nodes. `unknown_sizes=1` caused that assertion to
fail; actual values, allocations, frees and live/peak bytes agreed with Python
for all three probe policies. The retained reproduction distinguishes those
fresh process outputs from the separately labeled copied original diagnostic.
The observer case now respects that fixture precondition; no backend or
resource-admission rule was changed in response, and normal size-7/19 native
calls remain in the nine-module corpus.

A new, clean detached checkout of public `99cf106` was fetched and independently compared against all 14 exported blobs and modes. Its fresh exact-head 13-method composition and 98-method legacy runs passed, and the stacked Rust API v4 qualification passed 8/8 with 155 actual comparisons, 37 raw refusals and eight legacy-version sets. Per-command argv, UTC start/end, elapsed time, stdout and stderr are retained. The CLI example returned 37 with balanced owners and loans. These overlapping denominators remain separate.

Independent review at original local `e21d672` found no blocking defect within its finite scope. Its distinct zero-width/expanded partial-result, two loan-origin, mutual-recursion, CFG-origin-refusal and allocator-precondition controls remain identified as independent local observations. The original public-source publication receipt retains its historical `public_execution_performed_at_this_snapshot=false`; later public execution receipts record the new successful runs.

## Scope

This closes the finite nominal partial-record/primitive parameter-returned-loan
composition gap. Historical source, bridge, local-view and task/I/O convergence
remains open. General memory/provenance, arbitrary recursive ADTs, complete
partial initialization, stored escaping loans, external lifetimes and complete
cancellation/error cleanup remain open. No source/Core/backend refinement
theorem, callback/reentrant/threaded ABI, performance or physical-device
qualification follows from this change. Python remains production admission
authority and the optimization policy remains `no_change`.
