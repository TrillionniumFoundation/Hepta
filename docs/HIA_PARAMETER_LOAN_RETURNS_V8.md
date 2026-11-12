# Parameter-bound internal loan returns in primitive v8

`hepta.hia.program.v8` extends the independently verified standalone Core with
the finite profile `closed-ssa-parameter-loan-returns-64-v8`. The production
authority remains `verify_core`. Python execution and direct LLVM compilation
reverify the same immutable program bytes; a source or proof receipt cannot
grant admission. Primitive v1–v7 retain their existing wire grammar and reject
borrowed results and the new field. Composite v1/v2/v3 still normalize exactly to
primitive v6/v7. The earlier development-branch spelling `return_origins` is
not a second accepted v8 wire format. Current source producers and examples
emit `return_loans`, and historical receipts keep their original bytes.

## Function contract

A v8 function may declare an optional `return_loans` array. It has exactly as
many entries as `returns`. Every `readbuf` or `mutbuf` result names an original
loan parameter. Other result positions contain JSON `null`. Missing entries
therefore cannot qualify a borrowed result. For example:

```json
{
  "params": [{"name": "input", "type": "readbuf"}],
  "returns": ["readbuf", "bool"],
  "return_loans": ["input", null]
}
```

This excerpt illustrates the contract fields; a complete function also needs
its name, effects, entry and executable blocks. A mutable result must name a
mutable loan parameter. An owned parameter, missing name, malformed entry,
permission escalation or wrong result arity rejects. Nonloan functions may
omit the field or spell the all-null array explicitly.

The original function-parameter identity is carried independently of SSA
names, roots and parent names. CFG parameter renaming cannot silently change
it. Functions without borrowed results retain the older loan-graph join rules;
adding v8 does not retroactively restrict their source-parameter interchange.

## Exact returned capabilities

A borrowed return must be its declared external parameter capability itself,
or a direct child of that parameter. A child obtained from another internal
call is admitted when it has this direct parent relationship. Forwarding,
read-only reborrowing, exclusive reborrowing, explicit CFG transfers and
recursive calls therefore compose within this rule.

Returning a loan rooted in a local or consumed owner, a loan from another
declared parameter, a deeper local descendant, a capability with live children,
or the same consumable capability twice rejects. A return must still consume
all local owners and other local loans. Normal error-as-value returns obey the
same cleanup requirements; a trap or evaluator budget stop retains the actual
stopped ledger and does not claim destructor unwinding.

Each caller receives a child loan of the actual argument selected by the
contract. The parent stays live and suspended until the child ends. Owner
move/drop, chain pop/drop, parent access and parent end must respect this graph.
Multiple shared results may refer to the same actual parent through distinct
formal parameters, but are separate consumable result capabilities. Multiple
exclusive actual arguments that alias the same root reject. Results may swap
two independent mutable origins only when the contract explicitly declares
that ordering.

The interpreter creates a fresh child view when the callee forwards a parameter
and increments the loan ledger once. Returning an already-created direct child
transfers that view without creating or counting another view. This prevents
ending the caller's parent by ending a forwarded result. The runtime also
checks the selected actual parent, liveness and mutable permission.

## Native and consumer boundaries

Internal LLVM functions reuse the existing buffer descriptor and multiple
result lowering. The x86-64, AArch64 and RV64 profiles explicitly identify v8.
Public entrypoints and C wrappers retain scalar-only signatures; this does not
expose loan handles across a foreign ABI or implement callback lifetimes.
Object generation on a target is separate from actual target execution.

The finite native observation tests compare real allocator calls, frees,
result values and byte peaks for successful/error-value paths and for chain
heads borrowed through returned-loan calls. Runtime loan objects are erased
in LLVM; static loan checks and VM loan counters are not presented as native
loan instrumentation.

The independent Rust owned shadow and byte-owner Machine have separately
versioned [v8 returned-loan profiles](HIA_RUST_RETURNED_LOANS_V8.md). Rust
scalar-only execution remains v1–v7. The separately versioned
[v5 chain execution profile](HIA_RUST_RETURNED_CHAINS_V8.md) composes inherited
chain operations and parameter-bound returned loans in the same Rust Machine.
The existing analyzers provide separate [v8 frame, event and public-entry
payload profiles](HIA_V8_RESOURCE_BUDGETS.md); the old all-function heap and
source-facing native receipt consumers keep their original refusal boundaries.
The [cross-target qualifier](HIA_RETURNED_LOAN_CROSS_EXECUTION.md) executes
finite returned-loan programs under AArch64/RV64 QEMU, without qualifying
physical hardware or external borrowed-handle ABI. Older optimization proofs
still refuse v8. Versioned Agent inspection, query, atomic edits and
whole-function interface comparison include the declared origins.

This increment does not close general resource safety: arbitrary lifetime
parameters, arbitrary ancestor returns, escaping stored self-references,
general recursive heap ADTs, asynchronous cancellation and external
lifetimes remain separate work. No whole-language soundness, LLVM refinement,
universal resource bound or universal Rust performance claim is established.

The implementation was recreated after an unpublished worktree was reclaimed.
Current qualification belongs to the newly committed bytes and its retained
logs; earlier lost-worktree results are not relabeled as current results.
