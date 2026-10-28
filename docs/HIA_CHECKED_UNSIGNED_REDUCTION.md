# Checked unsigned reduction candidate

`hepta.hia_checked_reduction_opt.rewrite_checked_unsigned_reduction` implements
`checked-unsigned-reduction.v1`. The input and complete output are independently
admitted by `verify_program`. The rule retains the input primitive schema,
including v7; it refuses composite inputs instead of erasing their structured
identity. NDU's registered adapter separately retains its primitive v1–v6 scope.

## Accepted dataflow

The exact admitted loop computes this unsigned operation at a single type
(`u8`, `u16`, `u32`, `u64`, or `usize`):

```text
index = 0
sum = 0
while index < count:
    sum = checked_add(sum, value)
    index = checked_add(index, 1)
```

The replacement computes `checked_mul(count, value)`. An escaping final sum is
replaced with the product; an escaping final index is replaced with `count`.
The zero-count case returns zero even when `value` is the type maximum.

The matcher checks one non-entry header with exactly the comparison and one
body with exactly the literal one and the two checked additions. It checks
every incoming edge, the unique zero-initializing preheader, unit stride, all
block argument positions and types, the exact backedge and unchanged carried
values. Count and value are invariant and cannot refer to the changing index
or accumulator. Count may also be the invariant addend. Additional operations,
extra predecessors, wrapping or signed arithmetic, nonzero starts, changed
carried values, inclusive comparisons and escaped comparison results refuse
the rewrite. Valid programs outside the pattern are returned unchanged.

Resource values may be carried through the loop without operations on them.
The exact edge mapping and the Core verifier still enforce their ownership and
loan identities. No load, store, call, allocation, destruction, borrow transition
or cancellation event can occur in the matched header or body. Outside
instructions and their ordering remain unchanged. A new SSA result name is
chosen deterministically from the function's actual definition inventory.

## Why the overflow behavior agrees

For unsigned `value`, partial mathematical sums are nondecreasing. If
`count × value` fits, every preceding sum fits. If the product does not fit,
one checked addition in the original loop and the replacement checked multiply
both trap with the Core overflow code. The original index increment cannot
overflow on a taken iteration: `index < count ≤ maximum` implies
`index + 1 ≤ maximum`. No intervening loop operation has another trap or an
observable resource/memory effect. Preceding and following traps retain their
order relative to the reduction, including caller-side casts and live owners
or loans at overflow.

`formal/HiaCheckedReduction.lean` independently defines checked repeated
addition and checked multiplication over mathematical naturals. Its theorems
state equality of the complete optional outcome for every bound, count and
value, agreement of overflow, and the index increment bound. The executable
proof control also requires rejection of two mutations: starting the sum at
one, and removing the multiplication overflow guard. The imported Lean kernel
and its stated axioms remain trusted.

That theorem does **not** prove the Python matcher, CFG interpretation,
resource verifier, LLVM emitter, native ABI or backend refinement. The matcher
is reviewed implementation, and finite Python/native controls provide separate
evidence. There is no theorem establishing global optimality or whole-language
soundness.

## Execution and measurement scope

`tests/test_hia_checked_reduction_opt.py` checks every u8 count around its exact
overflow boundary, representative boundaries at all wider unsigned types,
full resource ledgers during caller allocation refusal and active borrowing,
valid near misses, schema identity and native u32 return/abort behavior. The
native control compares actual artifact bytes under identical Clang flags;
different bytes alone establish no speedup. The step-budget control deliberately
demonstrates that the optimized program can finish when the original exhausts
its instruction budget. Execution fuel, host interruption/scheduling and host
allocation failures are outside this optional rule's equivalence contract.

`examples/hia_ndu/checked_reduction.json` is a scalar four-usize-to-u8 adapter
for the existing native NDU instrument. It retains an initial checked mask
cast, the reduction call, a subsequent checked offset addition, a wrapping
byte cast and XOR. The adjacent case files explicitly retain both successful
and failing combinations. They are an arithmetic mechanism corpus authored
for this rule, not an unchanged external application's measured hot function.
Any frozen timing experiment must retain that distinction, all raw samples,
both compiler identities and flags, actual artifact identities, paid search
costs, refusals and no-change outcomes. Industrial P4 acceptance remains a
separate obligation even if this mechanism obtains an accepted measured gain.
