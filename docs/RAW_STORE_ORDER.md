# Raw store call-order characterization

This checkpoint changes no compiler implementation and does not expand the C
subset. It records a suspected lowering mismatch for the unsafe builtin call
`store(pointer, offset, value)` before repairing it. Ordinary assignment is a
separate operation and retains its existing right-hand-side-first contract.

SPEC section 7 states left-to-right named-call argument evaluation. The frontend
checks the three store arguments in pointer, offset, value order. The Rust
emitter currently emits an assignment, `*pointer.add(offset) = value`, whose
[right operand is evaluated first](https://doc.rust-lang.org/reference/expressions/operator-expr.html#assignment-expressions).
The precise Rust rule is `expr.assign.evaluation-order`: assigned value first,
then assignee. By contrast, volatile_store uses a function call. The C emitter
currently rejects effectful calls in either store builtin's operands.

The new native harness logs P (pointer), I (index), V (value), and A (the next
operation). V switches which of two valid, aligned i64 cells a later pointer
selection will return. The explicit ordered C oracle produces PIVA and cell
values 42/0; the existing Rust store lowering is expected to produce VPIA and
0/42. Thus the observation is not a commutative counter or source-string check.
Each process starts with fresh cells. Aborts at P/I/V retain the exact prefix,
with stdout explicitly flushed before abort, and must not execute A.

Local GCC O0/O3 plus UBSan validates the ordered oracle and all abort prefixes;
frontend success and the exact C rejection are also checked. Actual Rust
characterization requires the pinned Rust 1.90 Linux x86-64/AArch64 CI, where
all four tests must execute without skips. Until that result is observed, the
Rust outcome is a prediction from the emitted source and official semantics,
not a claimed native observation. This checkpoint is not a fix, pointer-safety
proof, MMIO qualification, or permission to use invalid/dangling raw pointers.
