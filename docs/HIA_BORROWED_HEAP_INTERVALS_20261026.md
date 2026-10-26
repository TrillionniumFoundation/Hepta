# HIA P1 — Borrow-root SSA heap interval propagation (2026-10-26)

This increment extends the **existing**, opt-in `hepta.hia_heap_bound` analyzer on
the exact PR #214 parent `54964668878d6e3ba792037da6bae91f78a87553`.
No new checker, ISA, AST/IR, LLVM backend or alternate semantic authority is
introduced. `hepta.hia_program.verify_program` remains mandatory and decides
all executable Owner/Loan legality.

## Gap addressed

The previous interval analyzer tracked bounded owner extents across SSA blocks
but forgot borrowed aliases. `buffer.len(readbuf/mutbuf)` therefore lost a
finite bound even when the Core had independently verified that the view came
from a live, locally allocated bounded Buffer. Such a program was rejected by
optional heap admission despite having a safe, finite requested-payload bound.

The new state is `(owner_upper_bytes, scalar_interval, live_loan_root)`.
The per-function analysis:

- Associates `borrow.read` and `borrow.mut`, including nested reborrows,
  with the verified originating owner without duplicating ownership or bytes.
- Removes loan associations at `loan.end`. An Owner cannot be dropped/moved
  while the analyzer still tracks a loan rooted in it.
- Propagates loan root identities through the *same* HIA CFG block-argument
  transfer mapping as owners. Joins require identical normalized loan-root
  relationships; different finite owner sizes are merged by maxima.
- Treats owner/view `buffer.len` as the interval `[0, upper]`. In particular,
  a failed `buffer.try_new` is **not** treated as having its requested length.
- Refuses any borrow with an unknown/non-forwarded bounded root rather than
  inventing an allocation size. Existing cycle, recursion, future-opcode and
  future-schema rejection remains unchanged.

These are allocation *payload byte* bounds only. Runtime allocator metadata,
native RSS, stack, FFI, device memory, data-dependent loop invariants and
whole-language proof are OUTSIDE this analyzer.

## Genuine source acceptance inputs

`tests/test_hia_heap_borrowed.py` commits five regression methods using
actual `verify_program` and `execute_program` entry points:

| Program | Required abstract peak | Bound test |
|---|---:|---|
| Single-owner borrowed length followed by fallible second allocation | 14 | normal plus second-allocator denial, opt-in gate at 14 and refusal at 13 |
| Nested read reborrow from mutable view across CFG blocks | 8 | real checked loan/root remapping and VM result |
| Diamond join of alternative owner+view roots, 3 vs 11 bytes | 22 | both branch executions bounded |
| View edge carrying wrong type/root | rejected | canonical verifier must refuse |
| `buffer.len` after `loan.end` | rejected | canonical verifier must refuse |

These are **committed test cases, not a claim of passing results**. The current
environment does not have the complete checkout or a native Rust toolchain;
exact-head Python/native and LLVM tests remain unexecuted.

Reproduction on the exact checkout:

```bash
python -m unittest tests.test_hia_heap_borrowed tests.test_hia_heap_bound \
  tests.test_hia_heap_intervals tests.test_hia_static_budget -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
python tools/release_check.py
```

**P0–P7 all-blocker closure remains false.** General Memory/Provenance SSA,
C/C++ L2/L3 equivalence, Rust compiler proof, real Agent A/B, GPU/NPU and
physical device, fair p99/RSS acceptance remain separate requirements.
