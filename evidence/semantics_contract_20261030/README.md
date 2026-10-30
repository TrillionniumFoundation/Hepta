# Unified semantics: explicit-interface refusal and cancellation outcomes

Starting repository commit:
`a32ad51250b905bb4729168f4d8f9328880b44db`.

The original native backend could accept an explicit export list containing
`scalar(u64)->u64` and `pair(u64)->(u64,u64)`, build a real shared library and
publish a receipt listing only `scalar`. The interpreter returned `[7, 7]` from
`pair(7)`, while the compiled library had no `pair` symbol. This was a concrete
public-interface mismatch, rather than a proposed expansion of the native ABI.

`hepta/hia_program_llvm.py` now rejects the whole native build with
`E_HIA_PROGRAM_ABI` if any explicit export falls outside the existing C wrapper
signature profile. Unsupported internal signatures and historical implicit
export discovery retain their original scopes. No arithmetic, resource, trap
or optimization check was relaxed.

The new `tests/test_hia_semantics_contract.py` covers the original counterexample,
unit arguments, all three target emitters, refusal before compilation and
publication, and real native exact-export execution. It also executes composite
cooperative tasks whose cancellation handler traps or exhausts its evaluator
budget, ensuring their stopped resource ledgers do not claim completed cleanup.
A native child aborts with `SIGABRT` when that handler traps; cancellation after
success retains the result and returns normally without running the handler.

## Recorded execution

Four test modules ran from the isolated source snapshot identified in
`SOURCE_MANIFEST.json`: **70 tests, 0 failures, 0 errors, 0 skips**. This includes
the 10 new contract tests and the existing primitive, composite and direct LLVM
tests. Python-source hashes remained unchanged through the run. `RESULT.json`
records interpreter/tool selection, duration and hashes; `TESTS.log` retains
every test outcome.

```sh
CLANG=/absolute/path/to/clang-20 python -B -m unittest \
  tests.test_hia_semantics_contract \
  tests.test_hia_program \
  tests.test_hia_program_composite \
  tests.test_hia_program_llvm -v
```

The result applies to the exact recorded source files. It does not requalify
later edits by other workstreams, prove general source/backend refinement or
establish performance superiority. Cross-target object/emission checks do not
count as AArch64 or RISC-V native execution. Final integration must re-run the
tests against its own frozen source identity.
