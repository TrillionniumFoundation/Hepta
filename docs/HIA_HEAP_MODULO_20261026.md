# HIA P1: proof-bounded dynamic unsigned remainder allocation

Exact parent: PR #249 `f42c84869116d2db59750c9d214ed11b2abfaf51`.
This increments the existing `hepta.hia_heap_bound` abstract interpreter,
not the canonical HIA parser/verifier or either native backend.

## The closed arithmetic transfer

Verified HIA `int.rem.checked` on an unsigned machine-width type satisfies
`0 <= x % d < d` whenever the divisor is nonzero. The existing
`_bounded_divrem` admitted only exact pairs and therefore lost all resource
bounds for arbitrary user-controlled `u64`/`usize` operands, even after
`x % 16`. The updated transfer admits **only** an independently known,
strictly positive divisor interval `[lo, hi]`, producing `[0, hi-1]`
when the dividend or divisor is otherwise unknown/nonexact.

- A divisor which is zero or whose proven interval contains zero does not
  qualify a dynamic allocation. An exactly known zero traps and refuses.
- Unknown signed dividends remain unsupported; signed remainder can be
  negative and `MIN/-1` can trap. Unknown divisions do not gain bounds.
- Known exact operands keep the existing HIA truncation-toward-zero semantics.
- Resource owners, borrows, interprocedural owner transfer, loops, recursion,
  native CPU/RSS, FFI and hardware remain unchanged and unproved.
- The resulting interval must still fit the HIA allocator's `MAX_REQUEST`
  bound before any heap policy accepts an allocation. A divisor as large as
  `u64::MAX` is therefore **not** a small-memory certificate.

## Qualification and evidence

In-repository real HIA Core verifier/interpreter/budget tests are committed in
`tests/test_hia_heap_modulo.py`. Their cases include a fully dynamic u64
input, a nonconstant but provably positive divisor selected by a public bool,
the 256x255 exhaustive 8-bit arithmetic oracle, zero-divisor VM trap, signed
unknown refusal, and old exact signed remainder/division behavior.

Independent standalone mathematical controls executed in this task:
65,280 exhaustive u8 dividend/divisor pairs, 150,000 fixed-seed samples
on u16/u32/u64 with positive divisor intervals, 16,640 exhaustive
variable-divisor interval cases, and four negative controls. Those controls
are **not** full Hepta exact-HEAD integration or LLVM/native qualification.

Run the exact source with full repository and toolchain:

```sh
python -m unittest tests.test_hia_heap_modulo tests.test_hia_heap_scalar_exact \
  tests.test_hia_heap_bound tests.test_hia_program -v
python tools/release_check.py
```

`whole_project_blockers_closed=false`. Do not treat remote CI queueing as
a development stop, or independent arithmetic controls as a production pass.

## Additional native/VM acceptance boundary

`tests.test_hia_heap_modulo` now contains an opt-in **actual HIA**
`verify_program -> emit_program_llvm -> compile_program_llvm` x86-64 shared
library differential against the independent Core VM on bounded u64 inputs.
The test is skipped unless the pinned Clang20+ toolchain is available;
skipping must never be reported as a passing native qualification.

Separately, a handwritten LLVM control using the current emitter's
`icmp ne i64 divisor,0` / `urem i64` pattern compiled under Clang17 and
matched Python arithmetic on 250,000 fixed-seed u64 input/divisor pairs.
A separately compiled native C11 control matched 265,280 u8/u64 cases.
These are **real host machine-code probes but NOT Hepta-emitted objects**,
and must not be substituted for the unexecuted in-repository native test.
The handwritten LLVM shared object SHA-256 was
`742da3324514ea9704adc348c407f428013054d72a54ef8bd4c9bdf017663796`.
