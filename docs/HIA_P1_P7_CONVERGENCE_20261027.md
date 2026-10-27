# HIA P1/P7 two-line convergence — 2026-10-27

**Primary source parent:** PR #258 exact `930c1a8508d84d75643bdb0879bff0bda6b99206` (inherits #255).
**Numeric donor parent:** PR #260 exact `88b772826c83402f09d3e8e1cdb73c4a7a9eac3b`.
**Security donor parent:** PR #257 exact `d6696f6efea3cb35fc7d5f8f695b143d2d8de74a`.

These were integrated using two genuine two-parent Git commits. Neither
parent PR is considered production-merged or independently safe to merge
without reviewing the common dependency graph.

## Single retained authorities

- Keep primary #258's canonical `hepta.hia_program.verify_program`,
  `hepta.hia_heap_bound` and source/LLVM/VM paths.
- Preserve #255/#258's **entire unsigned division/remainder transfer** and
  the stronger type-checked `_bounded_nonnegative_and_mask` helper.
- Preserve #260's orthogonal typed `_bounded_bitnot` and
  `_bounded_positive_or_xor` helpers, transplanting only those two
  exact implementation bodies into primary's source.
- Remove the competing earlier `_bounded_bitand_mask` helper by keeping
  primary's stronger predicate. Translate only the donor test's helper
  spelling/types; no second bitwise resource checker.
- Import PR #257's three original exact Git blobs for pre-dlopen native
  seccomp kernel-effect denial; the destination's preimage matches the
  common #253 ancestor for the only existing overlapping file.

This convergence does NOT relax any byte budget, resource proof, LLVM
source replay, ABI, artifact publication or external assumptions.

## Actual new cross-feature acceptance

`tests/test_hia_p1_p7_convergence.py` exercises one genuinely
verified program through a dynamic u64 unsigned quotient by u64::MAX,
checked u8 cast, bit.not, selected non-exact mask AND, OR, XOR,
checked usize cast and actual Buffer allocation/drop. The verified
static live-payload upper bound must be **7 bytes**; an admission
limit of **6 must reject**. The independent VM checks runtime values,
owner cleanup and peak bytes for boundary inputs. It does not execute
foreign code.

Existing source-controlled tests from both parents are retained,
including native syscall denial and cross-target guards.

## Scope of proof

The arithmetic bounds are purely conservative transfer functions:
they prove requested live HIA *payload* upper bounds only on modeled
normal execution; not allocator overhead, process RSS, termination,
native machine-code refinement, general Provenance, or arbitrary
C++ behavior. The seccomp denylist is a finite Linux x86-64 native
worker protection, NOT an allowlist, secure sandbox or GPU/device
qualification.

Do not wait for CI to continue development. Do not convert absent
full-checkout/native exact-HEAD tests into passed evidence.

    python -m unittest tests.test_hia_p1_p7_convergence \
      tests.test_hia_heap_division_bounds tests.test_hia_heap_interval_bitmask \
      tests.test_hia_heap_interval_mask tests.test_hia_heap_bitnot \
      tests.test_hia_heap_or_xor tests.test_hia_heap_scalar_exact \
      tests.test_hia_native_kernel_effect_guard -v
    python tools/release_check.py

All broad P0–P7 soundness, ABI, C/C++ conversion, live Agent/model A/B,
physical DMA/GPU/IRQ and production performance remain OPEN/PARTIAL.
`whole_project_blockers_closed=false`.
